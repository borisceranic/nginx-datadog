#include "body_parsing.h"
#include <sys/types.h>
#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include "ddwaf.h"
#include "security/ddwaf_memres.h"
#include "security/ddwaf_obj.h"
#include "util.h"

namespace dnsec = datadog::nginx::security;

namespace {
bool is_application_json(const std::string_view sv_arg) {
  auto sv = sv_arg;
  while (sv.at(0) == ' ' || sv.at(0) == '\t') {
    sv.remove_prefix(1);
  }

  // do the c++ equiv of memcmp()
  if (sv.length() < sizeof("application/json") - 1) {
    return false;
  }

  if (sv.starts_with("application/json")) {
    if (sv.length() == sizeof("application/json") - 1) {
      return true;
    }

    auto next = sv.at(sizeof("application/json") - 1);
    if (next == ';' || next == ' ' || next == '\t') {
      return true;
    }
  }

  return false;
}

bool is_json(const ngx_http_request_t &req) {
  for (const ngx_table_elt_t *ct = req.headers_in.content_type; ct;
       ct = ct->next) {
    if (is_application_json(datadog::nginx::to_string_view(ct->value))) {
      return true;
    }
  }

  return false;
}

class NgxChainInputStream {
 public:
  using Ch = char;

  NgxChainInputStream(ngx_chain_t *chain) : current_{chain} {
    if (current_) {
      pos_ = current_->buf->pos;
      end_ = current_->buf->last;
    }
  }

  Ch Peek() {  // NOLINT
    if (make_readable()) {
      return *pos_;
    }
    return '\0';
  }

  Ch Take() {  // NOLINT
    if (make_readable()) {
      read_++;
      return *pos_++;
    }
    return '\0';
  }

  std::size_t Tell() const {  // NOLINT
    return read_;
  }

  void Put(Ch) {  // NOLINT
                  // Not implemented because we're only reading
  }
  char *PutBegin() { return nullptr; }  // NOLINT
  size_t PutEnd(Ch *) { return 0; }     // NOLINT

 private:
  bool advance_buffer() {
    if (current_->next) {
      current_ = current_->next;
      pos_ = current_->buf->pos;
      end_ = current_->buf->last;
      return true;
    }
    return false;
  }

  bool make_readable() {
    while (pos_ == end_) {
      if (!advance_buffer()) {
        return false;
      }
    }
    return true;
  }

  ngx_chain_t *current_;
  u_char *pos_{};
  u_char *end_{};
  std::size_t read_{};
};

class DdwafObjArrPool {
 public:
  DdwafObjArrPool(dnsec::DdwafMemres &memres) : memres_{memres} {}

  dnsec::ddwaf_obj *get(std::size_t size) {
    auto it = free_.find(size);
    if (it != free_.end()) {
      std::vector<dnsec::ddwaf_obj *> &free_list = it->second;
      if (!free_list.empty()) {
        auto *obj = free_list.back();
        free_list.pop_back();
        return obj;
      }
    }

    return memres_.allocate_objects<dnsec::ddwaf_obj>(size);
  }

  dnsec::ddwaf_obj *realloc(dnsec::ddwaf_obj *arr, std::size_t cur_size,
                            std::size_t new_size) {
    auto *new_arr = get(new_size);
    std::copy_n(arr, cur_size, new_arr);

    std::vector<dnsec::ddwaf_obj *> free_list = free_[cur_size];
    free_list.emplace_back(arr);

    return new_arr;
  }

 private:
  dnsec::DdwafMemres &memres_;
  std::unordered_map<std::size_t, std::vector<dnsec::ddwaf_obj *>> free_;
};

class ToDdwafObjHandler
    : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>,
                                          ToDdwafObjHandler> {
 public:
  ToDdwafObjHandler(dnsec::ddwaf_obj &slot, dnsec::DdwafMemres &memres)
      : pool_{memres}, memres_{memres}, root_{slot} {}

  bool Null() {
    get_slot().make_null();
    return true;
  }

  bool Bool(bool b) {
    get_slot().make_bool(b);
    return true;
  }

  bool Int(int i) {
    get_slot().make_number(i);
    return true;
  }

  bool Uint(unsigned u) {
    get_slot().make_number(u);
    return true;
  }

  bool Int64(int64_t i) {
    get_slot().make_number(i);
    return true;
  }

  bool Uint64(uint64_t u) {
    get_slot().make_number(u);
    return true;
  }

  bool Double(double d) {
    get_slot().make_number(d);
    return true;
  }

  bool String(const char *str, rapidjson::SizeType length, bool copy) {
    std::string_view sv{str, length};
    current_->make_string(sv, memres_);
    return true;
  }

  bool Key(const char *str, rapidjson::SizeType length, bool copy) {
    std::string_view sv{str, length};
    current_->set_key(sv, memres_);
    return true;
  }

  bool StartObject() {
    std::cout << "Start Object" << std::endl;
    return true;
  }

  bool EndObject(rapidjson::SizeType memberCount) {
    std::cout << "End Object, Member Count: " << memberCount << std::endl;
    return true;
  }

  bool StartArray() {
    std::cout << "Start Array" << std::endl;
    return true;
  }

  bool EndArray(rapidjson::SizeType elementCount) {
    std::cout << "End Array, Element Count: " << elementCount << std::endl;
    return true;
  }

 private:
  DdwafObjArrPool pool_;
  dnsec::DdwafMemres &memres_;
  dnsec::ddwaf_obj &root_;
  dnsec::ddwaf_obj *current_{&root_};
  struct LenCap {
    std::size_t len;
    std::size_t cap;
  };
  std::vector<LenCap> capacity_stack_{{0, 1}};

  dnsec::ddwaf_obj &get_slot() {
    auto &len_cap = capacity_stack_.back();
    if (len_cap.len < len_cap.cap) {
      len_cap.len++;
      return current_[len_cap.len - 1];
    }

    assert(!capacity_stack_.empty());
    assert(current_ != &root_);

    std::size_t new_cap = len_cap.cap * 2;
    current_ = pool_.realloc(current_, len_cap.cap, new_cap);

    len_cap.len++;
    len_cap.cap = new_cap;
    return current_[len_cap.len - 1];
  }
};

}  // namespace

namespace datadog::nginx::security {

ddwaf_obj parse_body(ngx_http_request_t &req, const ngx_chain_t &chain,
                     std::size_t size, DdwafMemres &memres) {
  ddwaf_obj obj; 

  ddwaf_str_obj &str = obj.make_string(size, memres);
  char *buf = str.buffer();

  std::size_t left = size;
  for (const ngx_chain_t *cl = &chain; cl != nullptr && left > 0;
       cl = cl->next) {
    const ngx_buf_t *b = cl->buf;
    assert(!b->in_file);
    std::size_t to_copy =
        std::min(left, static_cast<std::size_t>(b->last - b->pos));
    std::copy_n(b->pos, to_copy, buf);
    buf += to_copy;
    left -= to_copy;
  }

  if (left > 0) {
    throw std::runtime_error("mismatch between declared size and read size");
  }

  return obj;
}

}  // namespace datadog::nginx::security
