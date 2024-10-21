#include "body_parsing.h"

#include <rapidjson/error/en.h>
#include <rapidjson/reader.h>

#include <algorithm>
#include <cstddef>
#include <unordered_map>

#include "ddwaf.h"
#include "ddwaf_memres.h"
#include "ddwaf_obj.h"
#include "security/decode.h"
#include "util.h"

extern "C" {
#include <ngx_http.h>
#include <sys/types.h>
}

namespace dnsec = datadog::nginx::security;

namespace {

bool is_content_type(std::string_view actual, std::string_view tested) {
  auto sv = actual;
  while (sv.at(0) == ' ' || sv.at(0) == '\t') {
    sv.remove_prefix(1);
  }

  if (sv.starts_with(tested)) {
    if (sv.length() == tested.length()) {
      return true;
    }

    auto next = sv.at(tested.length());
    if (next == ';' || next == ' ' || next == '\t') {
      return true;
    }
  }

  return false;
}

bool is_json(const ngx_http_request_t &req) {
  const ngx_table_elt_t *ct = req.headers_in.content_type;
  // don't look at ct->next; consider only the first value
  return ct && is_content_type(datadog::nginx::to_string_view(ct->value),
                               "application/json"sv);
}

class NgxChainInputStream {
 public:
  using Ch = char;

  NgxChainInputStream(const ngx_chain_t *chain) : current_{chain} {
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

  const ngx_chain_t *current_;
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
        return new (obj) dnsec::ddwaf_obj[size]{};
      }
    }

    return memres_.allocate_objects<dnsec::ddwaf_obj>(size);
  }

  dnsec::ddwaf_obj *realloc(dnsec::ddwaf_obj *arr, std::size_t cur_size,
                            std::size_t new_size) {
    assert(new_size > cur_size);
    auto *new_arr = get(new_size);
    if (cur_size > 0) {
      std::copy_n(arr, cur_size, new_arr);

      std::vector<dnsec::ddwaf_obj *> free_list = free_[cur_size];
      free_list.emplace_back(arr);
    }

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
      : pool_{memres}, memres_{memres}, bufs_{{&slot, 0, 1}} {}

  dnsec::ddwaf_obj *finish(ngx_http_request_t &req) {
    if (bufs_.size() != 1) {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req.connection->log, 0,
                     "json parsing finished prematurely");
      while (bufs_.size() > 1) {
        pop_container();
      }
    }

    auto &buf = bufs_.back();

    return buf.ptr;
  }

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
    get_slot().make_string(sv, memres_);
    return true;
  }

  bool Key(const char *str, rapidjson::SizeType length, bool copy) {
    std::string_view sv{str, length};
    get_slot_for_key().set_key(sv, memres_);

    return true;
  }

  bool StartObject() {
    push_map();
    return true;
  }

  bool EndObject(rapidjson::SizeType /*memberCount*/) {
    pop_container();
    return true;
  }

  bool StartArray() {
    push_array();
    return true;
  }

  bool EndArray(rapidjson::SizeType /*elementCount*/) {
    pop_container();
    return true;
  }

 private:
  DdwafObjArrPool pool_;
  dnsec::DdwafMemres &memres_;
  struct Buf {
    dnsec::ddwaf_obj *ptr;
    std::size_t len;
    std::size_t cap;
    bool key_last;

    auto cur_obj() -> dnsec::ddwaf_obj & { return ptr[len - 1]; }
  };
  std::vector<Buf> bufs_{{nullptr, 0, 0}};

  dnsec::ddwaf_obj &get_slot() { return do_get_slot(false); }

  dnsec::ddwaf_obj &get_slot_for_key() { return do_get_slot(true); }

  dnsec::ddwaf_obj &do_get_slot(bool for_key) {
    auto &buf = bufs_.back();
    assert(!for_key || !buf.key_last);  // no two keys in succession
    if (buf.key_last) {
      auto &ret = buf.cur_obj();
      buf.key_last = false;
      return ret;
    }

    if (for_key) {
      buf.key_last = true;
    }

    if (buf.len < buf.cap) {
      buf.len++;
      return buf.ptr[buf.len - 1];
    }

    std::size_t new_cap = buf.cap * 2;
    if (new_cap == 0) {
      new_cap = 1;
    }
    buf.ptr = pool_.realloc(buf.ptr, buf.cap, new_cap);

    buf.len++;
    buf.cap = new_cap;
    return buf.cur_obj();
  }

  void push_array() {
    auto &slot = get_slot();
    slot.type = DDWAF_OBJ_ARRAY;
    bufs_.emplace_back(Buf{nullptr, 0, 0});
  }

  void push_map() {
    auto &slot = get_slot();
    slot.type = DDWAF_OBJ_MAP;
    bufs_.emplace_back(Buf{nullptr, 0, 0});
  }

  void pop_container() {
    auto &buf_arr = bufs_.back();
    bufs_.pop_back();
    auto buf_cont = bufs_.back();
    dnsec::ddwaf_obj &slot = buf_cont.cur_obj();
    slot.nbEntries = buf_arr.len;
    slot.array = buf_arr.ptr;
  }
};

bool is_urlencoded(const ngx_http_request_t &req) {
  const ngx_table_elt_t *ct = req.headers_in.content_type;
  return ct && is_content_type(datadog::nginx::to_string_view(ct->value),
                               "application/x-www-form-urlencoded"sv);
}

}  // namespace

namespace datadog::nginx::security {

bool parse_body(ddwaf_obj &slot, ngx_http_request_t &req,
                const ngx_chain_t &chain, std::size_t size,
                DdwafMemres &memres) {
  // be as permissive as possible
  static constexpr unsigned parse_flags =
      rapidjson::kParseStopWhenDoneFlag |
      rapidjson::kParseEscapedApostropheFlag | rapidjson::kParseNanAndInfFlag |
      rapidjson::kParseTrailingCommasFlag | rapidjson::kParseCommentsFlag |
      rapidjson::kParseIterativeFlag;

  if (is_json(req)) {
    // use rapidjson to parse:

    ToDdwafObjHandler handler{slot, memres};
    rapidjson::Reader reader;
    NgxChainInputStream is{&chain};
    rapidjson::ParseResult res =
        reader.Parse<parse_flags, NgxChainInputStream>(is, handler);
    dnsec::ddwaf_obj *json_obj = handler.finish(req);
    if (res.IsError()) {
      if (json_obj) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req.connection->log, 0,
                       "json parsing failed after producing some output: %s",
                       rapidjson::GetParseError_En(res.Code()));
      } else {
        ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                      "json parsing failed without producing any output: %s",
                      rapidjson::GetParseError_En(res.Code()));
      }
    } else {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req.connection->log, 0,
                     "body json parsing finished successfully");
    }

    if (json_obj) {
      assert(json_obj == &slot);
      return true;
    }
  }

  char *buf = memres.allocate_string(size);

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
    throw std::runtime_error(
        "mismatch between declared size and read size (read is smaller than "
        "declared)");
  }

  if (is_urlencoded(req)) {
    QueryStringIter it{
        {buf, size}, memres, '&', QueryStringIter::trim_mode::no_trim};

    // count key occurrences
    std::unordered_map<std::string_view, std::size_t> bag;
    for (; !it.ended(); ++it) {
      std::string_view cur_key = it.cur_key();
      bag[cur_key]++;
    }

    // allocate all ddwaf_obj, set keys
    std::unordered_map<std::string_view, ddwaf_obj *> key_index;
    ddwaf_map_obj slot_map = slot.make_map(bag.size(), memres);
    std::size_t i = 0;
    for (auto &&[key, count] : bag) {
      ddwaf_obj &cur = slot_map.at_unchecked(i++);
      key_index.emplace(key, &cur);
      cur.set_key(key);
      if (count == 1) {
        cur.make_string(""sv);  // to be filled later
      } else {
        cur.make_array(count, memres);
        cur.nbEntries = 0;  // fixed later
      }
    }

    // set values
    it.reset();
    for (it.reset(); !it.ended(); ++it) {
      auto [cur_key, cur_value] = *it;
      ddwaf_obj &cur = *key_index.at(cur_key);
      if (cur.is_string()) {
        cur.make_string(cur_value);
      } else {
        ddwaf_arr_obj &cur_arr = static_cast<ddwaf_arr_obj &>(cur);
        cur_arr.at_unchecked(cur_arr.nbEntries++).make_string(cur_value);
      }
    }

    return true;
  }

  slot.make_string(std::string_view{buf, size});

  return true;
}

}  // namespace datadog::nginx::security
