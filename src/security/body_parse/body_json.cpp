#include "body_json.h"

#include <rapidjson/error/en.h>
#include <rapidjson/reader.h>

#include "../ddwaf_memres.h"
#include "../ddwaf_obj.h"
#include "chain_is.hpp"

extern "C" {
#include <ngx_core.h>
#include <ngx_http.h>
}

namespace datadog::nginx::security {

class ToDdwafObjHandler
    : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>,
                                          ToDdwafObjHandler> {
 public:
  ToDdwafObjHandler(ddwaf_obj &slot, DdwafMemres &memres)
      : pool_{memres}, memres_{memres}, bufs_{{&slot, 0, 1}} {}

  ddwaf_obj *finish(ngx_http_request_t &req) {
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
  DdwafObjArrPool<ddwaf_obj> pool_;
  DdwafMemres &memres_;
  struct Buf {
    ddwaf_obj *ptr;
    std::size_t len;
    std::size_t cap;
    bool key_last;

    auto cur_obj() -> ddwaf_obj & { return ptr[len - 1]; }
  };
  std::vector<Buf> bufs_{{nullptr, 0, 0}};

  ddwaf_obj &get_slot() { return do_get_slot(false); }

  ddwaf_obj &get_slot_for_key() { return do_get_slot(true); }

  ddwaf_obj &do_get_slot(bool for_key) {
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
    ddwaf_obj &slot = buf_cont.cur_obj();
    slot.nbEntries = buf_arr.len;
    slot.array = buf_arr.ptr;
  }
};

bool parse_json(ddwaf_obj &slot, ngx_http_request_t &req,
                const ngx_chain_t &chain, DdwafMemres &memres) {
  // be as permissive as possible
  static constexpr unsigned parse_flags =
      rapidjson::kParseStopWhenDoneFlag |
      rapidjson::kParseEscapedApostropheFlag | rapidjson::kParseNanAndInfFlag |
      rapidjson::kParseTrailingCommasFlag | rapidjson::kParseCommentsFlag |
      rapidjson::kParseIterativeFlag;

  ToDdwafObjHandler handler{slot, memres};
  rapidjson::Reader reader;
  NgxChainInputStream is{&chain};
  rapidjson::ParseResult res =
      reader.Parse<parse_flags, NgxChainInputStream>(is, handler);
  ddwaf_obj *json_obj = handler.finish(req);
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

  return false;
}

}  // namespace datadog::nginx::security
