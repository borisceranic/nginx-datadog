#include "body_multipart.h"

#include <string_view>
#include <unordered_map>
#include <utility>

#include "../ddwaf_memres.h"
#include "../ddwaf_obj.h"
#include "chain_is.hpp"
#include "header.h"

extern "C" {
#include <ngx_core.h>
}

namespace dnsec = datadog::nginx::security;

namespace {
enum class LineType { BOUNDARY, BOUNDARY_END, OTHER, END_OF_FILE };
auto bind_consume_line(dnsec::HttpContentType &ct,
                       std::unique_ptr<std::uint8_t[]> &bound_buf,
                       std::size_t beg_bound_size) {
  return [&ct, &bound_buf, beg_bound_size](dnsec::NgxChainInputStream &is,
                                           std::string *append) {
    std::size_t read =
        is.read_until(bound_buf.get(), bound_buf.get() + beg_bound_size, '\n');
    if (read == 0) {
      return LineType::END_OF_FILE;
    }
    if (bound_buf[read - 1] == '\n') {
      // too small; can't be boundary. The buffer is not long enough to include
      // --boundary\n
      if (append) {
        std::copy_n(bound_buf.get(), read, std::back_inserter(*append));
      }
      return LineType::OTHER;
    }

    // the input may have been truncated (we don't buffer the whole request)
    // so assume we saw a boundary if we see at least part of it
    if (is.eof() && read < beg_bound_size) {
      bool matched = true;
      for (std::size_t i = 0; matched && i < read; i++) {
        if (i < 3) {
          matched = bound_buf[i] == '-';
        } else {
          matched = bound_buf[i] == ct.boundary[i - 2];
        }
      }

      if (matched) {
        return LineType::BOUNDARY_END;
      }
    }

    if (read == beg_bound_size && std::memcmp(bound_buf.get(), "--", 2) == 0 &&
        std::memcmp(bound_buf.get() + 2, ct.boundary.data(),
                    ct.boundary.size()) == 0) {
      // we found the boundary. It doesn't matter if the line contains
      // extra characters (see RFC 2046)
      std::uint8_t ch{};
      LineType res;
      if (!is.eof() && (ch = is.read()) == '-' && !is.eof() &&
          ((ch = is.read()) == '-')) {
        res = LineType::BOUNDARY_END;
      } else {
        res = LineType::BOUNDARY;
      }

      // discard the rest of the line
      if (ch != '\n') {
        while (!is.eof() && is.read() != '\n') {
        }
      }

      return res;
    } else {
      // not a boundary
      if (append) {
        std::copy_n(bound_buf.get(), read, std::back_inserter(*append));
        while (!is.eof()) {
          std::uint8_t ch = is.read();
          append->push_back(ch);
          if (ch == '\n') {
            break;
          }
        }
      } else {
        while (!is.eof() && is.read() != '\n') {
        }
      }
      return LineType::OTHER;
    }
  };
}

struct Buf {
  dnsec::ddwaf_obj *ptr;
  std::size_t len;
  std::size_t cap;

  void extend(dnsec::DdwafObjArrPool<dnsec::ddwaf_obj> &pool) {
    std::size_t new_cap = cap * 2;
    if (new_cap == 0) {
      new_cap = 1;
    }
    ptr = pool.realloc(ptr, cap, new_cap);
    cap = new_cap;
  }

  dnsec::ddwaf_obj &new_slot(dnsec::DdwafObjArrPool<dnsec::ddwaf_obj> &pool) {
    if (len == cap) {
      extend(pool);
    }
    return ptr[len - 1];
  }
};

}  // namespace

namespace datadog::nginx::security {

bool parse_multipart(ddwaf_obj &slot, ngx_http_request_t &req,
                     HttpContentType &ct, const ngx_chain_t &chain,
                     std::size_t size, DdwafMemres &memres) {
  if (ct.boundary.size() == 0) {
    ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                  "multipart boundary is invalid: %s", ct.boundary.c_str());
  } else {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req.connection->log, 0,
                   "multipart boundary: %s", ct.boundary.c_str());
  }
  NgxChainInputStream stream{&chain};

  std::unique_ptr<std::uint8_t[]> bound_buf;
  std::size_t beg_bound_size = 2 /* -- */ + ct.boundary.size();
  bound_buf.reset(new std::uint8_t[beg_bound_size]);
  auto consume_line = bind_consume_line(ct, bound_buf, beg_bound_size);

  // find first boundary, discarding everything before it
  while (!stream.eof()) {
    auto line_type = consume_line(stream, nullptr);
    if (line_type == LineType::BOUNDARY) {
      break;
    } else if (line_type == LineType::BOUNDARY_END) {
      ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                    "multipart: found end boundary before first boundary");
      return false;
    }
  }

  if (stream.eof()) {
    ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                  "multipart: eof right after first boundary");
    return false;
  }

  DdwafObjArrPool<ddwaf_obj> pool{memres};
  std::unordered_map<std::string, Buf> data;

start_part:
  // headers after the previous boundary
  std::optional<MimeContentDisposition> cd =
      MimeContentDisposition::for_stream(stream);
  if (!cd) {
    ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                  "multipart: did not find Content-Disposition header");
  }

  // content
  {
    std::string content;
    while (!stream.eof()) {
      auto line_type = consume_line(stream, &content);

      if (line_type == LineType::BOUNDARY ||
          line_type == LineType::BOUNDARY_END) {
        // finished content
        // the \r\n preceding the boundary is deemed part of the boundary
        if (content.size() >= 1 && content.back() == '\n') {
          content.pop_back();
          if (content.size() >= 1 && content.back() == '\r') {
            content.pop_back();
          }
        }

        if (cd) {
          auto &buf = data[cd->name];
          buf.new_slot(pool).make_string({content.data(), content.size()},
                                         memres);
        }

        if (line_type == LineType::BOUNDARY_END) {
          break;
        }
        if (!stream.eof()) {
          goto start_part;
        }
      } else if (line_type == LineType::END_OF_FILE) {
        ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                      "multipart: eof before end boundary");
        return false;
      }  // else it was LineType::OTHER and there's nothing to do
    }
  }

  if (data.empty()) {
    return false;
  }

  auto &map = slot.make_map(data.size(), memres);
  std::size_t i = 0;
  for (auto &[key, buf] : data) {
    auto &map_slot = map.at_unchecked(i);
    map_slot.set_key(key);
    if (buf.len == 1) {
      map_slot.shallow_copy_val_from(buf.ptr[0]);
    } else {
      map_slot.make_array(buf.ptr, buf.len);
    }
  }

  return true;
}

}  // namespace datadog::nginx::security
