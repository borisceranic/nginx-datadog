#include "body_multipart.h"

#include <string_view>

#include "../ddwaf_obj.h"
#include "header.h"

extern "C" {
#include <ngx_core.h>
}

namespace {

class NgxChainInputStream {
 public:
  NgxChainInputStream(const ngx_chain_t *chain) : current_{chain} {
    if (current_) {
      pos_ = current_->buf->pos;
      end_ = current_->buf->last;
    }
  }

  std::uint8_t read() {
    if (pos_ == end_) {
      if (!advance_buffer()) {
        return 0;
      }
    }
    return *pos_++;
  }

  std::size_t read(std::uint8_t *buffer, size_t buf_size) {
    std::size_t read = 0;
    while (read > 0) {
      if (pos_ == end_) {
        if (!advance_buffer()) {
          return read;
        }
      }
      std::size_t to_read =
          std::min(static_cast<std::size_t>(end_ - pos_), buf_size - read);
      std::copy_n(pos_, to_read, buffer + read);
      read += to_read;
    }
    return read;
  }

  bool eof() const {
    if (pos_ == end_) {
      return current_ == nullptr || current_->next == nullptr;
    }
    return false;
  }

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

  const ngx_chain_t *current_;
  u_char *pos_{};
  u_char *end_{};
};
}  // namespace

namespace datadog::nginx::security {

bool parse_multipart(ddwaf_obj &slot, ngx_http_request_t &req, ContentType &ct,
                     const ngx_chain_t &chain, std::size_t size,
                     DdwafMemres &memres) {
  if (ct.boundary.size() == 0 || ct.boundary.size() > 70) {
    ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                  "multipart boundary is invalid: %s", ct.boundary.c_str());
  } else {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req.connection->log, 0,
                   "multipart boundary: %s", ct.boundary.c_str());
  }
  NgxChainInputStream stream{&chain};

  std::vector<std::uint8_t> bound_buf;
  bound_buf.reserve(2 /* -- */ + ct.boundary.size() + 2 /* \r\n */);
  while (!stream.eof()) {
    // 1. find beginning boundary
    std::size_t read = stream.read(bound_buf.data(), bound_buf.size());
    if (read < bound_buf.size()) {
      ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                    "multipart: expected boundary, got EOF");
      return false;
    }

    const std::uint8_t *p = bound_buf.data();
    if (*p++ != '-' || *p++ != '-') {
      ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                    "multipart: expected --, got: %c%c", bound_buf[0],
                    bound_buf[1]);
      return false;
    }

    if (std::memcmp(p, ct.boundary.data(), ct.boundary.size()) != 0) {
      ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                    "multipart: did not see the correct boundary after --");
      return false;
    }
    p += ct.boundary.size();

    if (*p++ != '\r' || *p++ != '\n') {
      ngx_log_error(NGX_LOG_NOTICE, req.connection->log, 0,
                    "multipart: expected \\r\\n, got: %c%c", bound_buf[0],
                    bound_buf[1]);
      return false;
    }

    // 2.
  }

  return false;
}

}  // namespace datadog::nginx::security
