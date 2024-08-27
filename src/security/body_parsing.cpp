#include "body_parsing.h"
#include "security/ddwaf_memres.h"

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
