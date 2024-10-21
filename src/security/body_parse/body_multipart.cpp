#include <cuchar>
#include <string_view>

#include "../ddwaf_obj.h"
#include "content_type.h"

extern "C" {
#include <ngx_core.h>
}

namespace datadog::nginx::security {

bool parse_multipart(ddwaf_obj &slot, ContentType &ct, const ngx_chain_t &chain,
                     std::size_t size, DdwafMemres &memres) {}

}  // namespace datadog::nginx::security
