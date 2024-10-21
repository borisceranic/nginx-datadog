#pragma once

extern "C" {
#include <ngx_http.h>
}

#include <string_view>

#include "../ddwaf_obj.h"

using namespace std::literals;

namespace datadog::nginx::security {

bool parse_body(ddwaf_obj &slot, ngx_http_request_t &req,
                const ngx_chain_t &chain, std::size_t size,
                DdwafMemres &memres);

}  // namespace datadog::nginx::security
