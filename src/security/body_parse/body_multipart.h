#pragma once

#include <string_view>

#include "../ddwaf_obj.h"
#include "header.h"

extern "C" {
#include <ngx_core.h>
#include <ngx_http.h>
}

namespace datadog::nginx::security {

bool parse_multipart(ddwaf_obj &slot, ngx_http_request_t &req, ContentType &ct,
                     const ngx_chain_t &chain, std::size_t size,
                     DdwafMemres &memres);

}  // namespace datadog::nginx::security
