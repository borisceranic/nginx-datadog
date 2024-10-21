#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace datadog::nginx::security {

struct ContentType {
  std::string_view type;
  std::string_view subtype;
  std::string encoding;
  std::string boundary;

  // see https://httpwg.org/specs/rfc9110.html#field.content-type
  static std::optional<ContentType> for_string(std::string_view sv);
};

}  // namespace datadog::nginx::security
