#include "content_type.h"

using namespace std::literals;

namespace {

inline bool equals_ci(std::string_view a, std::string_view lc_b) {
  if (a.size() != lc_b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); i++) {
    if (std::tolower(a[i]) != lc_b[i]) {
      return false;
    }
  }
  return true;
}

/*
 * quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 * qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 * obs-text       = %x80-FF
 * quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 */
std::optional<std::string> consume_quoted_string(std::string_view &sv) {
  if (sv.front() != '"') {
    return std::nullopt;
  }
  sv.remove_prefix(1);

  std::string result;
  while (!sv.empty()) {
    unsigned char ch = sv.front();
    sv.remove_prefix(1);
    if (ch == '"' /* 0x22 */) {
      return result;
    }

    if (ch == '\t' || ch == ' ' || (ch >= 0x21 && ch != '\\' && ch != 0x7F)) {
      result.push_back(ch);
      continue;
    }

    if (ch == '\\') {
      if (sv.empty()) {
        return std::nullopt;
      }
      ch = sv.front();
      sv.remove_prefix(1);
      if (ch == '\t' || ch == ' ' || (ch >= 0x21 && ch != 0x7F)) {
        result.push_back(ch);
        continue;
      }
    }

    return std::nullopt;
  }
  return std::nullopt;
}

}  // namespace

namespace datadog::nginx::security {

// see https://httpwg.org/specs/rfc9110.html#field.content-type
std::optional<ContentType> ContentType::for_string(std::string_view sv) {
  ContentType ct{};
  auto consume_token = [&sv]() -> std::optional<std::string_view> {
    static constexpr std::string_view tchar =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789!#$%&'*+-.^_`|~";
    auto end = sv.find_first_not_of(tchar);
    if (end == 0 || end == std::string_view::npos) {
      return std::nullopt;
    }
    auto res = std::optional{sv.substr(0, end)};
    sv.remove_prefix(end);
    return res;
  };

  auto maybe_type = consume_token();
  if (!maybe_type) {
    return std::nullopt;
  }
  ct.type = *maybe_type;
  sv.remove_prefix(maybe_type->size());

  if (sv.empty() || sv.front() != '/') {
    return std::nullopt;
  }
  sv.remove_prefix('/');

  auto maybe_subtype = consume_token();
  if (!maybe_subtype) {
    return std::nullopt;
  }
  ct.subtype = *maybe_subtype;
  sv.remove_prefix(maybe_subtype->size());

  auto consume_ows = [&sv]() {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
      sv.remove_prefix(1);
    }
  };

  /*
   * parameters      = *( OWS ";" OWS [ parameter ] )
   * parameter       = parameter-name "=" parameter-value
   * parameter-name  = token
   * parameter-value = ( token / quoted-string )
   */
  while (true) {
    consume_ows();
    if (sv.empty()) {
      return ct;
    }
    if (sv != ";") {
      return std::nullopt;
    }
    consume_ows();

    auto maybe_param_name = consume_token();
    if (!maybe_param_name) {
      return std::nullopt;
    }
    sv.remove_prefix(maybe_param_name->size());

    if (sv.empty() || sv.front() != '=') {
      return std::nullopt;
    }
    sv.remove_prefix(1);

    if (sv.empty()) {
      return std::nullopt;
    }

    std::string value;
    if (sv.front() == '"') {
      auto maybe_value = consume_quoted_string(sv);
      if (!maybe_value) {
        return std::nullopt;
      }
      value = *maybe_value;
    }

    if (equals_ci(*maybe_param_name, "charset"sv)) {
      ct.encoding = value;
    } else if (equals_ci(*maybe_param_name, "boundary"sv)) {
      ct.boundary = value;
    }
  }
}
}  // namespace datadog::nginx::security
