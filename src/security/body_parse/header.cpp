#include "header.h"

#include <algorithm>

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

inline std::string to_lc(std::string_view sv) {
  std::string result;
  result.reserve(sv.size());
  std::transform(sv.begin(), sv.end(), result.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return result;
}

void consume_ows(std::string_view &sv) {
  while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
    sv.remove_prefix(1);
  }
}

/* https://httpwg.org/specs/rfc9110.html#rfc.section.5.6.2
 *   token          = 1*tchar
 *   tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
 *                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *                  / DIGIT / ALPHA
 *                  ; any VCHAR, except delimiters
 *
 * For multipart/form-data, RFC 9110 refers to RFC 7578 ("Returning Values from
 * Forms: multipart/form-data"), which in refers to RFC 2183 ("The
 * Content-Disposition Header Field"), which in turn defines their tokens like
 * this:
 *
 * https://datatracker.ietf.org/doc/html/rfc2045 (by reference to RFC 822)
 *   token      := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
 *                    or tspecials>
 *
 *   tspecials :=  "(" / ")" / "<" / ">" / "@" /
 *                 "," / ";" / ":" / "\" / <">
 *                 "/" / "[" / "]" / "?" / "="
 *                 ; Must be in quoted-string,
 *                 ; to use within parameter values
 *
 * This is both more permissive (allows {}) and more restrictive (forbids
 * characters outside ASCII).
 */
std::optional<std::string_view> consume_wg_token(std::string_view &sv) {
  static constexpr std::string_view tchar =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789!#$%&'*+-.^_`|~";
  auto end = sv.find_first_not_of(tchar);
  if (end == 0 || end == std::string_view::npos) {
    return std::nullopt;
  }
  auto ret = std::optional{sv.substr(0, end)};
  sv.remove_prefix(end);
  return ret;
}

std::optional<std::string_view> consume_2045_token(std::string_view &sv) {
  static constexpr std::string_view excluded_chars =
      R"(()<>@,;:\"/[]?=)"
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F"
      "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
      " ";
  auto end = sv.find_first_of(excluded_chars);
  if (end == 0 || end == std::string_view::npos) {
    return std::nullopt;
  }
  auto ret = std::optional{sv.substr(0, end)};
  sv.remove_prefix(end);
  return ret;
}

/*
 * https://httpwg.org/specs/rfc9110.html#quoted.strings
 * quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 * qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 * obs-text       = %x80-FF
 * quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 *
 * This is more restrictive than the original definition in RFC 822:
 * https://datatracker.ietf.org/doc/html/rfc822#section-3.3
 * quoted-string = <"> *(qtext/quoted-pair) <">
 * qtext         =  <any CHAR excepting <">,      may be folded
 *                  "\" & CR, and including linear-white-space>
 * quoted-pair   =  "\" CHAR
 * CHAR          =  <any ASCII character>
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

    // qdtext
    if (ch == '\t' || ch == ' ' || (ch >= 0x21 && ch != '\\' && ch != 0x7F)) {
      result.push_back(ch);
      continue;
    }

    // quoted-pair
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

/*
 * https://httpwg.org/specs/rfc9110.html#field.content-type
 * Content-Type    = media-type
 * media-type      = type "/" subtype parameters
 * type            = token
 * subtype         = token
 * parameters      = *( OWS ";" OWS [ parameter ] )
 * parameter       = parameter-name "=" parameter-value
 * parameter-name  = token
 * parameter-value = ( token / quoted-string )
 *
 * This definition is taken from the HTTP spec, but we use it for multipart
 * MIME parts too.
 */
std::optional<ContentType> ContentType::for_string(std::string_view sv) {
  ContentType ct{};

  consume_ows(sv);

  auto maybe_type = consume_wg_token(sv);
  if (!maybe_type) {
    return std::nullopt;
  }
  ct.type = to_lc(*maybe_type);
  sv.remove_prefix(maybe_type->size());

  if (sv.empty() || sv.front() != '/') {
    return std::nullopt;
  }
  sv.remove_prefix('/');

  auto maybe_subtype = consume_wg_token(sv);
  if (!maybe_subtype) {
    return std::nullopt;
  }
  ct.subtype = to_lc(*maybe_subtype);
  sv.remove_prefix(maybe_subtype->size());

  while (true) {
    consume_ows(sv);
    if (sv.empty()) {
      return std::move(ct);
    }
    if (sv != ";") {
      return std::nullopt;
    }
    consume_ows(sv);

    if (sv.empty()) {
      return std::move(ct);
    }

    std::optional<std::string_view> maybe_param_name = consume_wg_token(sv);
    if (!maybe_param_name) {
      return std::nullopt;
    }

    if (sv.empty() || sv.front() != '=') {
      return std::nullopt;
    }
    sv.remove_prefix(1);

    if (sv.empty()) {
      return std::nullopt;
    }

    std::string value;
    if (sv.front() == '"') {
      std::optional<std::string> maybe_value = consume_quoted_string(sv);
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

/*
 * https://www.ietf.org/rfc/rfc2183.txt
 *   disposition        := "Content-Disposition" ":"
 *                         disposition-type
 *                         *(";" disposition-parm)
 *
 *   disposition-type    := "inline"
 *                         / "attachment"
 *                         / extension-token
 *                         ; values are not case-sensitive
 *
 *   disposition-parm    := filename-parm
 *                         / creation-date-parm
 *                         / modification-date-parm
 *                         / read-date-parm
 *                         / size-parm
 *                         / parameter
 *
 *   filename-parm       := "filename" "=" value
 *
 *   creation-date-parm  := "creation-date" "=" quoted-date-time
 *
 *   modification-date-parm := "modification-date" "=" quoted-date-time
 *
 *   read-date-parm      := "read-date" "=" quoted-date-time
 *
 *   size-parm           := "size" "=" 1*DIGIT
 *
 *   quoted-date-time    := quoted-string
 *                         ; contents MUST be an RFC 822 `date-time'
 *                         ; numeric timezones (+HHMM or -HHMM) MUST be used
 *
 *   value := token / quoted-string (RFC 2045, continue to see)
 *
 * Parameter values longer than 78  characters, or which contain non-ASCII
 * characters, MUST be encoded as specified in [RFC 2184].
 *
 * We ignore this last part; stuff looks like this:
 * Content-Type: application/x-stuff
 *  title*1*=us-ascii'en'This%20is%20even%20more%20
 *  title*2*=%2A%2A%2Afun%2A%2A%2A%20
 *  title*3="isn't it!"
 */

std::optional<ContentDisposition> ContentDisposition::for_string(
    std::string_view sv) {
  ContentDisposition cd{};

  consume_ows(sv);

  auto maybe_disp = consume_2045_token(sv);
  if (!maybe_disp) {
    return std::nullopt;
  }

  cd.disposition = to_lc(*maybe_disp);

  while (true) {
    consume_ows(sv);
    if (sv.empty()) {
      return std::move(cd);
    }
    if (sv != ";") {
      return std::nullopt;
    }
    sv.remove_prefix(1);
    consume_ows(sv);

    // trailing ; doesn't seem allowed above, but...
    if (sv.empty()) {
      return std::move(cd);
    }

    auto maybe_param_name = consume_2045_token(sv);
    if (!maybe_param_name) {
      return std::nullopt;
    }

    consume_ows(sv);
    if (sv.empty() || sv.front() != '=') {
      return std::nullopt;
    }
    sv.remove_prefix(1);

    if (sv.empty()) {
      return std::nullopt;
    }
    if (sv.front() == '"') {
      std::optional<std::string> maybe_value = consume_quoted_string(sv);
      if (!maybe_value) {
        return std::nullopt;
      }
      std::string value = *maybe_value;
      if (equals_ci(*maybe_param_name, "filename"sv)) {
        cd.filename = value;
      } else if (equals_ci(*maybe_param_name, "name"sv)) {
        cd.name = value;
      }
    }
  }
}
}  // namespace datadog::nginx::security
