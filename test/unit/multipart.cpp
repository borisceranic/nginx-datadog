#include <ngx_core.h>
#include <security/body_parse/body_multipart.h>
#include <security/body_parse/header.h>

#include <catch2/catch_test_macros.hpp>
#include <string_view>
#include <type_traits>

namespace {
using namespace datadog::nginx::security;

ddwaf_obj parse(std::string_view content_type,
                std::vector<std::string_view> parts) {
  ddwaf_obj slot;
  ngx_http_request_t req{};
  auto ct = HttpContentType::for_string(content_type);
  ngx_chain_t chain{};
  ngx_chain_t *chain_cur = nullptr;
  for (auto &&p : parts) {
    chain_cur->buf = new ngx_buf_t{};
    chain_cur->buf->start =
        reinterpret_cast<u_char *>(const_cast<char *>(p.data()));
    chain_cur->buf->end = chain_cur->buf->start + p.size();
    chain_cur->buf->last = chain_cur->buf->end;
    chain_cur = chain_cur->next;
  }
  parse_multipart(slot, req, ct, const ngx_chain_t &chain, std::size_t size,
                  DdwafMemres &memres)

      TEST_CASE("parse_multipart") {
    SECTION("empty") {
      ddwaf_obj slot;
      ngx_http_request_t req;
      HttpContentType ct;
      ngx_chain_t chain;
      std::size_t size = 0;
      DdwafMemres memres;

      REQUIRE(parse_multipart(slot, req, ct, chain, size, memres) == false);
    }
  }
}  // namespace

TEST_CASE("full multipart examples", "[multipart]") {
  SECTION("canonical example") {}
}
