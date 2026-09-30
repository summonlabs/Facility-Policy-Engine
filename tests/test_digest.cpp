#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "fpe/digest.hpp"
#include "test_support.hpp"

using fpe::Digest256;
using fpe::Sha256;

namespace {

std::string hash_hex(std::string_view text) { return Digest256::of(text).to_hex(); }

std::string streaming_hex(std::string_view text, std::size_t chunk) {
  Sha256 hasher;
  std::size_t offset = 0;
  while (offset < text.size()) {
    const std::size_t take = std::min(chunk, text.size() - offset);
    hasher.update(text.data() + offset, take);
    offset += take;
  }
  std::array<std::byte, Sha256::kDigestBytes> digest{};
  hasher.final(digest);
  return Digest256::from_bytes(digest).to_hex();
}

}  // namespace

FPE_TEST(digest_sha256_known_answer_vectors) {
  FPE_CHECK_EQ(hash_hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  FPE_CHECK_EQ(hash_hex("abc"),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  FPE_CHECK_EQ(hash_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
               std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  FPE_CHECK_EQ(
      hash_hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
               "mnopqrstnopqrstu"),
      std::string("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
}

FPE_TEST(digest_sha256_million_byte_vector) {
  Sha256 hasher;
  const std::string block(1000, 'a');
  for (int i = 0; i < 1000; ++i) {
    hasher.update(block);
  }
  std::array<std::byte, Sha256::kDigestBytes> digest{};
  hasher.final(digest);
  FPE_CHECK_EQ(Digest256::from_bytes(digest).to_hex(),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

FPE_TEST(digest_streaming_matches_one_shot_for_every_chunking) {
  const std::string message =
      "The policy engine hashes exactly the bytes it is given, and never anything else.";
  const std::string expected = hash_hex(message);
  for (std::size_t chunk = 1; chunk <= 64; ++chunk) {
    FPE_CHECK_EQ(streaming_hex(message, chunk), expected);
  }
  const std::size_t lengths[] = {0,  1,  55, 56,  63,  64,
                                 65, 119, 120, 127, 128};
  for (const std::size_t length : lengths) {
    const std::string padded(length, 'x');
    FPE_CHECK_EQ(streaming_hex(padded, 7), hash_hex(padded));
  }
}

FPE_TEST(digest_is_reusable_after_final) {
  Sha256 hasher;
  hasher.update("abc");
  std::array<std::byte, Sha256::kDigestBytes> first{};
  hasher.final(first);
  hasher.update("abc");
  std::array<std::byte, Sha256::kDigestBytes> second{};
  hasher.final(second);
  FPE_CHECK(first == second);
}

FPE_TEST(digest_crc32_known_answer_vectors) {
  FPE_CHECK_EQ(fpe::crc32("123456789"), 0xCBF43926u);
  FPE_CHECK_EQ(fpe::crc32(""), 0u);
  FPE_CHECK_EQ(fpe::crc32("The quick brown fox jumps over the lazy dog"), 0x414FA339u);
  FPE_CHECK_EQ(fpe::crc32("a"), 0xE8B7BE43u);
}

FPE_TEST(digest_hex_round_trip_and_validation) {
  const Digest256 digest = Digest256::of("facility");
  const std::string hex = digest.to_hex();
  FPE_CHECK_EQ(hex.size(), std::size_t{64});
  auto parsed = Digest256::from_hex(hex);
  FPE_REQUIRE(parsed.has_value());
  FPE_CHECK(parsed.value() == digest);

  std::string upper = hex;
  for (char& c : upper) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  auto parsed_upper = Digest256::from_hex(upper);
  FPE_REQUIRE(parsed_upper.has_value());
  FPE_CHECK(parsed_upper.value() == digest);

  FPE_CHECK(!Digest256::from_hex(hex.substr(0, 63)).has_value());
  FPE_CHECK(!Digest256::from_hex(hex + "0").has_value());
  FPE_CHECK(!Digest256::from_hex("").has_value());
  std::string non_hex = hex;
  non_hex[5] = 'z';
  FPE_CHECK(!Digest256::from_hex(non_hex).has_value());
  FPE_CHECK(!Digest256::from_hex("0x" + hex.substr(2)).has_value());
}

FPE_TEST(digest_zero_value_is_reserved_and_never_produced) {
  const Digest256 zero;
  FPE_CHECK(zero.is_zero());
  FPE_CHECK(!Digest256::of("").is_zero());
  FPE_CHECK(!Digest256::of("facility").is_zero());
  auto parsed = Digest256::from_hex(std::string(64, '0'));
  FPE_REQUIRE(parsed.has_value());
  FPE_CHECK(parsed.value().is_zero());
}

FPE_TEST(digest_hex_helper_is_lowercase_and_exact) {
  const unsigned char raw[] = {0x00, 0x0F, 0xA0, 0xFF};
  FPE_CHECK_EQ(fpe::to_hex(raw, sizeof(raw)), std::string("000fa0ff"));
  FPE_CHECK_EQ(fpe::to_hex(raw, 0), std::string(""));
}
