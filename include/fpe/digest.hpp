#ifndef FPE_DIGEST_HPP
#define FPE_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "fpe/status.hpp"

namespace fpe {

/// Streaming SHA-256 (FIPS 180-4).
///
/// Implemented first-party because the digest is a load-bearing part of the
/// policy/digest binding contract; it is validated against the published
/// FIPS 180-4 and NIST CAVP known-answer vectors in the test suite.
class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = 32;
  static constexpr std::size_t kBlockBytes = 64;

  Sha256() noexcept { reset(); }

  void reset() noexcept;
  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept { update(text.data(), text.size()); }

  /// Writes the digest and leaves the object reset and reusable.
  void final(std::array<std::byte, kDigestBytes>& out) noexcept;

  static std::array<std::byte, kDigestBytes> hash(std::string_view text) noexcept;

 private:
  void compress(const std::byte* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::byte, kBlockBytes> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
};

/// A 32-byte content digest.
///
/// The all-zero value is the reserved "unset" digest and is never produced by
/// \ref Sha256 for any input, so "no digest" can never be confused with a
/// computed one.
class Digest256 {
 public:
  static constexpr std::size_t kBytes = 32;
  static constexpr std::size_t kHexChars = 64;

  constexpr Digest256() noexcept = default;

  static constexpr Digest256 from_bytes(const std::array<std::byte, kBytes>& bytes) noexcept {
    Digest256 digest;
    digest.bytes_ = bytes;
    return digest;
  }

  /// Computes SHA-256 over \p text.
  static Digest256 of(std::string_view text) noexcept {
    return from_bytes(Sha256::hash(text));
  }

  /// Parses exactly 64 hexadecimal characters. Rejects any other length,
  /// non-hexadecimal characters, and a leading "0x" prefix.
  static Result<Digest256> from_hex(std::string_view hex);

  std::string to_hex() const;

  const std::array<std::byte, kBytes>& bytes() const noexcept { return bytes_; }
  const std::byte* data() const noexcept { return bytes_.data(); }

  bool is_zero() const noexcept;

  friend bool operator==(const Digest256& a, const Digest256& b) noexcept { return a.bytes_ == b.bytes_; }
  friend std::strong_ordering operator<=>(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ <=> b.bytes_;
  }

 private:
  std::array<std::byte, kBytes> bytes_{};
};

/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320).
///
/// Used as a fast corruption checksum alongside the strong digest, so that
/// accidental corruption and deliberate substitution are distinguishable in
/// diagnostics.
std::uint32_t crc32(const void* data, std::size_t size) noexcept;
std::uint32_t crc32(std::string_view text) noexcept;

/// Lowercase hexadecimal encoding of raw bytes.
std::string to_hex(const void* data, std::size_t size);

}  // namespace fpe

#endif  // FPE_DIGEST_HPP
