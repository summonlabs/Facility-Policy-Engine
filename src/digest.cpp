#include "fpe/digest.hpp"

#include <cstring>

namespace fpe {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
  return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
  return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
  return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
  return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}

constexpr std::array<std::uint32_t, 256> make_crc32_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < 256u; ++index) {
    std::uint32_t value = index;
    for (int bit = 0; bit < 8; ++bit) {
      value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
    }
    table[index] = value;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32Table = make_crc32_table();

constexpr std::byte kZeroByte{0};
constexpr std::byte kPaddingLeadByte{0x80};

int hex_digit_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

void Sha256::reset() noexcept {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  buffer_.fill(kZeroByte);
  buffered_ = 0;
  total_bytes_ = 0;
}

void Sha256::compress(const std::byte* block) noexcept {
  std::uint32_t schedule[64];
  for (std::size_t i = 0; i < 16; ++i) {
    schedule[i] = (std::to_integer<std::uint32_t>(block[i * 4]) << 24) |
                  (std::to_integer<std::uint32_t>(block[i * 4 + 1]) << 16) |
                  (std::to_integer<std::uint32_t>(block[i * 4 + 2]) << 8) |
                  std::to_integer<std::uint32_t>(block[i * 4 + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    schedule[i] = small_sigma1(schedule[i - 2]) + schedule[i - 7] + small_sigma0(schedule[i - 15]) +
                  schedule[i - 16];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t t1 = h + big_sigma1(e) + choose(e, f, g) + kRoundConstants[i] + schedule[i];
    const std::uint32_t t2 = big_sigma0(a) + majority(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) noexcept {
  if (size == 0) {
    return;
  }
  const auto* bytes = static_cast<const std::byte*>(data);
  total_bytes_ += static_cast<std::uint64_t>(size);

  if (buffered_ > 0) {
    const std::size_t needed = kBlockBytes - buffered_;
    const std::size_t taken = size < needed ? size : needed;
    std::memcpy(buffer_.data() + buffered_, bytes, taken);
    buffered_ += taken;
    bytes += taken;
    size -= taken;
    if (buffered_ == kBlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }

  while (size >= kBlockBytes) {
    compress(bytes);
    bytes += kBlockBytes;
    size -= kBlockBytes;
  }

  if (size > 0) {
    std::memcpy(buffer_.data(), bytes, size);
    buffered_ = size;
  }
}

void Sha256::final(std::array<std::byte, kDigestBytes>& out) noexcept {
  // The message length is encoded modulo 2^64, as FIPS 180-4 specifies.
  const std::uint64_t bit_length = total_bytes_ << 3;

  buffer_[buffered_] = kPaddingLeadByte;
  buffered_ += 1;
  if (buffered_ > 56) {
    std::memset(buffer_.data() + buffered_, 0, kBlockBytes - buffered_);
    compress(buffer_.data());
    buffered_ = 0;
  }
  std::memset(buffer_.data() + buffered_, 0, kBlockBytes - buffered_);
  for (std::size_t i = 0; i < 8; ++i) {
    buffer_[56 + i] = static_cast<std::byte>((bit_length >> (56u - (8u * i))) & 0xFFu);
  }
  compress(buffer_.data());

  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint32_t word = state_[i];
    out[i * 4] = static_cast<std::byte>((word >> 24) & 0xFFu);
    out[i * 4 + 1] = static_cast<std::byte>((word >> 16) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::byte>((word >> 8) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::byte>(word & 0xFFu);
  }
  reset();
}

std::array<std::byte, Sha256::kDigestBytes> Sha256::hash(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.update(text.data(), text.size());
  std::array<std::byte, kDigestBytes> out{};
  hasher.final(out);
  return out;
}

Result<Digest256> Digest256::from_hex(std::string_view hex) {
  if (hex.size() != kHexChars) {
    return Status::failure(ErrorCode::OutOfRange, "digest must be exactly 64 hexadecimal characters, got " +
                                                      std::to_string(hex.size()));
  }
  std::array<std::byte, kBytes> bytes{};
  for (std::size_t i = 0; i < kBytes; ++i) {
    const int high = hex_digit_value(hex[i * 2]);
    const int low = hex_digit_value(hex[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return Status::failure(ErrorCode::OutOfRange,
                             "digest contains a non-hexadecimal character at byte offset " + std::to_string(i * 2));
    }
    bytes[i] = static_cast<std::byte>((high << 4) | low);
  }
  return Digest256::from_bytes(bytes);
}

std::string Digest256::to_hex() const { return fpe::to_hex(bytes_.data(), bytes_.size()); }

bool Digest256::is_zero() const noexcept {
  for (const std::byte byte : bytes_) {
    if (byte != kZeroByte) {
      return false;
    }
  }
  return true;
}

std::uint32_t crc32(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::uint32_t crc = 0xFFFFFFFFu;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kCrc32Table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32(std::string_view text) noexcept { return crc32(text.data(), text.size()); }

std::string to_hex(const void* data, std::size_t size) {
  static constexpr char kDigits[] = "0123456789abcdef";
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::string out;
  out.resize(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out[i * 2] = kDigits[(bytes[i] >> 4) & 0x0Fu];
    out[i * 2 + 1] = kDigits[bytes[i] & 0x0Fu];
  }
  return out;
}

}  // namespace fpe
