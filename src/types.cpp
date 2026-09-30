#include "fpe/types.hpp"

#include <chrono>
#include <cstddef>

namespace fpe {
namespace {

bool is_continuation_byte(unsigned char byte) noexcept { return (byte & 0xC0u) == 0x80u; }

constexpr std::string_view kReservedDeviceNames[] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};

constexpr bool is_identifier_char(char c) noexcept {
  const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  const bool digit = c >= '0' && c <= '9';
  const bool punctuation = c == '.' || c == '_' || c == ':' || c == '-';
  return alpha || digit || punctuation;
}

constexpr bool is_identifier_edge_char(char c) noexcept {
  const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  const bool digit = c >= '0' && c <= '9';
  return alpha || digit || c == '_';
}

constexpr char ascii_upper(char c) noexcept {
  return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
}

bool is_reserved_device_name(std::string_view text) noexcept {
  const std::size_t dot = text.find('.');
  const std::string_view stem = dot == std::string_view::npos ? text : text.substr(0, dot);
  for (const std::string_view reserved : kReservedDeviceNames) {
    if (stem.size() != reserved.size()) {
      continue;
    }
    bool equal = true;
    for (std::size_t i = 0; i < stem.size(); ++i) {
      if (ascii_upper(stem[i]) != reserved[i]) {
        equal = false;
        break;
      }
    }
    if (equal) {
      return true;
    }
  }
  return false;
}

std::string code_point_name(std::uint32_t code_point) {
  static constexpr char kDigits[] = "0123456789ABCDEF";
  std::string out = "U+";
  for (int shift = 20; shift >= 0; shift -= 4) {
    out.push_back(kDigits[(code_point >> shift) & 0x0Fu]);
  }
  return out;
}

}  // namespace

bool decode_utf8(std::string_view text, std::size_t& offset, std::uint32_t& code_point) noexcept {
  if (offset >= text.size()) {
    return false;
  }
  const auto* bytes = reinterpret_cast<const unsigned char*>(text.data());
  const unsigned char first = bytes[offset];

  if (first < 0x80u) {
    code_point = first;
    offset += 1;
    return true;
  }
  if (first < 0xC2u) {
    // Continuation byte without a lead, or an overlong two-byte lead.
    return false;
  }

  std::size_t length = 0;
  std::uint32_t value = 0;
  if (first < 0xE0u) {
    length = 2;
    value = static_cast<std::uint32_t>(first & 0x1Fu);
  } else if (first < 0xF0u) {
    length = 3;
    value = static_cast<std::uint32_t>(first & 0x0Fu);
  } else if (first < 0xF5u) {
    length = 4;
    value = static_cast<std::uint32_t>(first & 0x07u);
  } else {
    return false;
  }

  if (length > text.size() - offset) {
    return false;
  }
  for (std::size_t i = 1; i < length; ++i) {
    const unsigned char next = bytes[offset + i];
    if (!is_continuation_byte(next)) {
      return false;
    }
    value = (value << 6) | static_cast<std::uint32_t>(next & 0x3Fu);
  }

  if (length == 2 && value < 0x80u) {
    return false;
  }
  if (length == 3 && value < 0x800u) {
    return false;
  }
  if (length == 4 && value < 0x10000u) {
    return false;
  }
  if (value >= 0xD800u && value <= 0xDFFFu) {
    return false;
  }
  if (value > 0x10FFFFu) {
    return false;
  }

  code_point = value;
  offset += length;
  return true;
}

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t offset = 0;
  while (offset < text.size()) {
    std::uint32_t code_point = 0;
    if (!decode_utf8(text, offset, code_point)) {
      return false;
    }
  }
  return true;
}

bool is_forbidden_text_code_point(std::uint32_t code_point) noexcept {
  if (code_point < 0x20u) {
    return true;  // C0 controls, including NUL, TAB, CR, LF
  }
  if (code_point == 0x7Fu) {
    return true;  // DEL
  }
  if (code_point >= 0x80u && code_point <= 0x9Fu) {
    return true;  // C1 controls
  }
  if (code_point == 0x200Eu || code_point == 0x200Fu) {
    return true;  // LRM / RLM
  }
  if (code_point >= 0x202Au && code_point <= 0x202Eu) {
    return true;  // bidi embedding and override
  }
  if (code_point >= 0x2066u && code_point <= 0x2069u) {
    return true;  // bidi isolates
  }
  if (code_point == 0xFEFFu) {
    return true;  // zero-width no-break space / BOM inside text
  }
  return false;
}

std::optional<std::string> text_violation(std::string_view text, std::size_t max_bytes, bool allow_empty) {
  if (text.empty()) {
    if (allow_empty) {
      return std::nullopt;
    }
    return std::string("text is empty");
  }
  if (text.size() > max_bytes) {
    return "text length " + std::to_string(text.size()) + " exceeds the maximum of " +
           std::to_string(max_bytes) + " bytes";
  }
  std::size_t offset = 0;
  while (offset < text.size()) {
    const std::size_t start = offset;
    std::uint32_t code_point = 0;
    if (!decode_utf8(text, offset, code_point)) {
      return "text is not valid UTF-8 at byte offset " + std::to_string(start);
    }
    if (is_forbidden_text_code_point(code_point)) {
      return "text contains forbidden code point " + code_point_name(code_point) + " at byte offset " +
             std::to_string(start);
    }
  }
  return std::nullopt;
}

std::optional<std::string> identifier_violation(std::string_view text, std::size_t max_bytes) {
  if (text.empty()) {
    return std::string("identifier is empty");
  }
  if (text.size() > max_bytes) {
    return "identifier length " + std::to_string(text.size()) + " exceeds the maximum of " +
           std::to_string(max_bytes) + " bytes";
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (!is_identifier_char(text[i])) {
      return "identifier contains a character outside [A-Za-z0-9._:-] at byte offset " + std::to_string(i);
    }
  }
  if (!is_identifier_edge_char(text.front())) {
    return std::string("identifier must begin with an alphanumeric or underscore character");
  }
  if (!is_identifier_edge_char(text.back())) {
    return std::string("identifier must end with an alphanumeric or underscore character");
  }
  if (text.find("..") != std::string_view::npos) {
    return std::string("identifier contains a parent-directory sequence");
  }
  if (is_reserved_device_name(text)) {
    return std::string("identifier is a reserved device name");
  }
  return std::nullopt;
}

bool is_reserved_windows_device_name(std::string_view text) noexcept {
  return is_reserved_device_name(text);
}

TimestampNanos TimestampNanos::now() noexcept {
  const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch).count();
  return TimestampNanos::from_unix_nanos(static_cast<std::int64_t>(nanos));
}

}  // namespace fpe
