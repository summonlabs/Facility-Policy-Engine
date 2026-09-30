#include "fpe/json.hpp"

#include <cstddef>
#include <limits>
#include <string>
#include <utility>

#include "fpe/types.hpp"

namespace fpe {
namespace {

constexpr bool is_json_whitespace(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

constexpr bool is_hex_digit(char c) noexcept {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

constexpr unsigned hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return static_cast<unsigned>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<unsigned>(c - 'a' + 10);
  }
  return static_cast<unsigned>(c - 'A' + 10);
}

void append_utf8(std::string& out, std::uint32_t code_point) {
  if (code_point < 0x80u) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800u) {
    out.push_back(static_cast<char>(0xC0u | (code_point >> 6)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else if (code_point < 0x10000u) {
    out.push_back(static_cast<char>(0xE0u | (code_point >> 12)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else {
    out.push_back(static_cast<char>(0xF0u | (code_point >> 18)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  }
}

Status type_mismatch(const JsonValue& value, std::string_view path, std::string_view expected) {
  return Status::failure(ErrorCode::JsonTypeMismatch, std::string(path) + " must be " + std::string(expected) +
                                                       ", found " + std::string(json_type_name(value.type())));
}

void write_canonical_string(std::string_view text, std::string& out) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  out.push_back('"');
  for (const char raw : text) {
    const unsigned char byte = static_cast<unsigned char>(raw);
    switch (byte) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\b':
        out.append("\\b");
        break;
      case '\f':
        out.append("\\f");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (byte < 0x20u || byte == 0x7Fu) {
          out.append("\\u00");
          out.push_back(kHexDigits[(byte >> 4) & 0x0Fu]);
          out.push_back(kHexDigits[byte & 0x0Fu]);
        } else {
          out.push_back(raw);
        }
        break;
    }
  }
  out.push_back('"');
}

/// Strict recursive-descent parser. Never allocates more than the input size,
/// never recurses deeper than the configured limit, and never accepts a second
/// interpretation of the same bytes.
class Parser {
 public:
  Parser(std::string_view text, const Limits& limits) noexcept : text_(text), limits_(limits) {}

  Result<JsonValue> parse_document() {
    if (text_.size() >= 3 && static_cast<unsigned char>(text_[0]) == 0xEFu &&
        static_cast<unsigned char>(text_[1]) == 0xBBu && static_cast<unsigned char>(text_[2]) == 0xBFu) {
      return Status::failure(ErrorCode::JsonSyntax, "document begins with a UTF-8 byte order mark at byte offset 0");
    }
    skip_whitespace();
    if (at_end()) {
      return fail("document is empty");
    }
    auto value = parse_value(0);
    if (!value) {
      return value.status();
    }
    skip_whitespace();
    if (!at_end()) {
      return Status::failure(ErrorCode::JsonTrailingContent,
                             "unexpected content after the top-level value at byte offset " +
                                 std::to_string(position_));
    }
    return std::move(value).value();
  }

 private:
  bool at_end() const noexcept { return position_ >= text_.size(); }
  char peek() const noexcept { return text_[position_]; }

  void skip_whitespace() noexcept {
    while (!at_end() && is_json_whitespace(text_[position_])) {
      position_ += 1;
    }
  }

  Status fail(std::string_view what) const {
    return Status::failure(ErrorCode::JsonSyntax,
                           std::string(what) + " at byte offset " + std::to_string(position_));
  }

  Result<JsonValue> parse_value(std::size_t depth) {
    if (nodes_ >= limits_.max_json_nodes) {
      return Status::failure(ErrorCode::JsonNodeLimit,
                             "document contains more than the maximum of " +
                                 std::to_string(limits_.max_json_nodes) + " values (byte offset " +
                                 std::to_string(position_) + ")");
    }
    if (depth > limits_.max_json_depth) {
      return Status::failure(ErrorCode::JsonDepthExceeded,
                             "document nests deeper than the maximum of " +
                                 std::to_string(limits_.max_json_depth) + " levels (byte offset " +
                                 std::to_string(position_) + ")");
    }
    if (at_end()) {
      return fail("unexpected end of document");
    }
    nodes_ += 1;

    switch (peek()) {
      case '{':
        return parse_object(depth);
      case '[':
        return parse_array(depth);
      case '"': {
        auto text = parse_string();
        if (!text) {
          return text.status();
        }
        return JsonValue::string(std::move(text).value());
      }
      case 't':
        return parse_literal("true", JsonValue::boolean(true));
      case 'f':
        return parse_literal("false", JsonValue::boolean(false));
      case 'n':
        return parse_literal("null", JsonValue::null());
      default:
        break;
    }
    if (peek() == '-' || is_digit(peek())) {
      return parse_number();
    }
    return fail("unexpected character");
  }

  Result<JsonValue> parse_literal(std::string_view literal, JsonValue value) {
    if (text_.compare(position_, literal.size(), literal) != 0) {
      return fail("invalid literal");
    }
    position_ += literal.size();
    return value;
  }

  Result<JsonValue> parse_object(std::size_t depth) {
    position_ += 1;  // consume '{'
    JsonValue::Object members;
    skip_whitespace();
    if (!at_end() && peek() == '}') {
      position_ += 1;
      return JsonValue::object(std::move(members));
    }
    for (;;) {
      skip_whitespace();
      if (at_end()) {
        return fail("unterminated object");
      }
      if (peek() != '"') {
        return fail("object member name must be a string");
      }
      auto key = parse_string();
      if (!key) {
        return key.status();
      }
      std::string name = std::move(key).value();
      skip_whitespace();
      if (at_end() || peek() != ':') {
        return fail("expected ':' after an object member name");
      }
      position_ += 1;
      skip_whitespace();
      auto value = parse_value(depth + 1);
      if (!value) {
        return value.status();
      }
      const auto inserted = members.emplace(std::move(name), std::move(value).value());
      if (!inserted.second) {
        return Status::failure(ErrorCode::JsonDuplicateKey, "duplicate object member '" + inserted.first->first +
                                                                "' at byte offset " + std::to_string(position_));
      }
      skip_whitespace();
      if (at_end()) {
        return fail("unterminated object");
      }
      if (peek() == ',') {
        position_ += 1;
        continue;
      }
      if (peek() == '}') {
        position_ += 1;
        break;
      }
      return fail("expected ',' or '}' in object");
    }
    return JsonValue::object(std::move(members));
  }

  Result<JsonValue> parse_array(std::size_t depth) {
    position_ += 1;  // consume '['
    JsonValue::Array items;
    skip_whitespace();
    if (!at_end() && peek() == ']') {
      position_ += 1;
      return JsonValue::array(std::move(items));
    }
    for (;;) {
      skip_whitespace();
      auto value = parse_value(depth + 1);
      if (!value) {
        return value.status();
      }
      items.push_back(std::move(value).value());
      skip_whitespace();
      if (at_end()) {
        return fail("unterminated array");
      }
      if (peek() == ',') {
        position_ += 1;
        continue;
      }
      if (peek() == ']') {
        position_ += 1;
        break;
      }
      return fail("expected ',' or ']' in array");
    }
    return JsonValue::array(std::move(items));
  }

  Result<std::string> parse_string() {
    const std::size_t start = position_;
    position_ += 1;  // consume '"'
    std::string out;
    for (;;) {
      if (at_end()) {
        position_ = start;
        return fail("unterminated string");
      }
      const unsigned char byte = static_cast<unsigned char>(text_[position_]);
      if (byte == static_cast<unsigned char>('"')) {
        position_ += 1;
        break;
      }
      if (byte == static_cast<unsigned char>('\\')) {
        position_ += 1;
        if (at_end()) {
          return fail("unterminated escape sequence");
        }
        const char escape = text_[position_];
        position_ += 1;
        switch (escape) {
          case '"':
            out.push_back('"');
            break;
          case '\\':
            out.push_back('\\');
            break;
          case '/':
            out.push_back('/');
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            auto code_point = parse_unicode_escape();
            if (!code_point) {
              return code_point.status();
            }
            append_utf8(out, code_point.value());
            break;
          }
          default:
            return fail("unrecognized escape sequence");
        }
        continue;
      }
      if (byte < 0x20u) {
        return Status::failure(ErrorCode::JsonSyntax,
                               "string contains a raw control character at byte offset " +
                                   std::to_string(position_) + "; it must be escaped");
      }
      std::size_t offset = position_;
      std::uint32_t code_point = 0;
      if (!decode_utf8(text_, offset, code_point)) {
        return Status::failure(ErrorCode::InvalidUtf8,
                               "string contains invalid UTF-8 at byte offset " + std::to_string(position_));
      }
      out.append(text_.substr(position_, offset - position_));
      position_ = offset;
      if (static_cast<std::uint64_t>(out.size()) > limits_.max_bundle_bytes) {
        return Status::failure(ErrorCode::LimitExceeded,
                               "string exceeds the maximum of " + std::to_string(limits_.max_bundle_bytes) +
                                   " bytes");
      }
    }
    return out;
  }

  Result<std::uint32_t> parse_hex4() {
    if (position_ + 4 > text_.size()) {
      return fail("truncated Unicode escape");
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
      const char c = text_[position_ + i];
      if (!is_hex_digit(c)) {
        return fail("invalid hexadecimal digit in Unicode escape");
      }
      value = (value << 4) | hex_value(c);
    }
    position_ += 4;
    return value;
  }

  Result<std::uint32_t> parse_unicode_escape() {
    auto first = parse_hex4();
    if (!first) {
      return first.status();
    }
    const std::uint32_t value = first.value();
    if (value >= 0xD800u && value <= 0xDBFFu) {
      if (position_ + 1 >= text_.size() || text_[position_] != '\\' || text_[position_ + 1] != 'u') {
        return fail("high surrogate is not followed by a low surrogate escape");
      }
      position_ += 2;
      auto second = parse_hex4();
      if (!second) {
        return second.status();
      }
      const std::uint32_t low = second.value();
      if (low < 0xDC00u || low > 0xDFFFu) {
        return fail("high surrogate is not followed by a low surrogate escape");
      }
      return 0x10000u + ((value - 0xD800u) << 10) + (low - 0xDC00u);
    }
    if (value >= 0xDC00u && value <= 0xDFFFu) {
      return fail("unpaired low surrogate escape");
    }
    return value;
  }

  Result<JsonValue> parse_number() {
    const std::size_t start = position_;
    bool negative = false;
    if (peek() == '-') {
      negative = true;
      position_ += 1;
    }
    if (at_end() || !is_digit(peek())) {
      return fail("expected a digit in number");
    }
    if (peek() == '0') {
      position_ += 1;
      if (!at_end() && is_digit(peek())) {
        return fail("number has a leading zero");
      }
    } else {
      while (!at_end() && is_digit(peek())) {
        position_ += 1;
      }
    }
    if (!at_end() && (peek() == '.' || peek() == 'e' || peek() == 'E')) {
      return Status::failure(ErrorCode::JsonSyntax,
                             "fractional and exponent number forms are not supported at byte offset " +
                                 std::to_string(position_));
    }

    const std::size_t digit_start = start + (negative ? 1u : 0u);
    const std::string_view digits = text_.substr(digit_start, position_ - digit_start);
    const std::uint64_t limit =
        negative ? 9223372036854775808ull : 9223372036854775807ull;
    std::uint64_t magnitude = 0;
    for (const char c : digits) {
      const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
      if (magnitude > (limit - digit) / 10u) {
        return Status::failure(ErrorCode::JsonNumberOutOfRange,
                               "integer literal at byte offset " + std::to_string(start) +
                                   " is outside the signed 64-bit range");
      }
      magnitude = (magnitude * 10u) + digit;
    }

    if (!negative) {
      return JsonValue::integer(static_cast<std::int64_t>(magnitude));
    }
    if (magnitude == 9223372036854775808ull) {
      return JsonValue::integer(std::numeric_limits<std::int64_t>::min());
    }
    return JsonValue::integer(-static_cast<std::int64_t>(magnitude));
  }

  std::string_view text_;
  const Limits& limits_;
  std::size_t position_ = 0;
  std::size_t nodes_ = 0;
};

}  // namespace

std::string_view json_type_name(JsonType type) noexcept {
  switch (type) {
    case JsonType::Null:
      return "null";
    case JsonType::Boolean:
      return "a boolean";
    case JsonType::Integer:
      return "an integer";
    case JsonType::String:
      return "a string";
    case JsonType::Array:
      return "an array";
    case JsonType::Object:
      return "an object";
  }
  return "an unknown type";
}

JsonValue JsonValue::boolean(bool value) noexcept {
  JsonValue out;
  out.value_ = value;
  return out;
}

JsonValue JsonValue::integer(std::int64_t value) noexcept {
  JsonValue out;
  out.value_ = value;
  return out;
}

JsonValue JsonValue::string(std::string text) noexcept {
  JsonValue out;
  out.value_ = std::move(text);
  return out;
}

JsonValue JsonValue::array(Array items) noexcept {
  JsonValue out;
  out.value_ = std::move(items);
  return out;
}

JsonValue JsonValue::object(Object members) noexcept {
  JsonValue out;
  out.value_ = std::move(members);
  return out;
}

JsonType JsonValue::type() const noexcept {
  if (std::holds_alternative<std::monostate>(value_)) {
    return JsonType::Null;
  }
  if (std::holds_alternative<bool>(value_)) {
    return JsonType::Boolean;
  }
  if (std::holds_alternative<std::int64_t>(value_)) {
    return JsonType::Integer;
  }
  if (std::holds_alternative<std::string>(value_)) {
    return JsonType::String;
  }
  if (std::holds_alternative<Array>(value_)) {
    return JsonType::Array;
  }
  return JsonType::Object;
}

const bool* JsonValue::as_boolean() const noexcept { return std::get_if<bool>(&value_); }
const std::int64_t* JsonValue::as_integer() const noexcept { return std::get_if<std::int64_t>(&value_); }
const std::string* JsonValue::as_string() const noexcept { return std::get_if<std::string>(&value_); }
const JsonValue::Array* JsonValue::as_array() const noexcept { return std::get_if<Array>(&value_); }
const JsonValue::Object* JsonValue::as_object() const noexcept { return std::get_if<Object>(&value_); }

const JsonValue* JsonValue::member(std::string_view key) const noexcept {
  const auto* members = std::get_if<Object>(&value_);
  if (members == nullptr) {
    return nullptr;
  }
  const auto found = members->find(key);
  if (found == members->end()) {
    return nullptr;
  }
  return &found->second;
}

const JsonValue* JsonValue::element(std::size_t index) const noexcept {
  const auto* items = std::get_if<Array>(&value_);
  if (items == nullptr || index >= items->size()) {
    return nullptr;
  }
  return &(*items)[index];
}

std::size_t JsonValue::member_count() const noexcept {
  const auto* members = std::get_if<Object>(&value_);
  return members == nullptr ? 0u : members->size();
}

Result<JsonValue> parse_json(std::string_view text, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  Parser parser(text, limits);
  return parser.parse_document();
}

void write_canonical_json(const JsonValue& value, std::string& out) {
  switch (value.type()) {
    case JsonType::Null:
      out.append("null");
      return;
    case JsonType::Boolean:
      out.append(*value.as_boolean() ? "true" : "false");
      return;
    case JsonType::Integer:
      out.append(std::to_string(*value.as_integer()));
      return;
    case JsonType::String:
      write_canonical_string(*value.as_string(), out);
      return;
    case JsonType::Array: {
      const auto& items = *value.as_array();
      out.push_back('[');
      bool first = true;
      for (const auto& item : items) {
        if (!first) {
          out.push_back(',');
        }
        first = false;
        write_canonical_json(item, out);
      }
      out.push_back(']');
      return;
    }
    case JsonType::Object: {
      const auto& members = *value.as_object();
      out.push_back('{');
      bool first = true;
      for (const auto& entry : members) {
        if (!first) {
          out.push_back(',');
        }
        first = false;
        write_canonical_string(entry.first, out);
        out.push_back(':');
        write_canonical_json(entry.second, out);
      }
      out.push_back('}');
      return;
    }
  }
}

std::string to_canonical_json(const JsonValue& value) {
  std::string out;
  write_canonical_json(value, out);
  return out;
}

Status require_canonical_json(std::string_view text, const Limits& limits) {
  auto parsed = parse_json(text, limits);
  if (!parsed) {
    return parsed.status();
  }
  const std::string canonical = to_canonical_json(parsed.value());
  std::size_t end = text.size();
  while (end > 0 && is_json_whitespace(text[end - 1])) {
    end -= 1;
  }
  const std::string_view body = text.substr(0, end);
  if (body == canonical) {
    return Status::success();
  }
  const std::size_t shared = body.size() < canonical.size() ? body.size() : canonical.size();
  std::size_t mismatch = 0;
  while (mismatch < shared && body[mismatch] == canonical[mismatch]) {
    mismatch += 1;
  }
  return Status::failure(ErrorCode::JsonNotCanonical,
                         "document is not in canonical form; first difference at byte offset " +
                             std::to_string(mismatch));
}

Status json_reject_unknown_members(const JsonValue& object, std::initializer_list<std::string_view> allowed,
                                   std::string_view path) {
  const auto* members = object.as_object();
  if (members == nullptr) {
    return type_mismatch(object, path, "an object");
  }
  Status failure = Status::success();
  for (const auto& entry : *members) {
    bool known = false;
    for (const std::string_view allowed_name : allowed) {
      if (allowed_name == entry.first) {
        known = true;
        break;
      }
    }
    if (!known) {
      Status unknown_member = Status::failure(ErrorCode::JsonUnknownField,
                                              "unknown member '" + entry.first + "' at " + std::string(path));
      failure = failure.ok() ? std::move(unknown_member)
                             : Status::prefer(std::move(failure), std::move(unknown_member));
    }
  }
  return failure;
}

Result<const JsonValue*> json_require_member(const JsonValue& object, std::string_view key, std::string_view path) {
  if (object.as_object() == nullptr) {
    return type_mismatch(object, path, "an object");
  }
  const JsonValue* found = object.member(key);
  if (found == nullptr) {
    return Status::failure(ErrorCode::JsonMissingField,
                           "missing required member '" + std::string(key) + "' at " + std::string(path));
  }
  return found;
}

const JsonValue* json_optional_member(const JsonValue& object, std::string_view key) noexcept {
  return object.member(key);
}

Result<bool> json_as_boolean(const JsonValue& value, std::string_view path) {
  const bool* found = value.as_boolean();
  if (found == nullptr) {
    return type_mismatch(value, path, "a boolean");
  }
  return *found;
}

Result<std::int64_t> json_as_integer(const JsonValue& value, std::string_view path) {
  const std::int64_t* found = value.as_integer();
  if (found == nullptr) {
    return type_mismatch(value, path, "an integer");
  }
  return *found;
}

Result<std::string_view> json_as_string(const JsonValue& value, std::string_view path) {
  const std::string* found = value.as_string();
  if (found == nullptr) {
    return type_mismatch(value, path, "a string");
  }
  return std::string_view(*found);
}

Result<const JsonValue::Array*> json_as_array(const JsonValue& value, std::string_view path) {
  const auto* found = value.as_array();
  if (found == nullptr) {
    return type_mismatch(value, path, "an array");
  }
  return found;
}

Result<const JsonValue::Object*> json_as_object(const JsonValue& value, std::string_view path) {
  const auto* found = value.as_object();
  if (found == nullptr) {
    return type_mismatch(value, path, "an object");
  }
  return found;
}

std::string json_child_path(std::string_view path, std::string_view key) {
  std::string out(path);
  if (!out.empty()) {
    out.push_back('.');
  }
  out.append(key);
  return out;
}

std::string json_index_path(std::string_view path, std::size_t index) {
  std::string out(path);
  out.push_back('[');
  out.append(std::to_string(index));
  out.push_back(']');
  return out;
}

}  // namespace fpe
