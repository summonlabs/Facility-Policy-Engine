#ifndef FPE_JSON_HPP
#define FPE_JSON_HPP

#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "fpe/limits.hpp"
#include "fpe/status.hpp"

namespace fpe {

enum class JsonType : std::uint8_t { Null = 0, Boolean = 1, Integer = 2, String = 3, Array = 4, Object = 5 };

std::string_view json_type_name(JsonType type) noexcept;

/// An immutable-in-practice JSON value.
///
/// The model is deliberately narrower than JSON: there is no floating point and
/// no null-versus-absent ambiguity inside policy. Integers are 64-bit signed, so
/// a policy number can never silently become a rounded double. Object members
/// are held in a byte-ordered map, which makes the canonical serialization of a
/// value independent of the order in which its members were written.
class JsonValue {
 public:
  using Array = std::vector<JsonValue>;
  using Object = std::map<std::string, JsonValue, std::less<>>;

  JsonValue() noexcept = default;  // null

  static JsonValue null() noexcept { return JsonValue(); }
  static JsonValue boolean(bool value) noexcept;
  static JsonValue integer(std::int64_t value) noexcept;
  static JsonValue string(std::string text) noexcept;
  static JsonValue array(Array items) noexcept;
  static JsonValue object(Object members) noexcept;

  JsonType type() const noexcept;

  bool is_null() const noexcept { return type() == JsonType::Null; }
  bool is_boolean() const noexcept { return type() == JsonType::Boolean; }
  bool is_integer() const noexcept { return type() == JsonType::Integer; }
  bool is_string() const noexcept { return type() == JsonType::String; }
  bool is_array() const noexcept { return type() == JsonType::Array; }
  bool is_object() const noexcept { return type() == JsonType::Object; }

  const bool* as_boolean() const noexcept;
  const std::int64_t* as_integer() const noexcept;
  const std::string* as_string() const noexcept;
  const Array* as_array() const noexcept;
  const Object* as_object() const noexcept;

  /// Object member lookup. Returns nullptr when absent or when this is not an
  /// object, so an absent member is never confused with a member whose value is
  /// null.
  const JsonValue* member(std::string_view key) const noexcept;

  /// Array element lookup. Returns nullptr when out of range or not an array.
  const JsonValue* element(std::size_t index) const noexcept;

  std::size_t member_count() const noexcept;

 private:
  std::variant<std::monostate, bool, std::int64_t, std::string, Array, Object> value_;
};

/// Strict JSON parser.
///
/// Accepted: exactly one top-level value, surrounded by optional whitespace.
/// Rejected: a UTF-8 BOM, invalid UTF-8, duplicate object keys, raw control
/// characters inside strings, any numeric form other than an optional minus
/// followed by an integer with no leading zeros, values beyond 64-bit signed
/// range, container nesting deeper than \ref Limits::max_json_depth, more than
/// \ref Limits::max_json_nodes values, and trailing content after the value.
///
/// Every rejection carries the byte offset of the offending byte.
Result<JsonValue> parse_json(std::string_view text, const Limits& limits);

/// Appends the canonical serialization of \p value to \p out.
///
/// Canonical form: object members in byte order, no insignificant whitespace,
/// integers in decimal with no leading zeros, and the shortest escape for every
/// string byte. Two values that compare equal serialize to identical bytes on
/// every platform, which is what makes a digest over the serialization a
/// portable identity.
void write_canonical_json(const JsonValue& value, std::string& out);

std::string to_canonical_json(const JsonValue& value);

/// Verifies that \p text is the canonical serialization of its own parse,
/// ignoring trailing whitespace. Used to reject non-canonical documents at
/// ingestion instead of silently re-canonicalizing them.
Status require_canonical_json(std::string_view text, const Limits& limits);

// ---- Schema helpers -------------------------------------------------------
//
// These keep document-shape validation uniform: every diagnostic names the
// exact JSON path that failed, and a type mismatch can never be mistaken for a
// missing field.

/// Fails when \p object carries a member outside \p allowed.
Status json_reject_unknown_members(const JsonValue& object, std::initializer_list<std::string_view> allowed,
                                  std::string_view path);

Result<const JsonValue*> json_require_member(const JsonValue& object, std::string_view key, std::string_view path);
const JsonValue* json_optional_member(const JsonValue& object, std::string_view key) noexcept;

Result<bool> json_as_boolean(const JsonValue& value, std::string_view path);
Result<std::int64_t> json_as_integer(const JsonValue& value, std::string_view path);
Result<std::string_view> json_as_string(const JsonValue& value, std::string_view path);
Result<const JsonValue::Array*> json_as_array(const JsonValue& value, std::string_view path);
Result<const JsonValue::Object*> json_as_object(const JsonValue& value, std::string_view path);

/// Builds "path.member" or "path[index]" diagnostics.
std::string json_child_path(std::string_view path, std::string_view key);
std::string json_index_path(std::string_view path, std::size_t index);

}  // namespace fpe

#endif  // FPE_JSON_HPP
