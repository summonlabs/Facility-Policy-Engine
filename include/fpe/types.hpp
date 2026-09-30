#ifndef FPE_TYPES_HPP
#define FPE_TYPES_HPP

#include <cstdint>
#include <compare>
#include <optional>
#include <string>
#include <string_view>

#include "fpe/status.hpp"

namespace fpe {

/// Strict UTF-8 validation (RFC 3629): rejects overlong encodings, UTF-16
/// surrogate code points, and values above U+10FFFF.
bool is_valid_utf8(std::string_view text) noexcept;

/// Decodes one code point starting at \p offset. Returns false on an invalid
/// sequence, leaving \p offset unchanged; otherwise advances \p offset past
/// the code point and writes it to \p code_point.
bool decode_utf8(std::string_view text, std::size_t& offset, std::uint32_t& code_point) noexcept;

/// True for code points that must never appear in policy text: C0 and C1
/// controls, DEL, and the Unicode bidirectional embedding/override/isolate
/// characters that make a displayed document differ from its bytes.
bool is_forbidden_text_code_point(std::uint32_t code_point) noexcept;

/// Returns the reason \p text is not acceptable as a policy text field, or
/// nullopt when it is acceptable. \p max_bytes is an inclusive byte bound.
std::optional<std::string> text_violation(std::string_view text, std::size_t max_bytes, bool allow_empty);

/// Returns the reason \p text is not acceptable as an identifier, or nullopt.
std::optional<std::string> identifier_violation(std::string_view text, std::size_t max_bytes);

/// True when \p text names a reserved Windows device, compared
/// case-insensitively against the component before the first '.'.
///
/// Such a component is refused everywhere a name can reach the file system,
/// because the device namespace makes its behaviour path- and depth-dependent.
bool is_reserved_windows_device_name(std::string_view text) noexcept;

/// Monotonic counter that refuses to wrap.
///
/// Generations, epochs, revisions, and sequences are all modelled with this
/// type so that a signed/unsigned or positional mix-up between them cannot
/// compile, and so that overflow is an explicit, reportable failure rather than
/// silent wraparound.
template <class Tag>
class Counter {
 public:
  static constexpr std::uint64_t kMax = 0xFFFFFFFFFFFFFFFFull;

  constexpr Counter() noexcept = default;

  static constexpr Counter from_raw(std::uint64_t value) noexcept {
    Counter counter;
    counter.value_ = value;
    return counter;
  }

  constexpr std::uint64_t raw() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  /// Saturating increment: reports failure instead of wrapping.
  bool try_increment() noexcept {
    if (value_ == kMax) {
      return false;
    }
    value_ += 1;
    return true;
  }

  /// Saturating add: reports failure instead of wrapping.
  bool try_add(std::uint64_t delta) noexcept {
    if (delta > kMax - value_) {
      return false;
    }
    value_ += delta;
    return true;
  }

  /// Incremented value, or a CounterOverflow failure at the ceiling.
  Result<Counter> next() const {
    Counter out = *this;
    if (!out.try_increment()) {
      return Status::failure(ErrorCode::CounterOverflow, "monotonic counter is at its maximum value");
    }
    return out;
  }

  friend constexpr bool operator==(const Counter& a, const Counter& b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(const Counter& a, const Counter& b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  std::uint64_t value_ = 0;
};

struct GenerationTag {};
struct EpochTag {};
struct RevisionTag {};
struct SequenceTag {};

/// Policy generation: increments once per successfully published policy
/// bundle. A decision is valid only against the generation that produced it.
using Generation = Counter<GenerationTag>;

/// Control epoch: increments once per writer incarnation of a store. Every
/// decision produced under an older epoch is fenced as superseded, so authority
/// is never inherited across a restart by accident.
using Epoch = Counter<EpochTag>;

/// Author-supplied revision of a bundle document.
using Revision = Counter<RevisionTag>;

/// Durable publication order. Distinct from Generation so that a reverted or
/// re-published generation can never look "newer" than what was on disk.
using Sequence = Counter<SequenceTag>;

/// Rule priority. Higher priority decides before lower priority.
class Priority {
 public:
  constexpr Priority() noexcept = default;

  static constexpr Priority from_raw(std::int32_t value) noexcept {
    Priority priority;
    priority.value_ = value;
    return priority;
  }

  constexpr std::int32_t raw() const noexcept { return value_; }

  friend constexpr bool operator==(const Priority& a, const Priority& b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(const Priority& a, const Priority& b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  std::int32_t value_ = 0;
};

/// Nanoseconds since the Unix epoch, UTC.
///
/// Never part of a digest and never an input to a decision, because it is the
/// only non-deterministic value in the runtime. Optionality is modelled with
/// std::optional rather than a zero sentinel.
class TimestampNanos {
 public:
  constexpr TimestampNanos() noexcept = default;

  static constexpr TimestampNanos from_unix_nanos(std::int64_t value) noexcept {
    TimestampNanos timestamp;
    timestamp.value_ = value;
    return timestamp;
  }

  constexpr std::int64_t unix_nanos() const noexcept { return value_; }

  friend constexpr bool operator==(const TimestampNanos& a, const TimestampNanos& b) noexcept {
    return a.value_ == b.value_;
  }
  friend constexpr std::strong_ordering operator<=>(const TimestampNanos& a, const TimestampNanos& b) noexcept {
    return a.value_ <=> b.value_;
  }

  /// Reads the system wall clock. Only used to stamp durable records.
  static TimestampNanos now() noexcept;

 private:
  std::int64_t value_ = 0;
};

struct BundleIdTag {};
struct RuleIdTag {};
struct FactKeyTag {};
struct PredicateIdTag {};
struct ScopeIdTag {};
struct AuthorityIdTag {};
struct ObligationCodeTag {};
struct ReasonCodeTag {};

/// A validated identity or key.
///
/// A default-constructed Name is explicitly *unset* (is_set() == false); parse()
/// never produces an unset Name, so "no identity" and "identity that happens to
/// be empty" cannot be confused.
template <class Tag>
class Name {
 public:
  Name() noexcept = default;

  static Result<Name> parse(std::string_view text, std::uint32_t max_bytes) {
    if (auto reason = identifier_violation(text, max_bytes)) {
      return Status::failure(ErrorCode::InvalidIdentifier, "invalid identifier: " + *reason);
    }
    Name name;
    name.text_.assign(text);
    return name;
  }

  bool is_set() const noexcept { return !text_.empty(); }
  const std::string& str() const noexcept { return text_; }

  friend bool operator==(const Name& a, const Name& b) noexcept { return a.text_ == b.text_; }
  friend std::strong_ordering operator<=>(const Name& a, const Name& b) noexcept {
    return a.text_ <=> b.text_;
  }

 private:
  std::string text_;
};

using BundleId = Name<BundleIdTag>;
using RuleId = Name<RuleIdTag>;
using FactKey = Name<FactKeyTag>;
using PredicateId = Name<PredicateIdTag>;
using ScopeId = Name<ScopeIdTag>;
using AuthorityId = Name<AuthorityIdTag>;
using ObligationCode = Name<ObligationCodeTag>;
using ReasonCode = Name<ReasonCodeTag>;

/// Bounded, validated UTF-8 text.
///
/// policy text is data, never code: it is length-bounded, strictly validated,
/// and rejected outright if it carries control or bidirectional characters.
class Text {
 public:
  Text() = default;

  static Result<Text> parse(std::string_view text, std::uint32_t max_bytes, bool allow_empty) {
    if (auto reason = text_violation(text, max_bytes, allow_empty)) {
      return Status::failure(ErrorCode::InvalidUtf8, "invalid text: " + *reason);
    }
    Text out;
    out.text_.assign(text);
    return out;
  }

  bool empty() const noexcept { return text_.empty(); }
  const std::string& str() const noexcept { return text_; }
  std::string_view view() const noexcept { return text_; }

  friend bool operator==(const Text& a, const Text& b) noexcept { return a.text_ == b.text_; }
  friend std::strong_ordering operator<=>(const Text& a, const Text& b) noexcept {
    return a.text_ <=> b.text_;
  }

 private:
  std::string text_;
};

}  // namespace fpe

#endif  // FPE_TYPES_HPP
