#ifndef FPE_INPUT_HPP
#define FPE_INPUT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "fpe/digest.hpp"
#include "fpe/json.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe {

/// Presence state of one authoritative fact.
///
/// The states are exhaustive and mutually exclusive. In particular there is no
/// value that means "false", "zero", or "not applicable": an absent fact is
/// Missing, an unreadable one is Unknown, and an expired one is Stale. A caller
/// that does not know a fact's state cannot express it as Observed, because
/// Observed requires a value.
enum class FactState : std::uint8_t {
  /// The authority reports that no such fact exists for this subject.
  Missing = 0,
  /// The authority was asked and could not answer, or answered "unknown".
  Unknown = 1,
  /// A previous observation exists but is past its validity.
  Stale = 2,
  /// A current observation with a value.
  Observed = 3,
};

std::string_view fact_state_name(FactState state) noexcept;
Result<FactState> parse_fact_state(std::string_view text);

/// A typed fact value.
///
/// The value is a closed union matching \\ref FactType. An unset value is
/// modelled explicitly and is only legal for a fact that is not Observed.
class FactValue {
 public:
  using SymbolSet = std::vector<std::string>;

  struct Symbol {
    std::string value;
  };
  struct TextValue {
    std::string value;
  };
  struct Quantity {
    std::int64_t magnitude = 0;
    std::string unit;
  };

  FactValue() noexcept = default;

  static FactValue boolean(bool value) noexcept;
  static FactValue integer(std::int64_t value) noexcept;
  static FactValue symbol(std::string value) noexcept;
  static FactValue text(std::string value) noexcept;
  static FactValue symbol_set(SymbolSet values) noexcept;
  static FactValue quantity(std::int64_t magnitude, std::string unit) noexcept;

  bool is_set() const noexcept;
  /// Precondition: is_set().
  FactType type() const noexcept;

  const bool* as_boolean() const noexcept;
  const std::int64_t* as_integer() const noexcept;
  const std::string* as_symbol() const noexcept;
  const std::string* as_text() const noexcept;
  const SymbolSet* as_symbol_set() const noexcept;
  const Quantity* as_quantity() const noexcept;

  /// Canonical JSON form of the value.
  JsonValue to_json() const;

  /// Parses a typed value, requiring exactly \p expected. Numbers, symbols, and
  /// units are validated against the same bounds the policy schema uses.
  static Result<FactValue> from_json(const JsonValue& document, FactType expected, const Limits& limits,
                                     std::string_view path);

 private:
  std::variant<std::monostate, bool, std::int64_t, Symbol, TextValue, SymbolSet, Quantity> value_;
};

/// One authoritative fact as supplied by an adjacent runtime.
///
/// The Facility Policy Engine never derives a fact's state, never reads a clock
/// on its own, and never invents a value. Everything here is a claim made by the
/// owning authority, and the decision artifact records exactly which claims
/// supported the decision.
struct Fact {
  FactKey key;
  FactState state = FactState::Missing;
  FactValue value;

  /// Value domain the owning authority declares for this fact. Required when the
  /// state is Observed, because a value without a declared domain cannot be
  /// checked against the policy that reads it.
  std::optional<FactType> type;

  AuthorityId authority;
  std::optional<Generation> generation;
  std::optional<Digest256> evidence_digest;
  std::optional<TimestampNanos> observed_at;
  std::optional<TimestampNanos> valid_until;
};

/// True when \\p fact is an observation that is still valid at \\p as_of.
///
/// A fact that declares a validity deadline is never fresh when the caller does
/// not supply the instant it wants the decision evaluated for: freshness cannot
/// be established without an evaluation instant, so it is reported as unknown
/// rather than assumed.
bool fact_is_fresh(const Fact& fact, std::optional<TimestampNanos> as_of) noexcept;

/// Provenance of one authority's contribution to an input set.
struct AuthorityBinding {
  AuthorityId authority;
  Generation generation;
  Digest256 digest;

  friend bool operator==(const AuthorityBinding& a, const AuthorityBinding& b) noexcept {
    return a.authority == b.authority && a.generation == b.generation && a.digest == b.digest;
  }
  friend std::strong_ordering operator<=>(const AuthorityBinding& a, const AuthorityBinding& b) noexcept {
    if (const auto by_authority = a.authority <=> b.authority; by_authority != 0) {
      return by_authority;
    }
    if (const auto by_generation = a.generation <=> b.generation; by_generation != 0) {
      return by_generation;
    }
    return a.digest <=> b.digest;
  }
};

/// A validated, canonically ordered set of authoritative facts.
///
/// Only an InputSet can be evaluated, so an input collection that has not been
/// validated (duplicate keys, a value on a non-observed fact, an unbounded
/// symbol set) cannot reach a decision.
class InputSet {
 public:
  InputSet(InputSet&&) noexcept = default;
  InputSet& operator=(InputSet&&) noexcept = default;
  InputSet(const InputSet&) = delete;
  InputSet& operator=(const InputSet&) = delete;

  /// Facts in canonical (fact-key) order.
  const std::vector<Fact>& facts() const noexcept { return facts_; }

  /// Returns nullptr when the key is absent from this set.
  const Fact* find(const FactKey& key) const noexcept;

  /// Digest of the canonical serialization, which the decision artifact carries
  /// so a consumer can prove which evidence supported a decision.
  const Digest256& digest() const noexcept { return digest_; }

  /// Every distinct authority provenance contributing to this set, in
  /// canonical order.
  const std::vector<AuthorityBinding>& authorities() const noexcept { return authorities_; }

  const std::string& canonical_bytes() const noexcept { return canonical_bytes_; }

  JsonValue to_json() const;

 private:
  friend Result<InputSet> build_input_set(std::vector<Fact> facts, const Limits& limits);

  InputSet() = default;

  std::vector<Fact> facts_;
  std::vector<AuthorityBinding> authorities_;
  std::string canonical_bytes_;
  Digest256 digest_;
};

/// Validates, canonicalizes, and digests a fact collection.
Result<InputSet> build_input_set(std::vector<Fact> facts, const Limits& limits);

/// Parses a fact collection document without digesting it, so callers can
/// inspect or transform facts before building a set.
Result<std::vector<Fact>> facts_from_json(const JsonValue& document, const Limits& limits);

/// Parses and builds an input set from a document.
Result<InputSet> input_set_from_json(const JsonValue& document, const Limits& limits);

/// Canonical JSON form of a fact collection.
JsonValue facts_to_json(const std::vector<Fact>& facts);

}  // namespace fpe

#endif  // FPE_INPUT_HPP
