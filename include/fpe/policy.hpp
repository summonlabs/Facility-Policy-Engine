#ifndef FPE_POLICY_HPP
#define FPE_POLICY_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/digest.hpp"
#include "fpe/json.hpp"
#include "fpe/limits.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe {

/// Value domain of a declared facility fact.
///
/// The domain is closed on purpose. A policy bundle cannot introduce a new
/// value kind, cannot express a computation, and cannot call out, so evaluating
/// a bundle can never execute arbitrary code.
enum class FactType : std::uint8_t {
  Boolean = 0,
  Integer = 1,
  Symbol = 2,
  Text = 3,
  SymbolSet = 4,
  Quantity = 5,
};

/// Comparison and presence operators available to a condition.
enum class PredicateOp : std::uint8_t {
  Exists = 0,
  NotExists = 1,
  IsUnknown = 2,
  IsStale = 3,
  IsMissing = 4,
  Equals = 5,
  NotEquals = 6,
  LessThan = 7,
  LessOrEqual = 8,
  GreaterThan = 9,
  GreaterOrEqual = 10,
  InSet = 11,
  ContainsAll = 12,
  ContainsAny = 13,
};

enum class ConditionKind : std::uint8_t { All = 0, Any = 1, Not = 2, Test = 3, NamedRef = 4 };

/// What a rule does when it matches.
enum class Effect : std::uint8_t { Allow = 0, Refuse = 1, Defer = 2 };

/// What a rule does when its applicability cannot be determined.
///
/// FailClosed is the default and the only value an author gets for free. The
/// other two are explicit, documented, per-rule decisions and are always
/// reported in the decision artifact.
enum class UnknownPolicy : std::uint8_t {
  /// The rule is undecided. It grants nothing and blocks an allow at or below
  /// its priority.
  FailClosed = 0,
  /// The rule matches as a refusal because its prerequisite is unknown. This is
  /// the explicit fail-closed refusal form.
  Refuse = 1,
  /// The rule is skipped, and the artifact records it as having failed open.
  /// This is the only fail-open behaviour in the model.
  Skip = 2,
};

/// Outcome when no rule applies at all. Never Allow.
enum class DefaultOutcome : std::uint8_t { Unknown = 0, Refuse = 1 };

std::string_view fact_type_name(FactType type) noexcept;
std::string_view predicate_op_name(PredicateOp op) noexcept;
std::string_view condition_kind_name(ConditionKind kind) noexcept;
std::string_view effect_name(Effect effect) noexcept;
std::string_view unknown_policy_name(UnknownPolicy policy) noexcept;
std::string_view default_outcome_name(DefaultOutcome outcome) noexcept;

Result<FactType> parse_fact_type(std::string_view text);
Result<PredicateOp> parse_predicate_op(std::string_view text);
Result<Effect> parse_effect(std::string_view text);
Result<UnknownPolicy> parse_unknown_policy(std::string_view text);
Result<DefaultOutcome> parse_default_outcome(std::string_view text);

/// True when \p op is a presence or state test and therefore takes no operand.
bool predicate_op_is_presence(PredicateOp op) noexcept;

/// True when \p op is a set/membership test.
bool predicate_op_is_collection(PredicateOp op) noexcept;

/// A condition tree node.
///
/// Every condition is a bounded, closed expression over declared facts. There
/// are no user-defined functions, no arithmetic, no string manipulation, and no
/// references outside the bundle's own fact and predicate declarations.
struct Condition {
  ConditionKind kind = ConditionKind::All;

  // ConditionKind::Test
  FactKey fact;
  PredicateOp op = PredicateOp::Exists;
  std::vector<JsonValue> operands;

  // ConditionKind::All / Any / Not
  std::vector<Condition> children;

  // ConditionKind::NamedRef
  PredicateId named;

  static Condition make_all(std::vector<Condition> children);
  static Condition make_any(std::vector<Condition> children);
  static Condition make_not(Condition child);
  static Condition make_test(FactKey fact, PredicateOp op, std::vector<JsonValue> operands);
  static Condition make_named_ref(PredicateId named);

  /// Always-true condition (an empty All).
  static Condition always() { return Condition{}; }
};

/// A reusable named condition. Named predicates may reference other named
/// predicates; the resulting graph must be acyclic.
struct NamedPredicate {
  PredicateId id;
  Condition body;
};

/// A declared facility fact.
struct FactDecl {
  FactKey key;
  FactType type = FactType::Boolean;
  AuthorityId authority;
  ScopeId scope;
  /// When true, the evaluation cannot grant permission while this fact is not a
  /// fresh observation.
  bool required = false;
};

/// An import of another canonical policy bundle.
///
/// The import binds to the exact digest of the imported bundle. There is no
/// version range and no "latest": compatibility is an exact content binding, so
/// a policy set can never silently pick up a different upstream bundle.
struct ImportDecl {
  BundleId bundle;
  Digest256 digest;
};

/// A single policy rule.
struct Rule {
  RuleId id;
  Priority priority;
  Effect effect = Effect::Refuse;
  UnknownPolicy on_unknown = UnknownPolicy::FailClosed;
  Condition applicability = Condition::always();
  std::vector<FactKey> prerequisites;
  std::vector<ObligationCode> obligations;
  ReasonCode reason;
  Text description;
};

/// A policy bundle document (pre-canonicalization).
struct Bundle {
  std::uint32_t schema_version = 1;
  BundleId id;
  Revision revision;
  ScopeId scope;
  Text description;
  DefaultOutcome default_outcome = DefaultOutcome::Unknown;
  std::vector<ImportDecl> imports;
  std::vector<FactDecl> facts;
  std::vector<NamedPredicate> predicates;
  std::vector<Rule> rules;
};

/// Everything a bundle's conditions may reference: the bundle's own
/// declarations plus those of every transitively resolved import.
struct PolicyIndex {
  /// Fact key to declared value type. The same key may be declared by more than
  /// one bundle only when the declared type agrees.
  std::map<FactKey, FactType> facts;

  /// Named predicate to the identity of the bundle that declares it, so that a
  /// shared transitive dependency merges idempotently while a genuine
  /// redeclaration by two different bundles is still a conflict.
  std::map<PredicateId, BundleId> predicates;

  /// Adds one bundle's declarations, failing on a conflicting redeclaration.
  Status add(const Bundle& bundle);

  /// Merges another declaration set. Idempotent for declarations that come from
  /// the same declaring bundle.
  Status merge(const PolicyIndex& other);
};

/// A bundle that has passed full validation and is stored in canonical order.
///
/// Only a CanonicalBundle can be evaluated, digested, or published. Its
/// constructor is private, so an unvalidated or non-canonically-ordered policy
/// set cannot reach a decision or a digest.
class CanonicalBundle {
 public:
  CanonicalBundle(CanonicalBundle&&) noexcept = default;
  CanonicalBundle& operator=(CanonicalBundle&&) noexcept = default;
  CanonicalBundle(const CanonicalBundle&) = delete;
  CanonicalBundle& operator=(const CanonicalBundle&) = delete;

  const Bundle& bundle() const noexcept { return bundle_; }
  const Digest256& digest() const noexcept { return digest_; }
  const BundleId& id() const noexcept { return bundle_.id; }
  Revision revision() const noexcept { return bundle_.revision; }

  /// Resolved imports in canonical (bundle-id) order.
  const std::vector<ImportDecl>& resolved_imports() const noexcept { return resolved_imports_; }

  /// Canonical serialization of the bundle (excluding the digest itself).
  const std::string& canonical_bytes() const noexcept { return canonical_bytes_; }

  /// Canonical document the serialization was produced from.
  const JsonValue& document() const noexcept { return document_; }

  /// Declarations this bundle's conditions may reference: its own plus those of
  /// every transitively resolved import.
  const PolicyIndex& declaration_closure() const noexcept { return closure_; }

  /// Resolved imports, held by shared ownership so that a canonical bundle is
  /// self-contained: it can be serialized, published, and reloaded without a
  /// separate resolution step. The import graph is acyclic, so this ownership is
  /// acyclic too and nothing leaks.
  const std::vector<std::shared_ptr<const CanonicalBundle>>& imports() const noexcept { return imports_; }

 private:
  friend Result<CanonicalBundle> canonicalize_bundle(Bundle,
                                                     std::vector<std::shared_ptr<const CanonicalBundle>>,
                                                     const Limits&);

  CanonicalBundle() = default;

  Bundle bundle_;
  Digest256 digest_;
  std::vector<ImportDecl> resolved_imports_;
  std::vector<std::shared_ptr<const CanonicalBundle>> imports_;
  PolicyIndex closure_;
  JsonValue document_;
  std::string canonical_bytes_;
};

/// Canonical JSON form of a bundle. The digest of a bundle is the SHA-256 of
/// the canonical JSON of its canonicalized form.
JsonValue bundle_to_json(const Bundle& bundle);

/// Parses a bundle document. Document shape is validated here; cross-reference,
/// cycle, compatibility, and limit validation happen at compile time.
Result<Bundle> bundle_from_json(const JsonValue& document, const Limits& limits);

/// Parses and validates a standalone bundle that declares no imports.
Result<CanonicalBundle> compile_standalone_bundle(Bundle document, const Limits& limits);

/// Compiles bundles and resolves imports.
///
/// Documents are supplied up front. compile() walks the import graph, and
/// refuses to compile a bundle whose import graph is cyclic or whose import
/// digest does not match the supplied document exactly.
class BundleCompiler {
 public:
  explicit BundleCompiler(Limits limits);

  /// Adds a raw document. Supplying the same bundle identity twice is refused
  /// rather than replaced, so a compiled bundle can never be silently swapped
  /// underneath a caller that already holds it.
  Status provide(Bundle document);

  /// Compiles \p id and everything it imports. The returned bundle is shared,
  /// so it stays valid for the lifetime of the compiler and cannot dangle.
  Result<std::shared_ptr<const CanonicalBundle>> compile(const BundleId& id);

  const Limits& limits() const noexcept { return limits_; }

 private:
  Result<std::shared_ptr<const CanonicalBundle>> compile_inner(const BundleId& id,
                                                               std::vector<BundleId>& stack);

  Limits limits_;
  std::map<BundleId, Bundle> documents_;
  std::map<BundleId, std::shared_ptr<const CanonicalBundle>> compiled_;
};

/// Validates and canonicalizes a bundle whose imports the caller has already
/// resolved. This is the only way to construct a CanonicalBundle, so a bundle
/// that has not passed schema, reference, cycle, compatibility, and limit
/// validation cannot be evaluated, digested, or published.
///
/// Because every import must already be a CanonicalBundle, an import cycle is
/// not constructible: the dependency order is enforced by the type system as
/// well as by the compiler's cycle check.
Result<CanonicalBundle> canonicalize_bundle(Bundle document,
                                            std::vector<std::shared_ptr<const CanonicalBundle>> imports,
                                            const Limits& limits);

/// The bundle and every transitive import, in deterministic topological order
/// with dependencies before dependents. This is the closure a publisher writes
/// into a store so that a later reader can evaluate without resolving anything.
std::vector<const CanonicalBundle*> policy_set_closure(const CanonicalBundle& root);

/// Finds a reference cycle among named predicates, in deterministic order.
/// Returns the first cycle found as a path of predicate identities, or an empty
/// vector when the graph is acyclic.
Result<std::vector<PredicateId>> find_predicate_cycle(const Bundle& bundle);

/// Validates every condition in \p bundle against \p index: reference
/// resolution, operand typing, depth, node count, and collection bounds.
Status validate_bundle_conditions(const Bundle& bundle, const PolicyIndex& index, const Limits& limits);

/// Counts condition nodes (each Test, NamedRef, Not, All, and Any node counts).
std::size_t condition_node_count(const Condition& condition);

/// Collects every fact key referenced by a condition tree, in sorted order.
void collect_condition_facts(const Condition& condition, std::set<FactKey>& out);

/// Collects every named predicate referenced by a condition tree.
void collect_condition_predicates(const Condition& condition, std::set<PredicateId>& out);

/// True when the operand type accepted by \p op for a \p fact_type fact is the
/// scalar type; used by the validator and by error messages.
Status validate_test_operands(FactType fact_type, PredicateOp op, const std::vector<JsonValue>& operands,
                              std::string_view path);

}  // namespace fpe

#endif  // FPE_POLICY_HPP
