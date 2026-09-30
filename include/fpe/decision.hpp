#ifndef FPE_DECISION_HPP
#define FPE_DECISION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/digest.hpp"
#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe {

/// What policy decided.
///
/// Unknown is a first-class outcome, not an error. A policy engine that cannot
/// establish permission returns Unknown; it never returns Allow because it
/// could not find a reason to refuse.
enum class Outcome : std::uint8_t {
  Allow = 0,
  Refuse = 1,
  Defer = 2,
  Unknown = 3,
};

/// How one rule contributed to the decision.
enum class RuleDisposition : std::uint8_t {
  /// Applicability held and every prerequisite was a fresh observation.
  Matched = 0,
  /// Applicability was provably false.
  NotApplicable = 1,
  /// Applicability could not be established. Grants nothing.
  Undecided = 2,
  /// Undecided, and the rule explicitly declared fail-open, so it was skipped.
  /// Recorded so a decision can never fail open silently.
  Skipped = 3,
  /// Undecided, and the rule explicitly declared that unknown means refuse.
  RefusedByUnknown = 4,
};

/// Machine-readable cause attached to a rule's disposition.
enum class AppraisalCause : std::uint8_t {
  None = 0,
  ConditionFalse = 1,
  ConditionUnknown = 2,
  PrerequisiteNotSupplied = 3,
  PrerequisiteMissing = 4,
  PrerequisiteUnknown = 5,
  PrerequisiteStale = 6,
  PrerequisiteExpired = 7,
  PrerequisiteFreshnessUndeterminable = 8,
  PrerequisiteTypeConflict = 9,
  SkippedByUnknownPolicy = 10,
  RefusedByUnknownPolicy = 11,
};

std::string_view outcome_name(Outcome outcome) noexcept;
std::string_view rule_disposition_name(RuleDisposition disposition) noexcept;
std::string_view appraisal_cause_name(AppraisalCause cause) noexcept;
Result<Outcome> parse_outcome(std::string_view text);
Result<RuleDisposition> parse_rule_disposition(std::string_view text);
Result<AppraisalCause> parse_appraisal_cause(std::string_view text);

/// Per-rule record inside a decision artifact.
struct RuleOutcome {
  RuleId id;
  Priority priority;
  Effect effect = Effect::Refuse;
  UnknownPolicy on_unknown = UnknownPolicy::FailClosed;
  RuleDisposition disposition = RuleDisposition::NotApplicable;
  AppraisalCause cause = AppraisalCause::None;
  ReasonCode reason;
  /// Facts that prevented this rule from deciding, in canonical order.
  std::vector<FactKey> unresolved;
  Text detail;
};

/// The policy state a decision was produced against.
struct PolicyBinding {
  /// Generation the bundle was published at. Absent when the bundle is used
  /// outside a store; the artifact then says so rather than claiming generation
  /// zero.
  std::optional<Generation> generation;
  /// Control epoch of the publishing store incarnation, when there is one.
  std::optional<Epoch> control_epoch;

  static PolicyBinding unpublished() noexcept { return PolicyBinding{}; }

  static PolicyBinding published(Generation generation, Epoch control_epoch) noexcept {
    PolicyBinding binding;
    binding.generation = generation;
    binding.control_epoch = control_epoch;
    return binding;
  }
};

/// The policy state a consumer currently trusts.
struct CurrentPolicy {
  BundleId bundle;
  Digest256 digest;
  std::optional<Generation> generation;
  std::optional<Epoch> control_epoch;
};

enum class FenceStatus : std::uint8_t {
  /// The decision was produced by exactly the policy state that is current.
  Current = 0,
  /// The artifact's own digest does not match its contents.
  ArtifactDigestMismatch = 1,
  /// A different evaluator revision produced the decision.
  EvaluatorRevisionChanged = 2,
  /// A different bundle, or a different revision of the same bundle.
  BundleChanged = 3,
  /// The decision is not bound to any published generation.
  UnboundDecision = 4,
  /// The current policy is not bound to a published generation.
  UnboundCurrentPolicy = 5,
  /// A newer policy generation is current.
  StaleGeneration = 6,
  /// The current generation is older than the one the decision names, which
  /// means the store moved backwards.
  GenerationRegressed = 7,
  /// A newer store incarnation is current.
  StaleEpoch = 8,
};

std::string_view fence_status_name(FenceStatus status) noexcept;

/// Result of checking a decision against the policy state a consumer trusts.
struct FenceResult {
  FenceStatus status = FenceStatus::Current;
  std::string detail;

  bool is_current() const noexcept { return status == FenceStatus::Current; }
};

/// A complete, attributable record of one policy evaluation.
struct DecisionArtifact {
  std::uint32_t schema_version = 1;
  std::uint32_t evaluator_revision = 0;

  Outcome outcome = Outcome::Unknown;
  /// True when two hard rules of equal priority disagreed. The outcome is then
  /// Refuse; a contradiction never resolves to allow.
  bool contradictory_hard_rules = false;
  /// True when at least one rule was skipped because it explicitly declared
  /// fail-open. A decision that failed open is always visible as such.
  bool failed_open = false;
  /// True when the explanation was truncated by the configured bound.
  bool explanation_truncated = false;

  /// Priority band that decided the outcome, when a rule decided it.
  std::optional<Priority> deciding_priority;

  BundleId bundle;
  Revision bundle_revision;
  Digest256 bundle_digest;
  std::optional<Generation> policy_generation;
  std::optional<Epoch> control_epoch;
  Digest256 input_digest;
  std::vector<AuthorityBinding> authorities;

  /// Every rule considered, in canonical identity order.
  std::vector<RuleOutcome> rules;
  std::vector<RuleId> matched_rules;
  std::vector<RuleId> refused_rules;
  std::vector<RuleId> allowed_rules;
  std::vector<RuleId> deferred_rules;
  std::vector<RuleId> undecided_rules;
  std::vector<RuleId> failed_open_rules;
  /// Declared required facts that were not fresh observations.
  std::vector<FactKey> unresolved_requirements;
  /// Union of the obligations of the allow rules that decided the outcome.
  std::vector<ObligationCode> obligations;
  std::vector<std::string> explanation;
  std::uint64_t evaluation_steps = 0;

  /// SHA-256 over the canonical serialization of everything above.
  Digest256 artifact_digest;
};

/// Canonical JSON form of an artifact's content, excluding the digest.
///
/// This is the form the digest is computed over, so the digest is never an
/// input to itself.
JsonValue artifact_to_json(const DecisionArtifact& artifact);

/// Exported form: the canonical content plus the digest that protects it.
///
/// This is what a consumer stores or transmits. Parsing it back recomputes the
/// digest from the content, so a document whose content was edited fails to
/// parse rather than silently becoming a different decision.
JsonValue artifact_document(const DecisionArtifact& artifact);

/// Digest of an artifact as it would be serialized right now.
Digest256 compute_artifact_digest(const DecisionArtifact& artifact);

/// Recomputes and stores the artifact digest. Called by the engine before an
/// artifact is returned, so a caller never receives an unfinalized artifact.
Status finalize_artifact(DecisionArtifact& artifact);

/// Recomputes the digest and reports whether it matches the stored one.
Status verify_artifact(const DecisionArtifact& artifact);

/// Parses an artifact document and verifies its digest.
Result<DecisionArtifact> artifact_from_json(const JsonValue& document, const Limits& limits);

/// Compares a decision against the policy state a consumer currently trusts.
///
/// Checks are applied in a fixed order so that a stale decision always produces
/// the same specific diagnosis rather than a generic failure.
FenceResult fence_decision(const DecisionArtifact& artifact, const CurrentPolicy& current);

/// One-line human summary, used by the CLI and by the artifact explanation.
std::string artifact_summary(const DecisionArtifact& artifact);

}  // namespace fpe

#endif  // FPE_DECISION_HPP
