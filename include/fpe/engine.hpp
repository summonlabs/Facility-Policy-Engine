#ifndef FPE_ENGINE_HPP
#define FPE_ENGINE_HPP

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/input.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe {

/// Whether an observation is still valid at the evaluation instant.
enum class Freshness : std::uint8_t {
  /// The fact is not an observation at all.
  NotObserved = 0,
  /// Observed, and either open-ended or inside its validity window.
  Fresh = 1,
  /// Observed, but past the validity deadline it declared.
  Expired = 2,
  /// Observed with a validity deadline, but the caller supplied no evaluation
  /// instant, so validity cannot be established.
  Undeterminable = 3,
};

std::string_view freshness_name(Freshness freshness) noexcept;

/// How one fact is seen by the evaluator.
struct FactAppraisal {
  FactKey key;
  FactType declared_type = FactType::Boolean;
  /// True when the fact was supplied in the input set.
  bool supplied = false;
  FactState state = FactState::Missing;
  Freshness freshness = Freshness::NotObserved;
  /// True when the supplied value's domain disagrees with the policy
  /// declaration.
  bool type_conflict = false;
  AppraisalCause cause = AppraisalCause::None;
};

/// Options for one evaluation.
struct EvaluationOptions {
  /// The instant the decision is evaluated for.
  ///
  /// This is an input, not a reading of the system clock: the engine never
  /// reads a clock, so the same bundle and the same facts always produce the
  /// same decision. A fact that declares a validity deadline is treated as
  /// Undeterminable when no instant is supplied.
  std::optional<TimestampNanos> as_of;

  Limits limits = Limits::defaults();

  /// The published generation and control epoch the bundle is current at.
  /// Defaults to "not published", which the artifact records honestly rather
  /// than claiming generation zero.
  PolicyBinding binding = PolicyBinding::unpublished();

  /// When false, per-rule explanation text is omitted. The machine-readable
  /// decision is unaffected.
  bool include_explanation = true;
};

/// Evaluates one canonical policy bundle against one validated input set.
///
/// This is a pure function: it takes only const references, holds no state, and
/// cannot publish policy or mutate authority. It is therefore also the dry-run
/// and explain path. A decision that cannot be established is returned as
/// Outcome::Unknown with full attribution; a bound breach is returned as a
/// failure with no artifact at all.
Result<DecisionArtifact> evaluate(const CanonicalBundle& bundle, const InputSet& inputs,
                                  const EvaluationOptions& options);

/// Reports how the evaluator sees every fact the bundle declares.
///
/// Read-only, and useful before a decision is attempted: it answers "which
/// declared facts are missing, unknown, stale, expired, or type-conflicting"
/// without producing authority.
Result<std::vector<FactAppraisal>> appraise_inputs(const CanonicalBundle& bundle, const InputSet& inputs,
                                                   const EvaluationOptions& options);

/// Freshness of one fact at one evaluation instant.
Freshness appraise_freshness(const Fact& fact, std::optional<TimestampNanos> as_of) noexcept;

}  // namespace fpe

#endif  // FPE_ENGINE_HPP
