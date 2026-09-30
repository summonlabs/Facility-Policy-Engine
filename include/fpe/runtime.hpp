#ifndef FPE_RUNTIME_HPP
#define FPE_RUNTIME_HPP

#include <filesystem>
#include <string>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/limits.hpp"
#include "fpe/status.hpp"
#include "fpe/store.hpp"

namespace fpe {

/// A reader of a published policy store that can evaluate and fence.
///
/// The runtime holds one verified read view of the store. It never takes the
/// writer lock, never advances the control epoch, and never publishes, so a
/// process that only evaluates cannot change policy or authority.
///
/// Hot reload is explicit: reload() re-reads the manifest and picks up a newer
/// published generation. Decisions produced before a reload stay exactly as they
/// were produced, carrying the generation and epoch they were made under, so a
/// change of policy can never be mistaken for a decision that was made against
/// the new one: fence() reports the difference.
class PolicyRuntime {
 public:
  static Result<PolicyRuntime> open(const std::filesystem::path& store_root, const Limits& limits);

  /// Re-reads the published generation. Returns true when the current policy
  /// digest changed, so a caller can tell a reload that mattered from one that
  /// did not.
  Result<bool> reload();

  StoreHead head() const noexcept { return reader_.head(); }
  bool has_policy() const noexcept { return reader_.has_policy(); }
  const std::filesystem::path& store_root() const noexcept { return reader_.root(); }

  /// Evaluates \\p inputs against the current published generation.
  ///
  /// The artifact is bound to the generation and control epoch of the store, so
  /// it can always be fenced against a later state.
  Result<DecisionArtifact> decide(const InputSet& inputs, const EvaluationOptions& options);

  /// Reports whether \\p artifact still matches the current published policy.
  Result<FenceResult> fence(const DecisionArtifact& artifact);

 private:
  PolicyRuntime() = default;

  StoreReader reader_;
  Digest256 loaded_digest_;
};

}  // namespace fpe

#endif  // FPE_RUNTIME_HPP
