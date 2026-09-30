#include "fpe/runtime.hpp"

#include <utility>

namespace fpe {

Result<PolicyRuntime> PolicyRuntime::open(const std::filesystem::path& store_root, const Limits& limits) {
  auto reader = open_reader(store_root, limits);
  if (!reader) {
    return reader.status();
  }
  PolicyRuntime runtime;
  runtime.loaded_digest_ = reader.value().head().bundle_digest;
  runtime.reader_ = std::move(reader).value();
  return runtime;
}

Result<bool> PolicyRuntime::reload() {
  if (auto refreshed = reader_.refresh(); !refreshed.ok()) {
    return refreshed;
  }
  const Digest256 current = reader_.head().bundle_digest;
  const bool changed = !(current == loaded_digest_);
  loaded_digest_ = current;
  return changed;
}

Result<DecisionArtifact> PolicyRuntime::decide(const InputSet& inputs, const EvaluationOptions& options) {
  auto canonical = reader_.policy();
  if (!canonical) {
    return canonical.status();
  }
  EvaluationOptions bound = options;
  bound.binding = PolicyBinding::published(reader_.head().generation, reader_.head().control_epoch);
  return evaluate(*canonical.value(), inputs, bound);
}

Result<FenceResult> PolicyRuntime::fence(const DecisionArtifact& artifact) {
  auto current = reader_.current_policy();
  if (!current) {
    return current.status();
  }
  return fence_decision(artifact, current.value());
}

}  // namespace fpe
