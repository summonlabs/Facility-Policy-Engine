#include "fpe/limits.hpp"

namespace fpe {

namespace {

Status bound(std::string_view field, std::uint64_t value, std::uint64_t cap) {
  if (value > cap) {
    return Status::failure(ErrorCode::LimitExceeded,
                           std::string("limit '") + std::string(field) + "' (" + std::to_string(value) +
                               ") exceeds the hard cap (" + std::to_string(cap) + ")");
  }
  return Status::success();
}

}  // namespace

Limits Limits::hard_caps() noexcept {
  Limits limits;
  limits.max_imports = HardCaps::kImports;
  limits.max_import_depth = HardCaps::kImportDepth;
  limits.max_rules = HardCaps::kRules;
  limits.max_facts = HardCaps::kFacts;
  limits.max_predicates = HardCaps::kPredicates;
  limits.max_condition_depth = HardCaps::kConditionDepth;
  limits.max_condition_nodes = HardCaps::kConditionNodes;
  limits.max_collection_items = HardCaps::kCollectionItems;
  limits.max_obligations_per_rule = HardCaps::kObligationsPerRule;
  limits.max_explanation_entries = HardCaps::kExplanationEntries;
  limits.max_evaluation_steps = HardCaps::kEvaluationSteps;
  limits.max_bundle_bytes = HardCaps::kBundleBytes;
  limits.max_input_facts = HardCaps::kInputFacts;
  limits.max_text_bytes = HardCaps::kTextBytes;
  limits.max_identifier_bytes = HardCaps::kIdentifierBytes;
  limits.max_json_depth = HardCaps::kJsonDepth;
  limits.max_json_nodes = HardCaps::kJsonNodes;
  limits.max_artifact_bytes = HardCaps::kArtifactBytes;
  limits.max_store_listing = HardCaps::kStoreListing;
  limits.max_record_payload_bytes = HardCaps::kRecordPayloadBytes;
  return limits;
}

Status validate_limits(const Limits& limits) {
  Status failure = Status::success();

  const struct {
    std::string_view name;
    std::uint64_t value;
    std::uint64_t cap;
  } checks[] = {
      {"max_imports", limits.max_imports, HardCaps::kImports},
      {"max_import_depth", limits.max_import_depth, HardCaps::kImportDepth},
      {"max_rules", limits.max_rules, HardCaps::kRules},
      {"max_facts", limits.max_facts, HardCaps::kFacts},
      {"max_predicates", limits.max_predicates, HardCaps::kPredicates},
      {"max_condition_depth", limits.max_condition_depth, HardCaps::kConditionDepth},
      {"max_condition_nodes", limits.max_condition_nodes, HardCaps::kConditionNodes},
      {"max_collection_items", limits.max_collection_items, HardCaps::kCollectionItems},
      {"max_obligations_per_rule", limits.max_obligations_per_rule, HardCaps::kObligationsPerRule},
      {"max_explanation_entries", limits.max_explanation_entries, HardCaps::kExplanationEntries},
      {"max_evaluation_steps", limits.max_evaluation_steps, HardCaps::kEvaluationSteps},
      {"max_bundle_bytes", limits.max_bundle_bytes, HardCaps::kBundleBytes},
      {"max_input_facts", limits.max_input_facts, HardCaps::kInputFacts},
      {"max_text_bytes", limits.max_text_bytes, HardCaps::kTextBytes},
      {"max_identifier_bytes", limits.max_identifier_bytes, HardCaps::kIdentifierBytes},
      {"max_json_depth", limits.max_json_depth, HardCaps::kJsonDepth},
      {"max_json_nodes", limits.max_json_nodes, HardCaps::kJsonNodes},
      {"max_artifact_bytes", limits.max_artifact_bytes, HardCaps::kArtifactBytes},
      {"max_store_listing", limits.max_store_listing, HardCaps::kStoreListing},
      {"max_record_payload_bytes", limits.max_record_payload_bytes, HardCaps::kRecordPayloadBytes},
  };

  for (const auto& check : checks) {
    Status candidate = bound(check.name, check.value, check.cap);
    if (!candidate.ok()) {
      failure = failure.ok() ? std::move(candidate) : Status::prefer(std::move(failure), std::move(candidate));
    }
  }

  // Internally inconsistent bounds: a zero-collection policy set can never
  // satisfy a positive item bound, and a depth above the node count is
  // unreachable. Rejecting these here keeps the evaluator free of dead limits.
  if (limits.max_condition_depth > limits.max_condition_nodes) {
    Status candidate = Status::failure(ErrorCode::LimitExceeded,
                                       "limit 'max_condition_depth' exceeds 'max_condition_nodes'");
    failure = failure.ok() ? std::move(candidate) : Status::prefer(std::move(failure), std::move(candidate));
  }
  if (limits.max_collection_items > limits.max_condition_nodes) {
    Status candidate = Status::failure(ErrorCode::LimitExceeded,
                                       "limit 'max_collection_items' exceeds 'max_condition_nodes'");
    failure = failure.ok() ? std::move(candidate) : Status::prefer(std::move(failure), std::move(candidate));
  }
  if (limits.max_text_bytes > limits.max_bundle_bytes) {
    Status candidate = Status::failure(ErrorCode::LimitExceeded,
                                       "limit 'max_text_bytes' exceeds 'max_bundle_bytes'");
    failure = failure.ok() ? std::move(candidate) : Status::prefer(std::move(failure), std::move(candidate));
  }
  if (limits.max_json_depth > limits.max_json_nodes) {
    Status candidate = Status::failure(ErrorCode::LimitExceeded,
                                       "limit 'max_json_depth' exceeds 'max_json_nodes'");
    failure = failure.ok() ? std::move(candidate) : Status::prefer(std::move(failure), std::move(candidate));
  }

  if (!failure.ok()) {
    return failure;
  }
  return Status::success();
}

}  // namespace fpe
