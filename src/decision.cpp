#include "fpe/decision.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "fpe/version.hpp"

namespace fpe {
namespace {

Status schema_error(std::string_view path, std::string message) {
  return Status::failure(ErrorCode::PolicySchema, std::string(path) + ": " + std::move(message));
}

Result<std::string> required_string(const JsonValue& object, std::string_view key, std::string_view path) {
  auto member = json_require_member(object, key, path);
  if (!member) {
    return member.status();
  }
  auto text = json_as_string(*member.value(), json_child_path(path, key));
  if (!text) {
    return text.status();
  }
  return std::string(text.value());
}

Result<std::string> optional_string(const JsonValue& object, std::string_view key, std::string_view path) {
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return std::string();
  }
  auto text = json_as_string(*member, json_child_path(path, key));
  if (!text) {
    return text.status();
  }
  return std::string(text.value());
}

Result<bool> optional_boolean(const JsonValue& object, std::string_view key, std::string_view path,
                              bool fallback) {
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return fallback;
  }
  return json_as_boolean(*member, json_child_path(path, key));
}

Result<std::optional<std::int64_t>> optional_integer(const JsonValue& object, std::string_view key,
                                                     std::string_view path) {
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return std::optional<std::int64_t>{};
  }
  auto value = json_as_integer(*member, json_child_path(path, key));
  if (!value) {
    return value.status();
  }
  return std::optional<std::int64_t>{value.value()};
}

template <class Name>
Result<std::vector<Name>> parse_name_array(const JsonValue& object, std::string_view key, std::string_view path,
                                           const Limits& limits) {
  std::vector<Name> out;
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return out;
  }
  auto items = json_as_array(*member, json_child_path(path, key));
  if (!items) {
    return items.status();
  }
  const JsonValue::Array& array = *items.value();
  out.reserve(array.size());
  for (std::size_t i = 0; i < array.size(); ++i) {
    const std::string item_path = json_index_path(json_child_path(path, key), i);
    auto text = json_as_string(array[i], item_path);
    if (!text) {
      return text.status();
    }
    auto parsed = Name::parse(text.value(), limits.max_identifier_bytes);
    if (!parsed) {
      return parsed.status();
    }
    out.push_back(std::move(parsed).value());
  }
  return out;
}

JsonValue names_to_json(const std::vector<RuleId>& names) {
  JsonValue::Array items;
  items.reserve(names.size());
  for (const auto& name : names) {
    items.push_back(JsonValue::string(name.str()));
  }
  return JsonValue::array(std::move(items));
}

JsonValue strings_to_json(const std::vector<std::string>& values) {
  JsonValue::Array items;
  items.reserve(values.size());
  for (const auto& value : values) {
    items.push_back(JsonValue::string(value));
  }
  return JsonValue::array(std::move(items));
}

void add_if_present(JsonValue::Object& members, std::string_view key, const std::vector<RuleId>& names) {
  if (!names.empty()) {
    members.emplace(std::string(key), names_to_json(names));
  }
}

}  // namespace

std::string_view outcome_name(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::Allow:
      return "allow";
    case Outcome::Refuse:
      return "refuse";
    case Outcome::Defer:
      return "defer";
    case Outcome::Unknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view rule_disposition_name(RuleDisposition disposition) noexcept {
  switch (disposition) {
    case RuleDisposition::Matched:
      return "matched";
    case RuleDisposition::NotApplicable:
      return "not-applicable";
    case RuleDisposition::Undecided:
      return "undecided";
    case RuleDisposition::Skipped:
      return "skipped";
    case RuleDisposition::RefusedByUnknown:
      return "refused-by-unknown";
  }
  return "unknown";
}

std::string_view appraisal_cause_name(AppraisalCause cause) noexcept {
  switch (cause) {
    case AppraisalCause::None:
      return "none";
    case AppraisalCause::ConditionFalse:
      return "condition-false";
    case AppraisalCause::ConditionUnknown:
      return "condition-unknown";
    case AppraisalCause::PrerequisiteNotSupplied:
      return "prerequisite-not-supplied";
    case AppraisalCause::PrerequisiteMissing:
      return "prerequisite-missing";
    case AppraisalCause::PrerequisiteUnknown:
      return "prerequisite-unknown";
    case AppraisalCause::PrerequisiteStale:
      return "prerequisite-stale";
    case AppraisalCause::PrerequisiteExpired:
      return "prerequisite-expired";
    case AppraisalCause::PrerequisiteFreshnessUndeterminable:
      return "prerequisite-freshness-undeterminable";
    case AppraisalCause::PrerequisiteTypeConflict:
      return "prerequisite-type-conflict";
    case AppraisalCause::SkippedByUnknownPolicy:
      return "skipped-by-unknown-policy";
    case AppraisalCause::RefusedByUnknownPolicy:
      return "refused-by-unknown-policy";
  }
  return "none";
}

Result<Outcome> parse_outcome(std::string_view text) {
  if (text == "allow") {
    return Outcome::Allow;
  }
  if (text == "refuse") {
    return Outcome::Refuse;
  }
  if (text == "defer") {
    return Outcome::Defer;
  }
  if (text == "unknown") {
    return Outcome::Unknown;
  }
  return schema_error("outcome", "unrecognized outcome '" + std::string(text) + "'");
}

Result<RuleDisposition> parse_rule_disposition(std::string_view text) {
  if (text == "matched") {
    return RuleDisposition::Matched;
  }
  if (text == "not-applicable") {
    return RuleDisposition::NotApplicable;
  }
  if (text == "undecided") {
    return RuleDisposition::Undecided;
  }
  if (text == "skipped") {
    return RuleDisposition::Skipped;
  }
  if (text == "refused-by-unknown") {
    return RuleDisposition::RefusedByUnknown;
  }
  return schema_error("disposition", "unrecognized rule disposition '" + std::string(text) + "'");
}

Result<AppraisalCause> parse_appraisal_cause(std::string_view text) {
  const AppraisalCause causes[] = {
      AppraisalCause::None,
      AppraisalCause::ConditionFalse,
      AppraisalCause::ConditionUnknown,
      AppraisalCause::PrerequisiteNotSupplied,
      AppraisalCause::PrerequisiteMissing,
      AppraisalCause::PrerequisiteUnknown,
      AppraisalCause::PrerequisiteStale,
      AppraisalCause::PrerequisiteExpired,
      AppraisalCause::PrerequisiteFreshnessUndeterminable,
      AppraisalCause::PrerequisiteTypeConflict,
      AppraisalCause::SkippedByUnknownPolicy,
      AppraisalCause::RefusedByUnknownPolicy,
  };
  for (const AppraisalCause cause : causes) {
    if (appraisal_cause_name(cause) == text) {
      return cause;
    }
  }
  return schema_error("cause", "unrecognized appraisal cause '" + std::string(text) + "'");
}

std::string_view fence_status_name(FenceStatus status) noexcept {
  switch (status) {
    case FenceStatus::Current:
      return "current";
    case FenceStatus::ArtifactDigestMismatch:
      return "artifact-digest-mismatch";
    case FenceStatus::EvaluatorRevisionChanged:
      return "evaluator-revision-changed";
    case FenceStatus::BundleChanged:
      return "bundle-changed";
    case FenceStatus::UnboundDecision:
      return "unbound-decision";
    case FenceStatus::UnboundCurrentPolicy:
      return "unbound-current-policy";
    case FenceStatus::StaleGeneration:
      return "stale-generation";
    case FenceStatus::GenerationRegressed:
      return "generation-regressed";
    case FenceStatus::StaleEpoch:
      return "stale-epoch";
  }
  return "unknown";
}

JsonValue artifact_to_json(const DecisionArtifact& artifact) {
  JsonValue::Object members;
  members.emplace("schema", JsonValue::integer(static_cast<std::int64_t>(artifact.schema_version)));
  members.emplace("evaluator_revision",
                  JsonValue::integer(static_cast<std::int64_t>(artifact.evaluator_revision)));
  members.emplace("outcome", JsonValue::string(std::string(outcome_name(artifact.outcome))));
  members.emplace("contradictory_hard_rules", JsonValue::boolean(artifact.contradictory_hard_rules));
  members.emplace("failed_open", JsonValue::boolean(artifact.failed_open));
  members.emplace("explanation_truncated", JsonValue::boolean(artifact.explanation_truncated));
  if (artifact.deciding_priority.has_value()) {
    members.emplace("deciding_priority",
                    JsonValue::integer(static_cast<std::int64_t>(artifact.deciding_priority->raw())));
  }
  members.emplace("bundle", JsonValue::string(artifact.bundle.str()));
  members.emplace("bundle_revision",
                  JsonValue::integer(static_cast<std::int64_t>(artifact.bundle_revision.raw())));
  members.emplace("bundle_digest", JsonValue::string(artifact.bundle_digest.to_hex()));
  if (artifact.policy_generation.has_value()) {
    members.emplace("policy_generation",
                    JsonValue::integer(static_cast<std::int64_t>(artifact.policy_generation->raw())));
  }
  if (artifact.control_epoch.has_value()) {
    members.emplace("control_epoch",
                    JsonValue::integer(static_cast<std::int64_t>(artifact.control_epoch->raw())));
  }
  members.emplace("input_digest", JsonValue::string(artifact.input_digest.to_hex()));

  if (!artifact.authorities.empty()) {
    JsonValue::Array items;
    items.reserve(artifact.authorities.size());
    for (const auto& binding : artifact.authorities) {
      JsonValue::Object item;
      item.emplace("authority", JsonValue::string(binding.authority.str()));
      item.emplace("generation", JsonValue::integer(static_cast<std::int64_t>(binding.generation.raw())));
      item.emplace("digest", JsonValue::string(binding.digest.to_hex()));
      items.push_back(JsonValue::object(std::move(item)));
    }
    members.emplace("authorities", JsonValue::array(std::move(items)));
  }

  if (!artifact.rules.empty()) {
    JsonValue::Array items;
    items.reserve(artifact.rules.size());
    for (const auto& outcome : artifact.rules) {
      JsonValue::Object item;
      item.emplace("id", JsonValue::string(outcome.id.str()));
      item.emplace("priority", JsonValue::integer(static_cast<std::int64_t>(outcome.priority.raw())));
      item.emplace("effect", JsonValue::string(std::string(effect_name(outcome.effect))));
      item.emplace("on_unknown", JsonValue::string(std::string(unknown_policy_name(outcome.on_unknown))));
      item.emplace("disposition", JsonValue::string(std::string(rule_disposition_name(outcome.disposition))));
      item.emplace("cause", JsonValue::string(std::string(appraisal_cause_name(outcome.cause))));
      item.emplace("reason", JsonValue::string(outcome.reason.str()));
      if (!outcome.unresolved.empty()) {
        JsonValue::Array unresolved;
        unresolved.reserve(outcome.unresolved.size());
        for (const auto& key : outcome.unresolved) {
          unresolved.push_back(JsonValue::string(key.str()));
        }
        item.emplace("unresolved", JsonValue::array(std::move(unresolved)));
      }
      if (!outcome.detail.empty()) {
        item.emplace("detail", JsonValue::string(outcome.detail.str()));
      }
      items.push_back(JsonValue::object(std::move(item)));
    }
    members.emplace("rules", JsonValue::array(std::move(items)));
  }

  add_if_present(members, "matched_rules", artifact.matched_rules);
  add_if_present(members, "refused_rules", artifact.refused_rules);
  add_if_present(members, "allowed_rules", artifact.allowed_rules);
  add_if_present(members, "deferred_rules", artifact.deferred_rules);
  add_if_present(members, "undecided_rules", artifact.undecided_rules);
  add_if_present(members, "failed_open_rules", artifact.failed_open_rules);

  if (!artifact.unresolved_requirements.empty()) {
    JsonValue::Array items;
    items.reserve(artifact.unresolved_requirements.size());
    for (const auto& key : artifact.unresolved_requirements) {
      items.push_back(JsonValue::string(key.str()));
    }
    members.emplace("unresolved_requirements", JsonValue::array(std::move(items)));
  }
  if (!artifact.obligations.empty()) {
    JsonValue::Array items;
    items.reserve(artifact.obligations.size());
    for (const auto& code : artifact.obligations) {
      items.push_back(JsonValue::string(code.str()));
    }
    members.emplace("obligations", JsonValue::array(std::move(items)));
  }
  if (!artifact.explanation.empty()) {
    members.emplace("explanation", strings_to_json(artifact.explanation));
  }
  members.emplace("evaluation_steps",
                  JsonValue::integer(static_cast<std::int64_t>(artifact.evaluation_steps)));
  return JsonValue::object(std::move(members));
}

JsonValue artifact_document(const DecisionArtifact& artifact) {
  JsonValue content = artifact_to_json(artifact);
  const auto* members = content.as_object();
  if (members == nullptr) {
    return content;
  }
  JsonValue::Object document = *members;
  if (!artifact.artifact_digest.is_zero()) {
    document.emplace("artifact_digest", JsonValue::string(artifact.artifact_digest.to_hex()));
  }
  return JsonValue::object(std::move(document));
}

Digest256 compute_artifact_digest(const DecisionArtifact& artifact) {
  return Digest256::of(to_canonical_json(artifact_to_json(artifact)));
}

Status finalize_artifact(DecisionArtifact& artifact) {
  artifact.artifact_digest = compute_artifact_digest(artifact);
  return Status::success();
}

Status verify_artifact(const DecisionArtifact& artifact) {
  if (artifact.artifact_digest.is_zero()) {
    return Status::failure(ErrorCode::DigestBindingMismatch, "artifact has not been finalized");
  }
  const Digest256 recomputed = compute_artifact_digest(artifact);
  if (!(recomputed == artifact.artifact_digest)) {
    return Status::failure(ErrorCode::DigestBindingMismatch,
                           "artifact digest " + artifact.artifact_digest.to_hex() +
                               " does not match its contents (" + recomputed.to_hex() + ")");
  }
  return Status::success();
}

Result<DecisionArtifact> artifact_from_json(const JsonValue& document, const Limits& limits) {
  auto unknown = json_reject_unknown_members(
      document,
      {"schema", "evaluator_revision", "outcome", "contradictory_hard_rules", "failed_open",
       "explanation_truncated", "deciding_priority", "bundle", "bundle_revision",
       "bundle_digest", "policy_generation", "control_epoch", "input_digest", "authorities", "rules",
       "matched_rules", "refused_rules", "allowed_rules", "deferred_rules", "undecided_rules",
       "failed_open_rules", "unresolved_requirements", "obligations", "explanation", "evaluation_steps",
       "artifact_digest"},
      "artifact");
  if (!unknown.ok()) {
    return unknown;
  }

  DecisionArtifact artifact;
  auto schema = json_require_member(document, "schema", "artifact");
  if (!schema) {
    return schema.status();
  }
  auto schema_value = json_as_integer(*schema.value(), "artifact.schema");
  if (!schema_value) {
    return schema_value.status();
  }
  if (schema_value.value() != static_cast<std::int64_t>(kArtifactSchemaVersion)) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "artifact schema revision " + std::to_string(schema_value.value()) +
                               " is not supported by this build (expected " +
                               std::to_string(kArtifactSchemaVersion) + ")");
  }
  artifact.schema_version = kArtifactSchemaVersion;

  auto revision = json_require_member(document, "evaluator_revision", "artifact");
  if (!revision) {
    return revision.status();
  }
  auto revision_value = json_as_integer(*revision.value(), "artifact.evaluator_revision");
  if (!revision_value) {
    return revision_value.status();
  }
  if (revision_value.value() < 0 || revision_value.value() > static_cast<std::int64_t>(UINT32_MAX)) {
    return schema_error("artifact.evaluator_revision", "value is outside the unsigned 32-bit range");
  }
  artifact.evaluator_revision = static_cast<std::uint32_t>(revision_value.value());

  auto outcome_text = required_string(document, "outcome", "artifact");
  if (!outcome_text) {
    return outcome_text.status();
  }
  auto outcome = parse_outcome(outcome_text.value());
  if (!outcome) {
    return outcome.status();
  }
  artifact.outcome = outcome.value();

  auto contradictory = optional_boolean(document, "contradictory_hard_rules", "artifact", false);
  if (!contradictory) {
    return contradictory.status();
  }
  artifact.contradictory_hard_rules = contradictory.value();

  auto failed_open = optional_boolean(document, "failed_open", "artifact", false);
  if (!failed_open) {
    return failed_open.status();
  }
  artifact.failed_open = failed_open.value();

  auto truncated = optional_boolean(document, "explanation_truncated", "artifact", false);
  if (!truncated) {
    return truncated.status();
  }
  artifact.explanation_truncated = truncated.value();

  auto deciding = optional_integer(document, "deciding_priority", "artifact");
  if (!deciding) {
    return deciding.status();
  }
  if (deciding.value().has_value()) {
    if (deciding.value().value() < static_cast<std::int64_t>(INT32_MIN) ||
        deciding.value().value() > static_cast<std::int64_t>(INT32_MAX)) {
      return schema_error("artifact.deciding_priority", "value is outside the 32-bit signed range");
    }
    artifact.deciding_priority = Priority::from_raw(static_cast<std::int32_t>(deciding.value().value()));
  }

  auto bundle = required_string(document, "bundle", "artifact");
  if (!bundle) {
    return bundle.status();
  }
  auto bundle_id = BundleId::parse(bundle.value(), limits.max_identifier_bytes);
  if (!bundle_id) {
    return bundle_id.status();
  }
  artifact.bundle = std::move(bundle_id).value();

  auto bundle_revision = json_require_member(document, "bundle_revision", "artifact");
  if (!bundle_revision) {
    return bundle_revision.status();
  }
  auto bundle_revision_value = json_as_integer(*bundle_revision.value(), "artifact.bundle_revision");
  if (!bundle_revision_value) {
    return bundle_revision_value.status();
  }
  if (bundle_revision_value.value() < 0) {
    return schema_error("artifact.bundle_revision", "value must not be negative");
  }
  artifact.bundle_revision = Revision::from_raw(static_cast<std::uint64_t>(bundle_revision_value.value()));

  auto bundle_digest_text = required_string(document, "bundle_digest", "artifact");
  if (!bundle_digest_text) {
    return bundle_digest_text.status();
  }
  auto bundle_digest = Digest256::from_hex(bundle_digest_text.value());
  if (!bundle_digest) {
    return bundle_digest.status();
  }
  if (bundle_digest.value().is_zero()) {
    return schema_error("artifact.bundle_digest", "value must not be the reserved all-zero digest");
  }
  artifact.bundle_digest = bundle_digest.value();

  auto generation = optional_integer(document, "policy_generation", "artifact");
  if (!generation) {
    return generation.status();
  }
  if (generation.value().has_value()) {
    if (generation.value().value() < 0) {
      return schema_error("artifact.policy_generation", "value must not be negative");
    }
    artifact.policy_generation = Generation::from_raw(static_cast<std::uint64_t>(generation.value().value()));
  }

  auto epoch = optional_integer(document, "control_epoch", "artifact");
  if (!epoch) {
    return epoch.status();
  }
  if (epoch.value().has_value()) {
    if (epoch.value().value() < 0) {
      return schema_error("artifact.control_epoch", "value must not be negative");
    }
    artifact.control_epoch = Epoch::from_raw(static_cast<std::uint64_t>(epoch.value().value()));
  }

  auto input_digest_text = required_string(document, "input_digest", "artifact");
  if (!input_digest_text) {
    return input_digest_text.status();
  }
  auto input_digest = Digest256::from_hex(input_digest_text.value());
  if (!input_digest) {
    return input_digest.status();
  }
  if (input_digest.value().is_zero()) {
    return schema_error("artifact.input_digest", "value must not be the reserved all-zero digest");
  }
  artifact.input_digest = input_digest.value();

  if (const JsonValue* authorities = json_optional_member(document, "authorities")) {
    auto items = json_as_array(*authorities, "artifact.authorities");
    if (!items) {
      return items.status();
    }
    const JsonValue::Array& array = *items.value();
    if (array.size() > limits.max_input_facts) {
      return Status::failure(ErrorCode::LimitExceeded, "artifact.authorities exceeds the supported size");
    }
    artifact.authorities.reserve(array.size());
    for (std::size_t i = 0; i < array.size(); ++i) {
      const std::string item_path = json_index_path("artifact.authorities", i);
      auto item_unknown = json_reject_unknown_members(array[i], {"authority", "generation", "digest"}, item_path);
      if (!item_unknown.ok()) {
        return item_unknown;
      }
      AuthorityBinding binding;
      auto authority = required_string(array[i], "authority", item_path);
      if (!authority) {
        return authority.status();
      }
      auto parsed_authority = AuthorityId::parse(authority.value(), limits.max_identifier_bytes);
      if (!parsed_authority) {
        return parsed_authority.status();
      }
      binding.authority = std::move(parsed_authority).value();

      auto generation_member = json_require_member(array[i], "generation", item_path);
      if (!generation_member) {
        return generation_member.status();
      }
      auto generation_value = json_as_integer(*generation_member.value(), json_child_path(item_path, "generation"));
      if (!generation_value) {
        return generation_value.status();
      }
      if (generation_value.value() < 0) {
        return schema_error(json_child_path(item_path, "generation"), "value must not be negative");
      }
      binding.generation = Generation::from_raw(static_cast<std::uint64_t>(generation_value.value()));

      auto digest_text = required_string(array[i], "digest", item_path);
      if (!digest_text) {
        return digest_text.status();
      }
      auto digest = Digest256::from_hex(digest_text.value());
      if (!digest) {
        return digest.status();
      }
      if (digest.value().is_zero()) {
        return schema_error(json_child_path(item_path, "digest"),
                            "value must not be the reserved all-zero digest");
      }
      binding.digest = digest.value();
      artifact.authorities.push_back(std::move(binding));
    }
  }

  if (const JsonValue* rules = json_optional_member(document, "rules")) {
    auto items = json_as_array(*rules, "artifact.rules");
    if (!items) {
      return items.status();
    }
    const JsonValue::Array& array = *items.value();
    if (array.size() > limits.max_rules) {
      return Status::failure(ErrorCode::LimitExceeded, "artifact.rules exceeds the supported size");
    }
    artifact.rules.reserve(array.size());
    for (std::size_t i = 0; i < array.size(); ++i) {
      const JsonValue& item = array[i];
      const std::string item_path = json_index_path("artifact.rules", i);
      auto item_unknown = json_reject_unknown_members(
          item, {"id", "priority", "effect", "on_unknown", "disposition", "cause", "reason", "unresolved",
                 "detail"},
          item_path);
      if (!item_unknown.ok()) {
        return item_unknown;
      }
      RuleOutcome outcome_record;
      auto id = required_string(item, "id", item_path);
      if (!id) {
        return id.status();
      }
      auto rule_id = RuleId::parse(id.value(), limits.max_identifier_bytes);
      if (!rule_id) {
        return rule_id.status();
      }
      outcome_record.id = std::move(rule_id).value();

      auto priority_member = json_require_member(item, "priority", item_path);
      if (!priority_member) {
        return priority_member.status();
      }
      auto priority = json_as_integer(*priority_member.value(), json_child_path(item_path, "priority"));
      if (!priority) {
        return priority.status();
      }
      if (priority.value() < static_cast<std::int64_t>(INT32_MIN) ||
          priority.value() > static_cast<std::int64_t>(INT32_MAX)) {
        return schema_error(json_child_path(item_path, "priority"), "value is outside the 32-bit signed range");
      }
      outcome_record.priority = Priority::from_raw(static_cast<std::int32_t>(priority.value()));

      auto effect_text = required_string(item, "effect", item_path);
      if (!effect_text) {
        return effect_text.status();
      }
      auto effect = parse_effect(effect_text.value());
      if (!effect) {
        return effect.status();
      }
      outcome_record.effect = effect.value();

      auto on_unknown_text = required_string(item, "on_unknown", item_path);
      if (!on_unknown_text) {
        return on_unknown_text.status();
      }
      auto on_unknown = parse_unknown_policy(on_unknown_text.value());
      if (!on_unknown) {
        return on_unknown.status();
      }
      outcome_record.on_unknown = on_unknown.value();

      auto disposition_text = required_string(item, "disposition", item_path);
      if (!disposition_text) {
        return disposition_text.status();
      }
      auto disposition = parse_rule_disposition(disposition_text.value());
      if (!disposition) {
        return disposition.status();
      }
      outcome_record.disposition = disposition.value();

      auto cause_text = required_string(item, "cause", item_path);
      if (!cause_text) {
        return cause_text.status();
      }
      auto cause = parse_appraisal_cause(cause_text.value());
      if (!cause) {
        return cause.status();
      }
      outcome_record.cause = cause.value();

      auto reason_text = required_string(item, "reason", item_path);
      if (!reason_text) {
        return reason_text.status();
      }
      auto reason = ReasonCode::parse(reason_text.value(), limits.max_identifier_bytes);
      if (!reason) {
        return reason.status();
      }
      outcome_record.reason = std::move(reason).value();

      if (const JsonValue* unresolved = json_optional_member(item, "unresolved")) {
        auto unresolved_items = json_as_array(*unresolved, json_child_path(item_path, "unresolved"));
        if (!unresolved_items) {
          return unresolved_items.status();
        }
        const JsonValue::Array& unresolved_array = *unresolved_items.value();
        outcome_record.unresolved.reserve(unresolved_array.size());
        for (std::size_t k = 0; k < unresolved_array.size(); ++k) {
          const std::string element_path =
              json_index_path(json_child_path(item_path, "unresolved"), k);
          auto text = json_as_string(unresolved_array[k], element_path);
          if (!text) {
            return text.status();
          }
          auto key = FactKey::parse(text.value(), limits.max_identifier_bytes);
          if (!key) {
            return key.status();
          }
          outcome_record.unresolved.push_back(std::move(key).value());
        }
      }

      auto detail = optional_string(item, "detail", item_path);
      if (!detail) {
        return detail.status();
      }
      auto detail_text = Text::parse(detail.value(), limits.max_text_bytes, true);
      if (!detail_text) {
        return detail_text.status();
      }
      outcome_record.detail = std::move(detail_text).value();
      artifact.rules.push_back(std::move(outcome_record));
    }
  }

  auto matched = parse_name_array<RuleId>(document, "matched_rules", "artifact", limits);
  if (!matched) {
    return matched.status();
  }
  artifact.matched_rules = std::move(matched).value();
  auto refused = parse_name_array<RuleId>(document, "refused_rules", "artifact", limits);
  if (!refused) {
    return refused.status();
  }
  artifact.refused_rules = std::move(refused).value();
  auto allowed = parse_name_array<RuleId>(document, "allowed_rules", "artifact", limits);
  if (!allowed) {
    return allowed.status();
  }
  artifact.allowed_rules = std::move(allowed).value();
  auto deferred = parse_name_array<RuleId>(document, "deferred_rules", "artifact", limits);
  if (!deferred) {
    return deferred.status();
  }
  artifact.deferred_rules = std::move(deferred).value();
  auto undecided = parse_name_array<RuleId>(document, "undecided_rules", "artifact", limits);
  if (!undecided) {
    return undecided.status();
  }
  artifact.undecided_rules = std::move(undecided).value();
  auto failed = parse_name_array<RuleId>(document, "failed_open_rules", "artifact", limits);
  if (!failed) {
    return failed.status();
  }
  artifact.failed_open_rules = std::move(failed).value();
  auto requirements = parse_name_array<FactKey>(document, "unresolved_requirements", "artifact", limits);
  if (!requirements) {
    return requirements.status();
  }
  artifact.unresolved_requirements = std::move(requirements).value();
  auto obligations = parse_name_array<ObligationCode>(document, "obligations", "artifact", limits);
  if (!obligations) {
    return obligations.status();
  }
  artifact.obligations = std::move(obligations).value();

  if (const JsonValue* explanation = json_optional_member(document, "explanation")) {
    auto items = json_as_array(*explanation, "artifact.explanation");
    if (!items) {
      return items.status();
    }
    const JsonValue::Array& array = *items.value();
    if (array.size() > limits.max_explanation_entries) {
      return Status::failure(ErrorCode::LimitExceeded,
                             "artifact.explanation carries " + std::to_string(array.size()) +
                                 " entries, above the maximum of " +
                                 std::to_string(limits.max_explanation_entries));
    }
    artifact.explanation.reserve(array.size());
    for (std::size_t i = 0; i < array.size(); ++i) {
      const std::string item_path = json_index_path("artifact.explanation", i);
      auto text = json_as_string(array[i], item_path);
      if (!text) {
        return text.status();
      }
      if (auto reason = text_violation(text.value(), limits.max_text_bytes, true)) {
        return schema_error(item_path, "not acceptable text: " + *reason);
      }
      artifact.explanation.emplace_back(text.value());
    }
  }

  auto steps = json_require_member(document, "evaluation_steps", "artifact");
  if (!steps) {
    return steps.status();
  }
  auto steps_value = json_as_integer(*steps.value(), "artifact.evaluation_steps");
  if (!steps_value) {
    return steps_value.status();
  }
  if (steps_value.value() < 0) {
    return schema_error("artifact.evaluation_steps", "value must not be negative");
  }
  artifact.evaluation_steps = static_cast<std::uint64_t>(steps_value.value());

  const JsonValue* digest_member = json_optional_member(document, "artifact_digest");
  if (digest_member == nullptr) {
    return Status::failure(ErrorCode::JsonMissingField,
                           "artifact.artifact_digest is required: a decision document without its digest "
                           "cannot be shown to be unmodified");
  }
  auto digest_text = json_as_string(*digest_member, "artifact.artifact_digest");
  if (!digest_text) {
    return digest_text.status();
  }
  auto parsed_digest = Digest256::from_hex(digest_text.value());
  if (!parsed_digest) {
    return parsed_digest.status();
  }
  artifact.artifact_digest = parsed_digest.value();

  if (auto verified = verify_artifact(artifact); !verified.ok()) {
    return verified;
  }
  return artifact;
}

FenceResult fence_decision(const DecisionArtifact& artifact, const CurrentPolicy& current) {
  FenceResult result;

  if (auto verified = verify_artifact(artifact); !verified.ok()) {
    result.status = FenceStatus::ArtifactDigestMismatch;
    result.detail = std::string(verified.message());
    return result;
  }
  if (artifact.evaluator_revision != kEvaluatorRevision) {
    result.status = FenceStatus::EvaluatorRevisionChanged;
    result.detail = "decision was produced by evaluator revision " +
                    std::to_string(artifact.evaluator_revision) + ", this build is revision " +
                    std::to_string(kEvaluatorRevision);
    return result;
  }
  if (!(artifact.bundle == current.bundle) || !(artifact.bundle_digest == current.digest)) {
    result.status = FenceStatus::BundleChanged;
    result.detail = "decision names bundle '" + artifact.bundle.str() + "' at digest " +
                    artifact.bundle_digest.to_hex() + ", current policy is bundle '" + current.bundle.str() +
                    "' at digest " + current.digest.to_hex();
    return result;
  }
  if (!artifact.policy_generation.has_value() || !artifact.control_epoch.has_value()) {
    result.status = FenceStatus::UnboundDecision;
    result.detail = "decision is not bound to a published policy generation and control epoch";
    return result;
  }
  if (!current.generation.has_value() || !current.control_epoch.has_value()) {
    result.status = FenceStatus::UnboundCurrentPolicy;
    result.detail = "the current policy is not bound to a published generation and control epoch";
    return result;
  }
  if (artifact.policy_generation.value() < current.generation.value()) {
    result.status = FenceStatus::StaleGeneration;
    result.detail = "decision was produced at policy generation " +
                    std::to_string(artifact.policy_generation->raw()) + ", current generation is " +
                    std::to_string(current.generation->raw());
    return result;
  }
  if (current.generation.value() < artifact.policy_generation.value()) {
    result.status = FenceStatus::GenerationRegressed;
    result.detail = "decision names policy generation " +
                    std::to_string(artifact.policy_generation->raw()) +
                    ", which is newer than the current generation " +
                    std::to_string(current.generation->raw()) + "; the store moved backwards";
    return result;
  }
  if (!(artifact.control_epoch.value() == current.control_epoch.value())) {
    result.status = FenceStatus::StaleEpoch;
    result.detail = "decision was produced under control epoch " +
                    std::to_string(artifact.control_epoch->raw()) + ", current epoch is " +
                    std::to_string(current.control_epoch->raw());
    return result;
  }
  result.status = FenceStatus::Current;
  result.detail = "decision matches the current policy generation and control epoch";
  return result;
}

std::string artifact_summary(const DecisionArtifact& artifact) {
  std::string out;
  out.append(outcome_name(artifact.outcome));
  out.append(": bundle '");
  out.append(artifact.bundle.str());
  out.append("' revision ");
  out.append(std::to_string(artifact.bundle_revision.raw()));
  out.append(" digest ");
  out.append(artifact.bundle_digest.to_hex().substr(0, 16));
  if (artifact.policy_generation.has_value()) {
    out.append(" generation ");
    out.append(std::to_string(artifact.policy_generation->raw()));
  } else {
    out.append(" generation unpublished");
  }
  if (artifact.control_epoch.has_value()) {
    out.append(" epoch ");
    out.append(std::to_string(artifact.control_epoch->raw()));
  }
  out.append(" input ");
  out.append(artifact.input_digest.to_hex().substr(0, 16));
  out.append(" rules ");
  out.append(std::to_string(artifact.rules.size()));
  out.append(" (matched ");
  out.append(std::to_string(artifact.matched_rules.size()));
  out.append(", refused ");
  out.append(std::to_string(artifact.refused_rules.size()));
  out.append(", undecided ");
  out.append(std::to_string(artifact.undecided_rules.size()));
  out.append(")");
  if (artifact.contradictory_hard_rules) {
    out.append(" contradictory-hard-rules");
  }
  if (artifact.failed_open) {
    out.append(" failed-open");
  }
  return out;
}

}  // namespace fpe
