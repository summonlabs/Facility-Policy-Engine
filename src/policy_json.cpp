#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "fpe/policy.hpp"
#include "fpe/version.hpp"

namespace fpe {
namespace {

Status schema_error(std::string_view path, std::string message) {
  return Status::failure(ErrorCode::PolicySchema, std::string(path) + ": " + std::move(message));
}

template <class Name>
Result<Name> name_member(const JsonValue& object, std::string_view key, std::string_view path,
                         const Limits& limits) {
  auto member = json_require_member(object, key, path);
  if (!member) {
    return member.status();
  }
  auto text = json_as_string(*member.value(), json_child_path(path, key));
  if (!text) {
    return text.status();
  }
  return Name::parse(text.value(), limits.max_identifier_bytes);
}

/// Reads an optional text member, producing a bounded std::string. A member that
/// is present but not a string is a type error, never a default value.
Result<std::string> optional_text_member(const JsonValue& object, std::string_view key, std::string_view path,
                                         const Limits& limits) {
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return std::string();
  }
  auto text = json_as_string(*member, json_child_path(path, key));
  if (!text) {
    return text.status();
  }
  if (auto reason = text_violation(text.value(), limits.max_text_bytes, true)) {
    return schema_error(json_child_path(path, key), "not acceptable text: " + *reason);
  }
  return std::string(text.value());
}

Result<std::int64_t> integer_member(const JsonValue& object, std::string_view key, std::string_view path) {
  auto member = json_require_member(object, key, path);
  if (!member) {
    return member.status();
  }
  return json_as_integer(*member.value(), json_child_path(path, key));
}

/// Reads an optional array member. The returned reference is valid for as long
/// as the document is.
Result<const JsonValue::Array*> optional_array_member(const JsonValue& object, std::string_view key,
                                                      std::string_view path) {
  const JsonValue* member = json_optional_member(object, key);
  if (member == nullptr) {
    return static_cast<const JsonValue::Array*>(nullptr);
  }
  auto items = json_as_array(*member, json_child_path(path, key));
  if (!items) {
    return items.status();
  }
  return items.value();
}

JsonValue condition_to_json(const Condition& condition) {
  JsonValue::Object out;
  switch (condition.kind) {
    case ConditionKind::All:
    case ConditionKind::Any: {
      JsonValue::Array children;
      children.reserve(condition.children.size());
      for (const auto& child : condition.children) {
        children.push_back(condition_to_json(child));
      }
      out.emplace(std::string(condition_kind_name(condition.kind)), JsonValue::array(std::move(children)));
      break;
    }
    case ConditionKind::Not: {
      out.emplace("not", condition_to_json(condition.children.front()));
      break;
    }
    case ConditionKind::NamedRef: {
      out.emplace("named", JsonValue::string(condition.named.str()));
      break;
    }
    case ConditionKind::Test: {
      JsonValue::Object test;
      test.emplace("fact", JsonValue::string(condition.fact.str()));
      test.emplace("op", JsonValue::string(std::string(predicate_op_name(condition.op))));
      if (!condition.operands.empty()) {
        JsonValue::Array operands;
        operands.reserve(condition.operands.size());
        for (const auto& operand : condition.operands) {
          operands.push_back(operand);
        }
        test.emplace("operands", JsonValue::array(std::move(operands)));
      }
      out.emplace("test", JsonValue::object(std::move(test)));
      break;
    }
  }
  return JsonValue::object(std::move(out));
}

JsonValue symbols_to_json(const std::vector<std::string>& symbols) {
  JsonValue::Array items;
  items.reserve(symbols.size());
  for (const auto& symbol : symbols) {
    items.push_back(JsonValue::string(symbol));
  }
  return JsonValue::array(std::move(items));
}

Result<std::vector<std::string>> parse_symbol_array(const JsonValue& document, std::string_view path,
                                                    const Limits& limits, std::size_t maximum) {
  auto items = json_as_array(document, path);
  if (!items) {
    return items.status();
  }
  const JsonValue::Array& array = *items.value();
  if (array.size() > maximum) {
    return Status::failure(ErrorCode::LimitExceeded,
                           std::string(path) + " carries " + std::to_string(array.size()) +
                               " entries, above the maximum of " + std::to_string(maximum));
  }
  std::vector<std::string> out;
  out.reserve(array.size());
  for (std::size_t i = 0; i < array.size(); ++i) {
    const std::string item_path = json_index_path(path, i);
    auto text = json_as_string(array[i], item_path);
    if (!text) {
      return text.status();
    }
    if (auto reason = identifier_violation(text.value(), limits.max_identifier_bytes)) {
      return schema_error(item_path, "not a valid identifier: " + *reason);
    }
    out.emplace_back(text.value());
  }
  return out;
}

Result<Condition> condition_from_json(const JsonValue& document, const Limits& limits, std::string_view path) {
  const auto* members = document.as_object();
  if (members == nullptr) {
    return schema_error(path, "condition must be an object");
  }
  if (members->size() != 1) {
    return schema_error(path, "condition object must carry exactly one of: all, any, not, test, named");
  }
  const std::string& keyword = members->begin()->first;
  const JsonValue& body = members->begin()->second;

  if (keyword == "all" || keyword == "any") {
    auto items = json_as_array(body, json_child_path(path, keyword));
    if (!items) {
      return items.status();
    }
    const JsonValue::Array& array = *items.value();
    if (array.size() > limits.max_condition_nodes) {
      return Status::failure(ErrorCode::LimitExceeded,
                             std::string(json_child_path(path, keyword)) + " carries " +
                                 std::to_string(array.size()) + " children, above the maximum of " +
                                 std::to_string(limits.max_condition_nodes));
    }
    std::vector<Condition> children;
    children.reserve(array.size());
    for (std::size_t i = 0; i < array.size(); ++i) {
      auto child =
          condition_from_json(array[i], limits, json_index_path(json_child_path(path, keyword), i));
      if (!child) {
        return child.status();
      }
      children.push_back(std::move(child).value());
    }
    return keyword == "all" ? Condition::make_all(std::move(children))
                            : Condition::make_any(std::move(children));
  }

  if (keyword == "not") {
    auto child = condition_from_json(body, limits, json_child_path(path, "not"));
    if (!child) {
      return child.status();
    }
    return Condition::make_not(std::move(child).value());
  }

  if (keyword == "named") {
    auto text = json_as_string(body, json_child_path(path, "named"));
    if (!text) {
      return text.status();
    }
    auto named = PredicateId::parse(text.value(), limits.max_identifier_bytes);
    if (!named) {
      return named.status();
    }
    return Condition::make_named_ref(std::move(named).value());
  }

  if (keyword == "test") {
    const std::string test_path = json_child_path(path, "test");
    auto unknown = json_reject_unknown_members(body, {"fact", "op", "operands"}, test_path);
    if (!unknown.ok()) {
      return unknown;
    }
    auto fact = name_member<FactKey>(body, "fact", test_path, limits);
    if (!fact) {
      return fact.status();
    }
    auto op_member = json_require_member(body, "op", test_path);
    if (!op_member) {
      return op_member.status();
    }
    auto op_string = json_as_string(*op_member.value(), json_child_path(test_path, "op"));
    if (!op_string) {
      return op_string.status();
    }
    auto op = parse_predicate_op(op_string.value());
    if (!op) {
      return op.status();
    }
    std::vector<JsonValue> operands;
    if (const JsonValue* operand_node = json_optional_member(body, "operands")) {
      auto operand_array = json_as_array(*operand_node, json_child_path(test_path, "operands"));
      if (!operand_array) {
        return operand_array.status();
      }
      const JsonValue::Array& array = *operand_array.value();
      if (array.size() > limits.max_collection_items) {
        return Status::failure(ErrorCode::LimitExceeded,
                               std::string(json_child_path(test_path, "operands")) + " carries " +
                                   std::to_string(array.size()) + " operands, above the maximum of " +
                                   std::to_string(limits.max_collection_items));
      }
      operands = array;
    }
    return Condition::make_test(std::move(fact).value(), op.value(), std::move(operands));
  }

  return schema_error(path, "unrecognized condition keyword '" + keyword + "'");
}

Result<Rule> rule_from_json(const JsonValue& document, const Limits& limits, std::string_view path) {
  auto unknown = json_reject_unknown_members(
      document, {"id", "priority", "effect", "on_unknown", "when", "prerequisites", "obligations", "reason",
                 "description"},
      path);
  if (!unknown.ok()) {
    return unknown;
  }
  Rule rule;

  auto id = name_member<RuleId>(document, "id", path, limits);
  if (!id) {
    return id.status();
  }
  rule.id = std::move(id).value();

  auto priority = integer_member(document, "priority", path);
  if (!priority) {
    return priority.status();
  }
  if (priority.value() < static_cast<std::int64_t>(INT32_MIN) ||
      priority.value() > static_cast<std::int64_t>(INT32_MAX)) {
    return schema_error(json_child_path(path, "priority"), "priority is outside the 32-bit signed range");
  }
  rule.priority = Priority::from_raw(static_cast<std::int32_t>(priority.value()));

  auto effect_member = json_require_member(document, "effect", path);
  if (!effect_member) {
    return effect_member.status();
  }
  auto effect_text = json_as_string(*effect_member.value(), json_child_path(path, "effect"));
  if (!effect_text) {
    return effect_text.status();
  }
  auto effect = parse_effect(effect_text.value());
  if (!effect) {
    return effect.status();
  }
  rule.effect = effect.value();

  if (const JsonValue* on_unknown = json_optional_member(document, "on_unknown")) {
    auto text = json_as_string(*on_unknown, json_child_path(path, "on_unknown"));
    if (!text) {
      return text.status();
    }
    auto policy = parse_unknown_policy(text.value());
    if (!policy) {
      return policy.status();
    }
    rule.on_unknown = policy.value();
  }

  if (const JsonValue* when = json_optional_member(document, "when")) {
    auto condition = condition_from_json(*when, limits, json_child_path(path, "when"));
    if (!condition) {
      return condition.status();
    }
    rule.applicability = std::move(condition).value();
  }

  if (const JsonValue* prerequisites = json_optional_member(document, "prerequisites")) {
    auto symbols = parse_symbol_array(*prerequisites, json_child_path(path, "prerequisites"), limits,
                                      limits.max_facts);
    if (!symbols) {
      return symbols.status();
    }
    for (const auto& symbol : symbols.value()) {
      auto key = FactKey::parse(symbol, limits.max_identifier_bytes);
      if (!key) {
        return key.status();
      }
      rule.prerequisites.push_back(std::move(key).value());
    }
  }

  if (const JsonValue* obligations = json_optional_member(document, "obligations")) {
    auto symbols = parse_symbol_array(*obligations, json_child_path(path, "obligations"), limits,
                                      limits.max_obligations_per_rule);
    if (!symbols) {
      return symbols.status();
    }
    for (const auto& symbol : symbols.value()) {
      auto code = ObligationCode::parse(symbol, limits.max_identifier_bytes);
      if (!code) {
        return code.status();
      }
      rule.obligations.push_back(std::move(code).value());
    }
  }

  auto reason = name_member<ReasonCode>(document, "reason", path, limits);
  if (!reason) {
    return reason.status();
  }
  rule.reason = std::move(reason).value();

  auto description = optional_text_member(document, "description", path, limits);
  if (!description) {
    return description.status();
  }
  auto description_text = Text::parse(description.value(), limits.max_text_bytes, true);
  if (!description_text) {
    return description_text.status();
  }
  rule.description = std::move(description_text).value();

  return rule;
}

}  // namespace

JsonValue bundle_to_json(const Bundle& bundle) {
  JsonValue::Object document;
  document.emplace("schema", JsonValue::integer(static_cast<std::int64_t>(bundle.schema_version)));
  document.emplace("bundle", JsonValue::string(bundle.id.str()));
  document.emplace("revision", JsonValue::integer(static_cast<std::int64_t>(bundle.revision.raw())));
  if (bundle.scope.is_set()) {
    document.emplace("scope", JsonValue::string(bundle.scope.str()));
  }
  if (!bundle.description.empty()) {
    document.emplace("description", JsonValue::string(bundle.description.str()));
  }
  document.emplace("default_outcome",
                   JsonValue::string(std::string(default_outcome_name(bundle.default_outcome))));

  if (!bundle.imports.empty()) {
    std::vector<ImportDecl> imports = bundle.imports;
    std::sort(imports.begin(), imports.end(),
              [](const ImportDecl& a, const ImportDecl& b) { return a.bundle < b.bundle; });
    JsonValue::Array items;
    items.reserve(imports.size());
    for (const auto& entry : imports) {
      JsonValue::Object item;
      item.emplace("bundle", JsonValue::string(entry.bundle.str()));
      item.emplace("digest", JsonValue::string(entry.digest.to_hex()));
      items.push_back(JsonValue::object(std::move(item)));
    }
    document.emplace("imports", JsonValue::array(std::move(items)));
  }

  if (!bundle.facts.empty()) {
    std::vector<FactDecl> facts = bundle.facts;
    std::sort(facts.begin(), facts.end(),
              [](const FactDecl& a, const FactDecl& b) { return a.key < b.key; });
    JsonValue::Array items;
    items.reserve(facts.size());
    for (const auto& declaration : facts) {
      JsonValue::Object item;
      item.emplace("key", JsonValue::string(declaration.key.str()));
      item.emplace("type", JsonValue::string(std::string(fact_type_name(declaration.type))));
      if (declaration.authority.is_set()) {
        item.emplace("authority", JsonValue::string(declaration.authority.str()));
      }
      if (declaration.scope.is_set()) {
        item.emplace("scope", JsonValue::string(declaration.scope.str()));
      }
      if (declaration.required) {
        item.emplace("required", JsonValue::boolean(true));
      }
      items.push_back(JsonValue::object(std::move(item)));
    }
    document.emplace("facts", JsonValue::array(std::move(items)));
  }

  if (!bundle.predicates.empty()) {
    std::vector<NamedPredicate> predicates = bundle.predicates;
    std::sort(predicates.begin(), predicates.end(),
              [](const NamedPredicate& a, const NamedPredicate& b) { return a.id < b.id; });
    JsonValue::Array items;
    items.reserve(predicates.size());
    for (const auto& predicate : predicates) {
      JsonValue::Object item;
      item.emplace("id", JsonValue::string(predicate.id.str()));
      item.emplace("body", condition_to_json(predicate.body));
      items.push_back(JsonValue::object(std::move(item)));
    }
    document.emplace("predicates", JsonValue::array(std::move(items)));
  }

  if (!bundle.rules.empty()) {
    std::vector<Rule> rules = bundle.rules;
    std::sort(rules.begin(), rules.end(), [](const Rule& a, const Rule& b) { return a.id < b.id; });
    JsonValue::Array items;
    items.reserve(rules.size());
    for (const auto& rule : rules) {
      JsonValue::Object item;
      item.emplace("id", JsonValue::string(rule.id.str()));
      item.emplace("priority", JsonValue::integer(static_cast<std::int64_t>(rule.priority.raw())));
      item.emplace("effect", JsonValue::string(std::string(effect_name(rule.effect))));
      item.emplace("on_unknown", JsonValue::string(std::string(unknown_policy_name(rule.on_unknown))));
      item.emplace("when", condition_to_json(rule.applicability));
      if (!rule.prerequisites.empty()) {
        std::vector<std::string> prerequisites;
        prerequisites.reserve(rule.prerequisites.size());
        for (const auto& key : rule.prerequisites) {
          prerequisites.push_back(key.str());
        }
        std::sort(prerequisites.begin(), prerequisites.end());
        prerequisites.erase(std::unique(prerequisites.begin(), prerequisites.end()), prerequisites.end());
        item.emplace("prerequisites", symbols_to_json(prerequisites));
      }
      if (!rule.obligations.empty()) {
        std::vector<std::string> obligations;
        obligations.reserve(rule.obligations.size());
        for (const auto& code : rule.obligations) {
          obligations.push_back(code.str());
        }
        std::sort(obligations.begin(), obligations.end());
        obligations.erase(std::unique(obligations.begin(), obligations.end()), obligations.end());
        item.emplace("obligations", symbols_to_json(obligations));
      }
      item.emplace("reason", JsonValue::string(rule.reason.str()));
      if (!rule.description.empty()) {
        item.emplace("description", JsonValue::string(rule.description.str()));
      }
      items.push_back(JsonValue::object(std::move(item)));
    }
    document.emplace("rules", JsonValue::array(std::move(items)));
  }

  return JsonValue::object(std::move(document));
}

Result<Bundle> bundle_from_json(const JsonValue& document, const Limits& limits) {
  auto unknown =
      json_reject_unknown_members(document, {"schema", "bundle", "revision", "scope", "description",
                                             "default_outcome", "imports", "facts", "predicates", "rules"},
                                  "bundle");
  if (!unknown.ok()) {
    return unknown;
  }

  Bundle bundle;
  auto schema = integer_member(document, "schema", "bundle");
  if (!schema) {
    return schema.status();
  }
  if (schema.value() != static_cast<std::int64_t>(kBundleSchemaVersion)) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "bundle schema revision " + std::to_string(schema.value()) +
                               " is not supported by this build (expected " +
                               std::to_string(kBundleSchemaVersion) + ")");
  }
  bundle.schema_version = kBundleSchemaVersion;

  auto id = name_member<BundleId>(document, "bundle", "bundle", limits);
  if (!id) {
    return id.status();
  }
  bundle.id = std::move(id).value();

  auto revision = integer_member(document, "revision", "bundle");
  if (!revision) {
    return revision.status();
  }
  if (revision.value() < 0) {
    return schema_error("bundle.revision", "revision must not be negative");
  }
  bundle.revision = Revision::from_raw(static_cast<std::uint64_t>(revision.value()));

  if (const JsonValue* scope_member = json_optional_member(document, "scope")) {
    auto text = json_as_string(*scope_member, "bundle.scope");
    if (!text) {
      return text.status();
    }
    auto parsed = ScopeId::parse(text.value(), limits.max_identifier_bytes);
    if (!parsed) {
      return parsed.status();
    }
    bundle.scope = std::move(parsed).value();
  }

  auto description = optional_text_member(document, "description", "bundle", limits);
  if (!description) {
    return description.status();
  }
  auto description_text = Text::parse(description.value(), limits.max_text_bytes, true);
  if (!description_text) {
    return description_text.status();
  }
  bundle.description = std::move(description_text).value();

  if (const JsonValue* default_outcome = json_optional_member(document, "default_outcome")) {
    auto text = json_as_string(*default_outcome, "bundle.default_outcome");
    if (!text) {
      return text.status();
    }
    auto parsed = parse_default_outcome(text.value());
    if (!parsed) {
      return parsed.status();
    }
    bundle.default_outcome = parsed.value();
  }

  auto imports = optional_array_member(document, "imports", "bundle");
  if (!imports) {
    return imports.status();
  }
  if (imports.value() != nullptr) {
    const JsonValue::Array& array = *imports.value();
    if (array.size() > limits.max_imports) {
      return Status::failure(ErrorCode::LimitExceeded,
                             "bundle.imports carries " + std::to_string(array.size()) +
                                 " entries, above the maximum of " + std::to_string(limits.max_imports));
    }
    for (std::size_t i = 0; i < array.size(); ++i) {
      const JsonValue& item = array[i];
      const std::string item_path = json_index_path("bundle.imports", i);
      auto item_unknown = json_reject_unknown_members(item, {"bundle", "digest"}, item_path);
      if (!item_unknown.ok()) {
        return item_unknown;
      }
      auto import_id = name_member<BundleId>(item, "bundle", item_path, limits);
      if (!import_id) {
        return import_id.status();
      }
      auto digest_member = json_require_member(item, "digest", item_path);
      if (!digest_member) {
        return digest_member.status();
      }
      auto digest_text = json_as_string(*digest_member.value(), json_child_path(item_path, "digest"));
      if (!digest_text) {
        return digest_text.status();
      }
      auto digest = Digest256::from_hex(digest_text.value());
      if (!digest) {
        return digest.status();
      }
      if (digest.value().is_zero()) {
        return schema_error(json_child_path(item_path, "digest"),
                            "an import digest must not be the reserved all-zero digest");
      }
      ImportDecl declaration;
      declaration.bundle = std::move(import_id).value();
      declaration.digest = digest.value();
      bundle.imports.push_back(std::move(declaration));
    }
  }

  auto facts = optional_array_member(document, "facts", "bundle");
  if (!facts) {
    return facts.status();
  }
  if (facts.value() != nullptr) {
    const JsonValue::Array& array = *facts.value();
    if (array.size() > limits.max_facts) {
      return Status::failure(ErrorCode::LimitExceeded, "bundle.facts carries " + std::to_string(array.size()) +
                                                           " entries, above the maximum of " +
                                                           std::to_string(limits.max_facts));
    }
    for (std::size_t i = 0; i < array.size(); ++i) {
      const JsonValue& item = array[i];
      const std::string item_path = json_index_path("bundle.facts", i);
      auto item_unknown =
          json_reject_unknown_members(item, {"key", "type", "authority", "scope", "required"}, item_path);
      if (!item_unknown.ok()) {
        return item_unknown;
      }
      FactDecl declaration;
      auto key = name_member<FactKey>(item, "key", item_path, limits);
      if (!key) {
        return key.status();
      }
      declaration.key = std::move(key).value();

      auto type_member = json_require_member(item, "type", item_path);
      if (!type_member) {
        return type_member.status();
      }
      auto type_text = json_as_string(*type_member.value(), json_child_path(item_path, "type"));
      if (!type_text) {
        return type_text.status();
      }
      auto type = parse_fact_type(type_text.value());
      if (!type) {
        return type.status();
      }
      declaration.type = type.value();

      if (const JsonValue* authority = json_optional_member(item, "authority")) {
        auto text = json_as_string(*authority, json_child_path(item_path, "authority"));
        if (!text) {
          return text.status();
        }
        auto parsed = AuthorityId::parse(text.value(), limits.max_identifier_bytes);
        if (!parsed) {
          return parsed.status();
        }
        declaration.authority = std::move(parsed).value();
      }
      if (const JsonValue* scope = json_optional_member(item, "scope")) {
        auto text = json_as_string(*scope, json_child_path(item_path, "scope"));
        if (!text) {
          return text.status();
        }
        auto parsed = ScopeId::parse(text.value(), limits.max_identifier_bytes);
        if (!parsed) {
          return parsed.status();
        }
        declaration.scope = std::move(parsed).value();
      }
      if (const JsonValue* required = json_optional_member(item, "required")) {
        auto value = json_as_boolean(*required, json_child_path(item_path, "required"));
        if (!value) {
          return value.status();
        }
        declaration.required = value.value();
      }
      bundle.facts.push_back(std::move(declaration));
    }
  }

  auto predicates = optional_array_member(document, "predicates", "bundle");
  if (!predicates) {
    return predicates.status();
  }
  if (predicates.value() != nullptr) {
    const JsonValue::Array& array = *predicates.value();
    if (array.size() > limits.max_predicates) {
      return Status::failure(ErrorCode::LimitExceeded,
                             "bundle.predicates carries " + std::to_string(array.size()) +
                                 " entries, above the maximum of " + std::to_string(limits.max_predicates));
    }
    for (std::size_t i = 0; i < array.size(); ++i) {
      const JsonValue& item = array[i];
      const std::string item_path = json_index_path("bundle.predicates", i);
      auto item_unknown = json_reject_unknown_members(item, {"id", "body"}, item_path);
      if (!item_unknown.ok()) {
        return item_unknown;
      }
      NamedPredicate predicate;
      auto predicate_id = name_member<PredicateId>(item, "id", item_path, limits);
      if (!predicate_id) {
        return predicate_id.status();
      }
      predicate.id = std::move(predicate_id).value();
      auto body = json_require_member(item, "body", item_path);
      if (!body) {
        return body.status();
      }
      auto condition = condition_from_json(*body.value(), limits, json_child_path(item_path, "body"));
      if (!condition) {
        return condition.status();
      }
      predicate.body = std::move(condition).value();
      bundle.predicates.push_back(std::move(predicate));
    }
  }

  auto rules = optional_array_member(document, "rules", "bundle");
  if (!rules) {
    return rules.status();
  }
  if (rules.value() != nullptr) {
    const JsonValue::Array& array = *rules.value();
    if (array.size() > limits.max_rules) {
      return Status::failure(ErrorCode::LimitExceeded, "bundle.rules carries " + std::to_string(array.size()) +
                                                           " entries, above the maximum of " +
                                                           std::to_string(limits.max_rules));
    }
    for (std::size_t i = 0; i < array.size(); ++i) {
      auto rule = rule_from_json(array[i], limits, json_index_path("bundle.rules", i));
      if (!rule) {
        return rule.status();
      }
      bundle.rules.push_back(std::move(rule).value());
    }
  }

  return bundle;
}

}  // namespace fpe
