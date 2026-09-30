#include <algorithm>
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fpe/policy.hpp"

namespace fpe {
namespace {

Status schema_error(std::string_view path, std::string message) {
  return Status::failure(ErrorCode::PolicySchema, std::string(path) + ": " + std::move(message));
}

Status duplicate_error(std::string_view what, std::string_view name) {
  return Status::failure(ErrorCode::DuplicateIdentity,
                         "duplicate " + std::string(what) + " '" + std::string(name) + "'");
}

Status validate_operand_value(FactType fact_type, const JsonValue& operand, std::string_view path,
                              const Limits& limits) {
  switch (fact_type) {
    case FactType::Boolean:
      if (!operand.is_boolean()) {
        return schema_error(path, "operand must be a boolean for a boolean fact, found " +
                                      std::string(json_type_name(operand.type())));
      }
      return Status::success();
    case FactType::Integer:
      if (!operand.is_integer()) {
        return schema_error(path, "operand must be an integer for an integer fact, found " +
                                      std::string(json_type_name(operand.type())));
      }
      return Status::success();
    case FactType::Symbol: {
      auto text = json_as_string(operand, path);
      if (!text) {
        return text.status();
      }
      if (auto reason = identifier_violation(text.value(), limits.max_identifier_bytes)) {
        return schema_error(path, "operand is not a valid symbol: " + *reason);
      }
      return Status::success();
    }
    case FactType::Text: {
      auto text = json_as_string(operand, path);
      if (!text) {
        return text.status();
      }
      if (auto reason = text_violation(text.value(), limits.max_text_bytes, false)) {
        return schema_error(path, "operand is not acceptable text: " + *reason);
      }
      return Status::success();
    }
    case FactType::SymbolSet:
      return schema_error(path, "a symbol-set fact is compared with contains-all or contains-any, not with a "
                                "single value");
    case FactType::Quantity: {
      const auto* members = operand.as_object();
      if (members == nullptr) {
        return schema_error(path, "operand must be an object with 'magnitude' and 'unit' for a quantity fact");
      }
      auto unknown = json_reject_unknown_members(operand, {"magnitude", "unit"}, path);
      if (!unknown.ok()) {
        return unknown;
      }
      auto magnitude = json_require_member(operand, "magnitude", path);
      if (!magnitude) {
        return magnitude.status();
      }
      auto unit = json_require_member(operand, "unit", path);
      if (!unit) {
        return unit.status();
      }
      auto magnitude_value = json_as_integer(*magnitude.value(), json_child_path(path, "magnitude"));
      if (!magnitude_value) {
        return magnitude_value.status();
      }
      auto unit_text = json_as_string(*unit.value(), json_child_path(path, "unit"));
      if (!unit_text) {
        return unit_text.status();
      }
      if (auto reason = identifier_violation(unit_text.value(), limits.max_identifier_bytes)) {
        return schema_error(json_child_path(path, "unit"), "unit is not a valid symbol: " + *reason);
      }
      return Status::success();
    }
  }
  return schema_error(path, "unrecognized fact type");
}

Status validate_condition_inner(const Condition& condition, const PolicyIndex& index, const Limits& limits,
                                std::string_view path, std::uint32_t depth) {
  if (depth > limits.max_condition_depth) {
    return Status::failure(ErrorCode::LimitExceeded,
                           std::string(path) + ": condition nests deeper than the maximum of " +
                               std::to_string(limits.max_condition_depth) + " levels");
  }
  if (condition_node_count(condition) > limits.max_condition_nodes) {
    return Status::failure(ErrorCode::LimitExceeded,
                           std::string(path) + ": condition exceeds the maximum of " +
                               std::to_string(limits.max_condition_nodes) + " nodes");
  }

  switch (condition.kind) {
    case ConditionKind::All:
    case ConditionKind::Any: {
      if (condition.children.empty() && condition.kind == ConditionKind::Any) {
        return schema_error(path, "an 'any' condition requires at least one child");
      }
      for (std::size_t i = 0; i < condition.children.size(); ++i) {
        auto failure = validate_condition_inner(condition.children[i], index, limits,
                                                json_index_path(path, i), depth + 1);
        if (!failure.ok()) {
          return failure;
        }
      }
      return Status::success();
    }
    case ConditionKind::Not: {
      if (condition.children.size() != 1) {
        return schema_error(path, "a 'not' condition requires exactly one child");
      }
      return validate_condition_inner(condition.children[0], index, limits, json_child_path(path, "not"),
                                      depth + 1);
    }
    case ConditionKind::NamedRef: {
      if (index.predicates.find(condition.named) == index.predicates.end()) {
        return Status::failure(ErrorCode::UnknownReference,
                               std::string(path) + ": named predicate '" + condition.named.str() +
                                   "' is not declared by this or any resolved bundle");
      }
      return Status::success();
    }
    case ConditionKind::Test: {
      const auto declared = index.facts.find(condition.fact);
      if (declared == index.facts.end()) {
        return Status::failure(ErrorCode::UnknownReference,
                               std::string(path) + ": fact '" + condition.fact.str() +
                                   "' is not declared by this or any resolved bundle");
      }
      const FactType fact_type = declared->second;
      if (predicate_op_is_collection(condition.op) && condition.operands.size() > limits.max_collection_items) {
        return Status::failure(ErrorCode::LimitExceeded,
                               std::string(path) + ": operand collection exceeds the maximum of " +
                                   std::to_string(limits.max_collection_items) + " items");
      }
      auto operands_ok = validate_test_operands(fact_type, condition.op, condition.operands, path);
      if (!operands_ok.ok()) {
        return operands_ok;
      }
      if (predicate_op_is_collection(condition.op)) {
        // A membership or containment test compares the fact against a set of
        // symbols, so each operand is a symbol rather than a value of the
        // fact's own domain.
        for (std::size_t i = 0; i < condition.operands.size(); ++i) {
          const std::string operand_path = json_index_path(path, i);
          auto text = json_as_string(condition.operands[i], operand_path);
          if (!text) {
            return text.status();
          }
          if (auto reason = identifier_violation(text.value(), limits.max_identifier_bytes)) {
            return schema_error(operand_path, "operand is not a valid symbol: " + *reason);
          }
        }
        return Status::success();
      }
      for (std::size_t i = 0; i < condition.operands.size(); ++i) {
        auto operand_ok =
            validate_operand_value(fact_type, condition.operands[i], json_index_path(path, i), limits);
        if (!operand_ok.ok()) {
          return operand_ok;
        }
      }
      return Status::success();
    }
  }
  return schema_error(path, "unrecognized condition kind");
}

}  // namespace

std::string_view fact_type_name(FactType type) noexcept {
  switch (type) {
    case FactType::Boolean:
      return "boolean";
    case FactType::Integer:
      return "integer";
    case FactType::Symbol:
      return "symbol";
    case FactType::Text:
      return "text";
    case FactType::SymbolSet:
      return "symbol-set";
    case FactType::Quantity:
      return "quantity";
  }
  return "unknown";
}

std::string_view predicate_op_name(PredicateOp op) noexcept {
  switch (op) {
    case PredicateOp::Exists:
      return "exists";
    case PredicateOp::NotExists:
      return "not-exists";
    case PredicateOp::IsUnknown:
      return "is-unknown";
    case PredicateOp::IsStale:
      return "is-stale";
    case PredicateOp::IsMissing:
      return "is-missing";
    case PredicateOp::Equals:
      return "equals";
    case PredicateOp::NotEquals:
      return "not-equals";
    case PredicateOp::LessThan:
      return "less-than";
    case PredicateOp::LessOrEqual:
      return "less-or-equal";
    case PredicateOp::GreaterThan:
      return "greater-than";
    case PredicateOp::GreaterOrEqual:
      return "greater-or-equal";
    case PredicateOp::InSet:
      return "in-set";
    case PredicateOp::ContainsAll:
      return "contains-all";
    case PredicateOp::ContainsAny:
      return "contains-any";
  }
  return "unknown";
}

std::string_view condition_kind_name(ConditionKind kind) noexcept {
  switch (kind) {
    case ConditionKind::All:
      return "all";
    case ConditionKind::Any:
      return "any";
    case ConditionKind::Not:
      return "not";
    case ConditionKind::Test:
      return "test";
    case ConditionKind::NamedRef:
      return "named";
  }
  return "unknown";
}

std::string_view effect_name(Effect effect) noexcept {
  switch (effect) {
    case Effect::Allow:
      return "allow";
    case Effect::Refuse:
      return "refuse";
    case Effect::Defer:
      return "defer";
  }
  return "unknown";
}

std::string_view unknown_policy_name(UnknownPolicy policy) noexcept {
  switch (policy) {
    case UnknownPolicy::FailClosed:
      return "fail-closed";
    case UnknownPolicy::Refuse:
      return "refuse";
    case UnknownPolicy::Skip:
      return "skip";
  }
  return "unknown";
}

std::string_view default_outcome_name(DefaultOutcome outcome) noexcept {
  switch (outcome) {
    case DefaultOutcome::Unknown:
      return "unknown";
    case DefaultOutcome::Refuse:
      return "refuse";
  }
  return "unknown";
}

Result<FactType> parse_fact_type(std::string_view text) {
  if (text == "boolean") {
    return FactType::Boolean;
  }
  if (text == "integer") {
    return FactType::Integer;
  }
  if (text == "symbol") {
    return FactType::Symbol;
  }
  if (text == "text") {
    return FactType::Text;
  }
  if (text == "symbol-set") {
    return FactType::SymbolSet;
  }
  if (text == "quantity") {
    return FactType::Quantity;
  }
  return schema_error("type", "unrecognized fact type '" + std::string(text) + "'");
}

Result<PredicateOp> parse_predicate_op(std::string_view text) {
  const PredicateOp ops[] = {
      PredicateOp::Exists,         PredicateOp::NotExists,      PredicateOp::IsUnknown,
      PredicateOp::IsStale,        PredicateOp::IsMissing,      PredicateOp::Equals,
      PredicateOp::NotEquals,      PredicateOp::LessThan,       PredicateOp::LessOrEqual,
      PredicateOp::GreaterThan,    PredicateOp::GreaterOrEqual, PredicateOp::InSet,
      PredicateOp::ContainsAll,    PredicateOp::ContainsAny};
  for (const PredicateOp op : ops) {
    if (predicate_op_name(op) == text) {
      return op;
    }
  }
  return schema_error("op", "unrecognized predicate operator '" + std::string(text) + "'");
}

Result<Effect> parse_effect(std::string_view text) {
  if (text == "allow") {
    return Effect::Allow;
  }
  if (text == "refuse") {
    return Effect::Refuse;
  }
  if (text == "defer") {
    return Effect::Defer;
  }
  return schema_error("effect", "unrecognized effect '" + std::string(text) + "'");
}

Result<UnknownPolicy> parse_unknown_policy(std::string_view text) {
  if (text == "fail-closed") {
    return UnknownPolicy::FailClosed;
  }
  if (text == "refuse") {
    return UnknownPolicy::Refuse;
  }
  if (text == "skip") {
    return UnknownPolicy::Skip;
  }
  return schema_error("on_unknown", "unrecognized unknown-input policy '" + std::string(text) + "'");
}

Result<DefaultOutcome> parse_default_outcome(std::string_view text) {
  if (text == "unknown") {
    return DefaultOutcome::Unknown;
  }
  if (text == "refuse") {
    return DefaultOutcome::Refuse;
  }
  return schema_error("default_outcome", "unrecognized default outcome '" + std::string(text) + "'");
}

bool predicate_op_is_presence(PredicateOp op) noexcept {
  switch (op) {
    case PredicateOp::Exists:
    case PredicateOp::NotExists:
    case PredicateOp::IsUnknown:
    case PredicateOp::IsStale:
    case PredicateOp::IsMissing:
      return true;
    default:
      return false;
  }
}

bool predicate_op_is_collection(PredicateOp op) noexcept {
  return op == PredicateOp::InSet || op == PredicateOp::ContainsAll || op == PredicateOp::ContainsAny;
}

Status PolicyIndex::add(const Bundle& bundle) {
  for (const auto& declaration : bundle.facts) {
    const auto inserted = facts.emplace(declaration.key, declaration.type);
    if (!inserted.second && inserted.first->second != declaration.type) {
      return Status::failure(ErrorCode::ImportConflict,
                             "fact '" + declaration.key.str() + "' is declared as '" +
                                 std::string(fact_type_name(inserted.first->second)) + "' and as '" +
                                 std::string(fact_type_name(declaration.type)) + "' by different bundles");
    }
  }
  for (const auto& predicate : bundle.predicates) {
    const auto inserted = predicates.emplace(predicate.id, bundle.id);
    if (!inserted.second && !(inserted.first->second == bundle.id)) {
      return Status::failure(ErrorCode::ImportConflict,
                             "named predicate '" + predicate.id.str() + "' is declared by both '" +
                                 inserted.first->second.str() + "' and '" + bundle.id.str() + "'");
    }
  }
  return Status::success();
}

Status PolicyIndex::merge(const PolicyIndex& other) {
  for (const auto& entry : other.facts) {
    const auto inserted = facts.emplace(entry.first, entry.second);
    if (!inserted.second && inserted.first->second != entry.second) {
      return Status::failure(ErrorCode::ImportConflict,
                             "fact '" + entry.first.str() + "' is declared as '" +
                                 std::string(fact_type_name(inserted.first->second)) + "' and as '" +
                                 std::string(fact_type_name(entry.second)) + "' by different bundles");
    }
  }
  for (const auto& entry : other.predicates) {
    const auto inserted = predicates.emplace(entry.first, entry.second);
    if (!inserted.second && !(inserted.first->second == entry.second)) {
      return Status::failure(ErrorCode::ImportConflict,
                             "named predicate '" + entry.first.str() + "' is declared by both '" +
                                 inserted.first->second.str() + "' and '" + entry.second.str() + "'");
    }
  }
  return Status::success();
}

Status validate_bundle_conditions(const Bundle& bundle, const PolicyIndex& index, const Limits& limits) {
  for (std::size_t i = 0; i < bundle.predicates.size(); ++i) {
    const std::string path = "predicates[" + std::to_string(i) + "].body";
    auto failure = validate_condition_inner(bundle.predicates[i].body, index, limits, path, 1);
    if (!failure.ok()) {
      return failure;
    }
  }
  for (std::size_t i = 0; i < bundle.rules.size(); ++i) {
    const std::string path = "rules[" + std::to_string(i) + "].when";
    auto failure = validate_condition_inner(bundle.rules[i].applicability, index, limits, path, 1);
    if (!failure.ok()) {
      return failure;
    }
  }
  return Status::success();
}

Condition Condition::make_all(std::vector<Condition> children) {
  Condition condition;
  condition.kind = ConditionKind::All;
  condition.children = std::move(children);
  return condition;
}

Condition Condition::make_any(std::vector<Condition> children) {
  Condition condition;
  condition.kind = ConditionKind::Any;
  condition.children = std::move(children);
  return condition;
}

Condition Condition::make_not(Condition child) {
  Condition condition;
  condition.kind = ConditionKind::Not;
  condition.children.push_back(std::move(child));
  return condition;
}

Condition Condition::make_test(FactKey fact, PredicateOp op, std::vector<JsonValue> operands) {
  Condition condition;
  condition.kind = ConditionKind::Test;
  condition.fact = std::move(fact);
  condition.op = op;
  condition.operands = std::move(operands);
  return condition;
}

Condition Condition::make_named_ref(PredicateId named) {
  Condition condition;
  condition.kind = ConditionKind::NamedRef;
  condition.named = std::move(named);
  return condition;
}

Status validate_test_operands(FactType fact_type, PredicateOp op, const std::vector<JsonValue>& operands,
                              std::string_view path) {
  if (predicate_op_is_presence(op)) {
    if (!operands.empty()) {
      return schema_error(path, "operator '" + std::string(predicate_op_name(op)) + "' takes no operands");
    }
    return Status::success();
  }

  if (op == PredicateOp::InSet) {
    if (fact_type != FactType::Symbol) {
      return schema_error(path, "operator 'in-set' requires a symbol fact, found " +
                                    std::string(fact_type_name(fact_type)));
    }
    if (operands.empty()) {
      return schema_error(path, "operator 'in-set' requires at least one symbol");
    }
    return Status::success();
  }

  if (predicate_op_is_collection(op)) {
    if (fact_type != FactType::SymbolSet) {
      return schema_error(path, "operator '" + std::string(predicate_op_name(op)) +
                                    "' requires a symbol-set fact, found " +
                                    std::string(fact_type_name(fact_type)));
    }
    if (operands.empty()) {
      return schema_error(path, "operator '" + std::string(predicate_op_name(op)) +
                                    "' requires at least one symbol");
    }
    return Status::success();
  }

  const bool is_equality = op == PredicateOp::Equals || op == PredicateOp::NotEquals;
  if (!is_equality) {
    if (fact_type != FactType::Integer && fact_type != FactType::Quantity) {
      return schema_error(path, "ordering operator '" + std::string(predicate_op_name(op)) +
                                    "' requires an integer or quantity fact, found " +
                                    std::string(fact_type_name(fact_type)));
    }
  }
  if (fact_type == FactType::SymbolSet) {
    return schema_error(path, "a symbol-set fact supports only contains-all and contains-any");
  }
  if (operands.size() != 1) {
    return schema_error(path, "operator '" + std::string(predicate_op_name(op)) +
                                  "' requires exactly one operand");
  }
  return Status::success();
}

std::size_t condition_node_count(const Condition& condition) {
  std::size_t count = 0;
  std::vector<const Condition*> pending;
  pending.push_back(&condition);
  while (!pending.empty()) {
    const Condition* node = pending.back();
    pending.pop_back();
    count += 1;
    for (const auto& child : node->children) {
      pending.push_back(&child);
    }
  }
  return count;
}

void collect_condition_facts(const Condition& condition, std::set<FactKey>& out) {
  std::vector<const Condition*> pending;
  pending.push_back(&condition);
  while (!pending.empty()) {
    const Condition* node = pending.back();
    pending.pop_back();
    if (node->kind == ConditionKind::Test) {
      out.insert(node->fact);
    }
    for (const auto& child : node->children) {
      pending.push_back(&child);
    }
  }
}

void collect_condition_predicates(const Condition& condition, std::set<PredicateId>& out) {
  std::vector<const Condition*> pending;
  pending.push_back(&condition);
  while (!pending.empty()) {
    const Condition* node = pending.back();
    pending.pop_back();
    if (node->kind == ConditionKind::NamedRef) {
      out.insert(node->named);
    }
    for (const auto& child : node->children) {
      pending.push_back(&child);
    }
  }
}

Result<std::vector<PredicateId>> find_predicate_cycle(const Bundle& bundle) {
  std::map<PredicateId, std::vector<PredicateId>> edges;
  for (const auto& predicate : bundle.predicates) {
    std::set<PredicateId> referenced;
    collect_condition_predicates(predicate.body, referenced);
    edges[predicate.id] = std::vector<PredicateId>(referenced.begin(), referenced.end());
  }

  enum class Color : std::uint8_t { White = 0, Gray = 1, Black = 2 };
  std::map<PredicateId, Color> color;
  struct Frame {
    PredicateId id;
    std::size_t child_index;
  };
  std::vector<Frame> stack;

  for (const auto& entry : edges) {
    if (color[entry.first] != Color::White) {
      continue;
    }
    color[entry.first] = Color::Gray;
    stack.push_back(Frame{entry.first, 0});
    while (!stack.empty()) {
      const PredicateId current = stack.back().id;
      const std::vector<PredicateId>& successors = edges[current];
      const std::size_t index = stack.back().child_index;
      if (index >= successors.size()) {
        color[current] = Color::Black;
        stack.pop_back();
        continue;
      }
      stack.back().child_index = index + 1;
      const PredicateId child = successors[index];
      const Color child_color = color[child];
      if (child_color == Color::Gray) {
        std::vector<PredicateId> cycle;
        bool started = false;
        for (const Frame& frame : stack) {
          if (!started && frame.id == child) {
            started = true;
          }
          if (started) {
            cycle.push_back(frame.id);
          }
        }
        cycle.push_back(child);
        return cycle;
      }
      if (child_color == Color::White) {
        color[child] = Color::Gray;
        stack.push_back(Frame{child, 0});
      }
    }
  }
  return std::vector<PredicateId>{};
}

}  // namespace fpe
