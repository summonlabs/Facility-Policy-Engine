#include "fpe/input.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "fpe/version.hpp"

namespace fpe {
namespace {

Status invalid_fact(std::string_view key, std::string message) {
  return Status::failure(ErrorCode::InvalidState,
                         "fact '" + std::string(key) + "': " + std::move(message));
}

}  // namespace

std::string_view fact_state_name(FactState state) noexcept {
  switch (state) {
    case FactState::Missing:
      return "missing";
    case FactState::Unknown:
      return "unknown";
    case FactState::Stale:
      return "stale";
    case FactState::Observed:
      return "observed";
  }
  return "unknown";
}

Result<FactState> parse_fact_state(std::string_view text) {
  if (text == "missing") {
    return FactState::Missing;
  }
  if (text == "unknown") {
    return FactState::Unknown;
  }
  if (text == "stale") {
    return FactState::Stale;
  }
  if (text == "observed") {
    return FactState::Observed;
  }
  return Status::failure(ErrorCode::PolicySchema, "unrecognized fact state '" + std::string(text) + "'");
}

FactValue FactValue::boolean(bool value) noexcept {
  FactValue out;
  out.value_ = value;
  return out;
}

FactValue FactValue::integer(std::int64_t value) noexcept {
  FactValue out;
  out.value_ = value;
  return out;
}

FactValue FactValue::symbol(std::string value) noexcept {
  FactValue out;
  out.value_ = Symbol{std::move(value)};
  return out;
}

FactValue FactValue::text(std::string value) noexcept {
  FactValue out;
  out.value_ = TextValue{std::move(value)};
  return out;
}

FactValue FactValue::symbol_set(SymbolSet values) noexcept {
  FactValue out;
  out.value_ = std::move(values);
  return out;
}

FactValue FactValue::quantity(std::int64_t magnitude, std::string unit) noexcept {
  FactValue out;
  out.value_ = Quantity{magnitude, std::move(unit)};
  return out;
}

bool FactValue::is_set() const noexcept { return !std::holds_alternative<std::monostate>(value_); }

FactType FactValue::type() const noexcept {
  if (std::holds_alternative<bool>(value_)) {
    return FactType::Boolean;
  }
  if (std::holds_alternative<std::int64_t>(value_)) {
    return FactType::Integer;
  }
  if (std::holds_alternative<Symbol>(value_)) {
    return FactType::Symbol;
  }
  if (std::holds_alternative<TextValue>(value_)) {
    return FactType::Text;
  }
  if (std::holds_alternative<SymbolSet>(value_)) {
    return FactType::SymbolSet;
  }
  if (std::holds_alternative<Quantity>(value_)) {
    return FactType::Quantity;
  }
  return FactType::Boolean;
}

const bool* FactValue::as_boolean() const noexcept { return std::get_if<bool>(&value_); }
const std::int64_t* FactValue::as_integer() const noexcept { return std::get_if<std::int64_t>(&value_); }

const std::string* FactValue::as_symbol() const noexcept {
  const auto* symbol = std::get_if<Symbol>(&value_);
  return symbol == nullptr ? nullptr : &symbol->value;
}

const std::string* FactValue::as_text() const noexcept {
  const auto* text = std::get_if<TextValue>(&value_);
  return text == nullptr ? nullptr : &text->value;
}

const FactValue::SymbolSet* FactValue::as_symbol_set() const noexcept {
  return std::get_if<SymbolSet>(&value_);
}

const FactValue::Quantity* FactValue::as_quantity() const noexcept {
  return std::get_if<Quantity>(&value_);
}

JsonValue FactValue::to_json() const {
  if (const bool* boolean_value = as_boolean()) {
    return JsonValue::boolean(*boolean_value);
  }
  if (const std::int64_t* integer_value = as_integer()) {
    return JsonValue::integer(*integer_value);
  }
  if (const std::string* symbol_value = as_symbol()) {
    return JsonValue::string(*symbol_value);
  }
  if (const std::string* text_value = as_text()) {
    return JsonValue::string(*text_value);
  }
  if (const SymbolSet* set = as_symbol_set()) {
    JsonValue::Array items;
    items.reserve(set->size());
    for (const auto& entry : *set) {
      items.push_back(JsonValue::string(entry));
    }
    return JsonValue::array(std::move(items));
  }
  if (const Quantity* quantity_value = as_quantity()) {
    JsonValue::Object members;
    members.emplace("magnitude", JsonValue::integer(quantity_value->magnitude));
    members.emplace("unit", JsonValue::string(quantity_value->unit));
    return JsonValue::object(std::move(members));
  }
  return JsonValue::null();
}

Result<FactValue> FactValue::from_json(const JsonValue& document, FactType expected, const Limits& limits,
                                       std::string_view path) {
  switch (expected) {
    case FactType::Boolean: {
      auto value = json_as_boolean(document, path);
      if (!value) {
        return value.status();
      }
      return FactValue::boolean(value.value());
    }
    case FactType::Integer: {
      auto value = json_as_integer(document, path);
      if (!value) {
        return value.status();
      }
      return FactValue::integer(value.value());
    }
    case FactType::Symbol: {
      auto value = json_as_string(document, path);
      if (!value) {
        return value.status();
      }
      if (auto reason = identifier_violation(value.value(), limits.max_identifier_bytes)) {
        return Status::failure(ErrorCode::InvalidIdentifier,
                               std::string(path) + ": not a valid symbol: " + *reason);
      }
      return FactValue::symbol(std::string(value.value()));
    }
    case FactType::Text: {
      auto value = json_as_string(document, path);
      if (!value) {
        return value.status();
      }
      if (auto reason = text_violation(value.value(), limits.max_text_bytes, true)) {
        return Status::failure(ErrorCode::InvalidUtf8, std::string(path) + ": not acceptable text: " + *reason);
      }
      return FactValue::text(std::string(value.value()));
    }
    case FactType::SymbolSet: {
      auto items = json_as_array(document, path);
      if (!items) {
        return items.status();
      }
      const JsonValue::Array& array = *items.value();
      if (array.size() > limits.max_collection_items) {
        return Status::failure(ErrorCode::LimitExceeded,
                               std::string(path) + " carries " + std::to_string(array.size()) +
                                   " symbols, above the maximum of " +
                                   std::to_string(limits.max_collection_items));
      }
      SymbolSet symbols;
      symbols.reserve(array.size());
      for (std::size_t i = 0; i < array.size(); ++i) {
        const std::string item_path = json_index_path(path, i);
        auto value = json_as_string(array[i], item_path);
        if (!value) {
          return value.status();
        }
        if (auto reason = identifier_violation(value.value(), limits.max_identifier_bytes)) {
          return Status::failure(ErrorCode::InvalidIdentifier,
                                 item_path + ": not a valid symbol: " + *reason);
        }
        symbols.emplace_back(value.value());
      }
      return FactValue::symbol_set(std::move(symbols));
    }
    case FactType::Quantity: {
      auto unknown = json_reject_unknown_members(document, {"magnitude", "unit"}, path);
      if (!unknown.ok()) {
        return unknown;
      }
      auto magnitude_member = json_require_member(document, "magnitude", path);
      if (!magnitude_member) {
        return magnitude_member.status();
      }
      auto magnitude = json_as_integer(*magnitude_member.value(), json_child_path(path, "magnitude"));
      if (!magnitude) {
        return magnitude.status();
      }
      auto unit_member = json_require_member(document, "unit", path);
      if (!unit_member) {
        return unit_member.status();
      }
      auto unit = json_as_string(*unit_member.value(), json_child_path(path, "unit"));
      if (!unit) {
        return unit.status();
      }
      if (auto reason = identifier_violation(unit.value(), limits.max_identifier_bytes)) {
        return Status::failure(ErrorCode::InvalidIdentifier,
                               std::string(json_child_path(path, "unit")) + ": not a valid unit: " + *reason);
      }
      return FactValue::quantity(magnitude.value(), std::string(unit.value()));
    }
  }
  return Status::failure(ErrorCode::PolicySchema, std::string(path) + ": unrecognized fact type");
}

bool fact_is_fresh(const Fact& fact, std::optional<TimestampNanos> as_of) noexcept {
  if (fact.state != FactState::Observed) {
    return false;
  }
  if (!fact.valid_until.has_value()) {
    return true;
  }
  if (!as_of.has_value()) {
    return false;
  }
  return as_of.value() <= fact.valid_until.value();
}

const Fact* InputSet::find(const FactKey& key) const noexcept {
  const auto found = std::lower_bound(facts_.begin(), facts_.end(), key,
                                      [](const Fact& fact, const FactKey& probe) { return fact.key < probe; });
  if (found == facts_.end() || !(found->key == key)) {
    return nullptr;
  }
  return &*found;
}

JsonValue InputSet::to_json() const { return facts_to_json(facts_); }

JsonValue facts_to_json(const std::vector<Fact>& facts) {
  std::vector<Fact> ordered = facts;
  std::sort(ordered.begin(), ordered.end(), [](const Fact& a, const Fact& b) { return a.key < b.key; });

  JsonValue::Object document;
  document.emplace("schema", JsonValue::integer(static_cast<std::int64_t>(kInputSchemaVersion)));
  JsonValue::Array items;
  items.reserve(ordered.size());
  for (const auto& fact : ordered) {
    JsonValue::Object item;
    item.emplace("key", JsonValue::string(fact.key.str()));
    item.emplace("state", JsonValue::string(std::string(fact_state_name(fact.state))));
    if (fact.type.has_value()) {
      item.emplace("type", JsonValue::string(std::string(fact_type_name(fact.type.value()))));
    }
    if (fact.state == FactState::Observed) {
      item.emplace("value", fact.value.to_json());
    }
    if (fact.authority.is_set()) {
      item.emplace("authority", JsonValue::string(fact.authority.str()));
    }
    if (fact.generation.has_value()) {
      item.emplace("generation", JsonValue::integer(static_cast<std::int64_t>(fact.generation->raw())));
    }
    if (fact.evidence_digest.has_value()) {
      item.emplace("evidence", JsonValue::string(fact.evidence_digest->to_hex()));
    }
    if (fact.observed_at.has_value()) {
      item.emplace("observed_at", JsonValue::integer(fact.observed_at->unix_nanos()));
    }
    if (fact.valid_until.has_value()) {
      item.emplace("valid_until", JsonValue::integer(fact.valid_until->unix_nanos()));
    }
    items.push_back(JsonValue::object(std::move(item)));
  }
  document.emplace("facts", JsonValue::array(std::move(items)));
  return JsonValue::object(std::move(document));
}

Result<std::vector<Fact>> facts_from_json(const JsonValue& document, const Limits& limits) {
  auto unknown = json_reject_unknown_members(document, {"schema", "facts"}, "input");
  if (!unknown.ok()) {
    return unknown;
  }
  auto schema_member = json_require_member(document, "schema", "input");
  if (!schema_member) {
    return schema_member.status();
  }
  auto schema = json_as_integer(*schema_member.value(), "input.schema");
  if (!schema) {
    return schema.status();
  }
  if (schema.value() != static_cast<std::int64_t>(kInputSchemaVersion)) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "input schema revision " + std::to_string(schema.value()) +
                               " is not supported by this build (expected " +
                               std::to_string(kInputSchemaVersion) + ")");
  }

  auto facts_member = json_require_member(document, "facts", "input");
  if (!facts_member) {
    return facts_member.status();
  }
  auto facts_array = json_as_array(*facts_member.value(), "input.facts");
  if (!facts_array) {
    return facts_array.status();
  }
  const JsonValue::Array& array = *facts_array.value();
  if (array.size() > limits.max_input_facts) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "input.facts carries " + std::to_string(array.size()) +
                               " entries, above the maximum of " + std::to_string(limits.max_input_facts));
  }

  std::vector<Fact> facts;
  facts.reserve(array.size());
  for (std::size_t i = 0; i < array.size(); ++i) {
    const JsonValue& item = array[i];
    const std::string item_path = json_index_path("input.facts", i);
    auto item_unknown =
        json_reject_unknown_members(item, {"key", "type", "state", "value", "authority", "generation",
                                           "evidence", "observed_at", "valid_until"},
                                    item_path);
    if (!item_unknown.ok()) {
      return item_unknown;
    }

    Fact fact;
    auto key_member = json_require_member(item, "key", item_path);
    if (!key_member) {
      return key_member.status();
    }
    auto key_text = json_as_string(*key_member.value(), json_child_path(item_path, "key"));
    if (!key_text) {
      return key_text.status();
    }
    auto key = FactKey::parse(key_text.value(), limits.max_identifier_bytes);
    if (!key) {
      return key.status();
    }
    fact.key = std::move(key).value();

    auto state_member = json_require_member(item, "state", item_path);
    if (!state_member) {
      return state_member.status();
    }
    auto state_text = json_as_string(*state_member.value(), json_child_path(item_path, "state"));
    if (!state_text) {
      return state_text.status();
    }
    auto state = parse_fact_state(state_text.value());
    if (!state) {
      return state.status();
    }
    fact.state = state.value();

    if (const JsonValue* type_member = json_optional_member(item, "type")) {
      auto type_text = json_as_string(*type_member, json_child_path(item_path, "type"));
      if (!type_text) {
        return type_text.status();
      }
      auto type = parse_fact_type(type_text.value());
      if (!type) {
        return type.status();
      }
      fact.type = type.value();
    } else if (fact.state == FactState::Observed) {
      return Status::failure(ErrorCode::JsonMissingField,
                             std::string(item_path) +
                                 ": an observed fact must declare its value type via 'type'");
    }

    if (const JsonValue* value_member = json_optional_member(item, "value")) {
      if (fact.state != FactState::Observed) {
        return invalid_fact(fact.key.str(),
                            std::string("state is '") + std::string(fact_state_name(fact.state)) +
                                "' but a value was supplied; a fact that is not observed must not carry a "
                                "value");
      }
      auto value = FactValue::from_json(*value_member, fact.type.value(), limits,
                                        json_child_path(item_path, "value"));
      if (!value) {
        return value.status();
      }
      fact.value = std::move(value).value();
    } else if (fact.state == FactState::Observed) {
      return Status::failure(ErrorCode::JsonMissingField,
                             std::string(item_path) + ": an observed fact must carry a value");
    }

    if (const JsonValue* authority_member = json_optional_member(item, "authority")) {
      auto text = json_as_string(*authority_member, json_child_path(item_path, "authority"));
      if (!text) {
        return text.status();
      }
      auto authority = AuthorityId::parse(text.value(), limits.max_identifier_bytes);
      if (!authority) {
        return authority.status();
      }
      fact.authority = std::move(authority).value();
    }

    if (const JsonValue* generation_member = json_optional_member(item, "generation")) {
      auto generation = json_as_integer(*generation_member, json_child_path(item_path, "generation"));
      if (!generation) {
        return generation.status();
      }
      if (generation.value() < 0) {
        return invalid_fact(fact.key.str(), "generation must not be negative");
      }
      fact.generation = Generation::from_raw(static_cast<std::uint64_t>(generation.value()));
    }

    if (const JsonValue* evidence_member = json_optional_member(item, "evidence")) {
      auto text = json_as_string(*evidence_member, json_child_path(item_path, "evidence"));
      if (!text) {
        return text.status();
      }
      auto digest = Digest256::from_hex(text.value());
      if (!digest) {
        return digest.status();
      }
      if (digest.value().is_zero()) {
        return invalid_fact(fact.key.str(), "evidence digest must not be the reserved all-zero digest");
      }
      fact.evidence_digest = digest.value();
    }

    if (const JsonValue* observed_member = json_optional_member(item, "observed_at")) {
      auto value = json_as_integer(*observed_member, json_child_path(item_path, "observed_at"));
      if (!value) {
        return value.status();
      }
      fact.observed_at = TimestampNanos::from_unix_nanos(value.value());
    }
    if (const JsonValue* valid_member = json_optional_member(item, "valid_until")) {
      auto value = json_as_integer(*valid_member, json_child_path(item_path, "valid_until"));
      if (!value) {
        return value.status();
      }
      fact.valid_until = TimestampNanos::from_unix_nanos(value.value());
    }

    facts.push_back(std::move(fact));
  }
  return facts;
}

Result<InputSet> input_set_from_json(const JsonValue& document, const Limits& limits) {
  auto facts = facts_from_json(document, limits);
  if (!facts) {
    return facts.status();
  }
  return build_input_set(std::move(facts).value(), limits);
}

Result<InputSet> build_input_set(std::vector<Fact> facts, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (facts.size() > limits.max_input_facts) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "input set carries " + std::to_string(facts.size()) +
                               " facts, above the maximum of " + std::to_string(limits.max_input_facts));
  }

  std::sort(facts.begin(), facts.end(), [](const Fact& a, const Fact& b) { return a.key < b.key; });
  for (std::size_t i = 1; i < facts.size(); ++i) {
    if (facts[i - 1].key == facts[i].key) {
      return Status::failure(ErrorCode::DuplicateIdentity,
                             "duplicate fact '" + facts[i].key.str() + "' in the input set");
    }
  }

  for (auto& fact : facts) {
    if (!fact.key.is_set()) {
      return Status::failure(ErrorCode::InvalidIdentifier, "a fact in the input set has no key");
    }
    if (fact.state == FactState::Observed) {
      if (!fact.value.is_set()) {
        return invalid_fact(fact.key.str(), "state is 'observed' but no value was supplied");
      }
      if (!fact.type.has_value()) {
        return invalid_fact(fact.key.str(), "state is 'observed' but no value type was declared");
      }
      if (fact.value.type() != fact.type.value()) {
        return invalid_fact(fact.key.str(),
                            "declared type '" + std::string(fact_type_name(fact.type.value())) +
                                "' does not match the supplied value type '" +
                                std::string(fact_type_name(fact.value.type())) + "'");
      }
    } else {
      if (fact.value.is_set()) {
        return invalid_fact(fact.key.str(),
                            std::string("state is '") + std::string(fact_state_name(fact.state)) +
                                "' but a value was supplied; a fact that is not observed must not carry a "
                                "value");
      }
    }

    if (const auto* symbols = fact.value.as_symbol_set()) {
      if (symbols->size() > limits.max_collection_items) {
        return invalid_fact(fact.key.str(), "symbol set carries " + std::to_string(symbols->size()) +
                                                " entries, above the maximum of " +
                                                std::to_string(limits.max_collection_items));
      }
      for (const auto& symbol : *symbols) {
        if (auto reason = identifier_violation(symbol, limits.max_identifier_bytes)) {
          return invalid_fact(fact.key.str(), "symbol set entry is not a valid symbol: " + *reason);
        }
      }
    }
    if (const auto* symbol = fact.value.as_symbol()) {
      if (auto reason = identifier_violation(*symbol, limits.max_identifier_bytes)) {
        return invalid_fact(fact.key.str(), "value is not a valid symbol: " + *reason);
      }
    }
    if (const auto* text = fact.value.as_text()) {
      if (auto reason = text_violation(*text, limits.max_text_bytes, true)) {
        return invalid_fact(fact.key.str(), "value is not acceptable text: " + *reason);
      }
    }
    if (const auto* quantity = fact.value.as_quantity()) {
      if (auto reason = identifier_violation(quantity->unit, limits.max_identifier_bytes)) {
        return invalid_fact(fact.key.str(), "quantity unit is not a valid symbol: " + *reason);
      }
    }

    if (fact.observed_at.has_value() && fact.valid_until.has_value() &&
        fact.valid_until.value() < fact.observed_at.value()) {
      return invalid_fact(fact.key.str(),
                          "validity deadline precedes the observation instant, which is impossible");
    }

    const bool has_authority = fact.authority.is_set();
    const bool has_generation = fact.generation.has_value();
    const bool has_digest = fact.evidence_digest.has_value();
    if (has_authority != has_generation || has_authority != has_digest) {
      return invalid_fact(fact.key.str(),
                          "provenance is incomplete: authority, generation, and evidence digest must be "
                          "supplied together or not at all");
    }
  }

  InputSet set;
  set.facts_ = std::move(facts);

  std::vector<AuthorityBinding> authorities;
  authorities.reserve(set.facts_.size());
  for (const auto& fact : set.facts_) {
    if (!fact.authority.is_set()) {
      continue;
    }
    AuthorityBinding binding;
    binding.authority = fact.authority;
    binding.generation = fact.generation.value();
    binding.digest = fact.evidence_digest.value();
    authorities.push_back(std::move(binding));
  }
  std::sort(authorities.begin(), authorities.end());
  authorities.erase(std::unique(authorities.begin(), authorities.end()), authorities.end());
  set.authorities_ = std::move(authorities);

  set.canonical_bytes_ = to_canonical_json(set.to_json());
  set.digest_ = Digest256::of(set.canonical_bytes_);
  return set;
}

}  // namespace fpe
