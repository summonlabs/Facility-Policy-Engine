#include "fpe/engine.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fpe/version.hpp"

namespace fpe {
namespace {

/// Kleene three-valued logic. Unknown is a distinct value that is never coerced
/// to true or false.
enum class Truth : std::uint8_t { False = 0, True = 1, Unknown = 2 };

Truth negate(Truth value) noexcept {
  switch (value) {
    case Truth::False:
      return Truth::True;
    case Truth::True:
      return Truth::False;
    case Truth::Unknown:
      return Truth::Unknown;
  }
  return Truth::Unknown;
}

Truth conjunction(Truth a, Truth b) noexcept {
  if (a == Truth::False || b == Truth::False) {
    return Truth::False;
  }
  if (a == Truth::Unknown || b == Truth::Unknown) {
    return Truth::Unknown;
  }
  return Truth::True;
}

Truth disjunction(Truth a, Truth b) noexcept {
  if (a == Truth::True || b == Truth::True) {
    return Truth::True;
  }
  if (a == Truth::Unknown || b == Truth::Unknown) {
    return Truth::Unknown;
  }
  return Truth::False;
}

struct FactView {
  FactType declared_type = FactType::Boolean;
  bool supplied = false;
  FactState state = FactState::Missing;
  Freshness freshness = Freshness::NotObserved;
  bool type_conflict = false;
  const Fact* fact = nullptr;
};

struct ConditionOutcome {
  Truth value = Truth::Unknown;
  std::vector<FactKey> unknown_facts;
};

class Evaluator {
 public:
  Evaluator(const CanonicalBundle& bundle, const InputSet& inputs, const EvaluationOptions& options)
      : bundle_(bundle), inputs_(inputs), options_(options), facts_(bundle.declaration_closure().facts) {
    // Named predicates are resolvable from the whole dependency closure, not
    // just from this bundle, because a bundle may reuse a predicate declared by
    // one of its imports. The canonical bundles own each other, so these
    // pointers stay valid for as long as the evaluator exists.
    for (const CanonicalBundle* node : policy_set_closure(bundle)) {
      for (const auto& predicate : node->bundle().predicates) {
        predicate_bodies_.emplace(predicate.id, &predicate.body);
      }
    }
  }

  Result<DecisionArtifact> run() {
    const Bundle& source = bundle_.bundle();
    DecisionArtifact artifact;
    fill_identity(artifact);
    if (auto appraised = appraise_rules(source, artifact); !appraised.ok()) {
      return appraised;
    }
    // Requirements are computed before composition, because an unresolved
    // requirement is what stops the evaluation from granting permission.
    for (const auto& declaration : source.facts) {
      if (!declaration.required) {
        continue;
      }
      const FactView view = view_for(declaration.key);
      if (!(view.supplied && view.state == FactState::Observed && view.freshness == Freshness::Fresh &&
            !view.type_conflict)) {
        artifact.unresolved_requirements.push_back(declaration.key);
      }
    }
    std::sort(artifact.unresolved_requirements.begin(), artifact.unresolved_requirements.end());
    compose(source, artifact);
    if (options_.include_explanation) {
      explain(source, artifact);
    }
    if (auto finalized = finalize_artifact(artifact); !finalized.ok()) {
      return finalized;
    }
    return artifact;
  }

  std::vector<FactAppraisal> appraisals() {
    std::vector<FactAppraisal> out;
    for (const auto& entry : facts_) {
      const FactView view = view_for(entry.first);
      FactAppraisal appraisal;
      appraisal.key = entry.first;
      appraisal.declared_type = entry.second;
      appraisal.supplied = view.supplied;
      appraisal.state = view.state;
      appraisal.freshness = view.freshness;
      appraisal.type_conflict = view.type_conflict;
      appraisal.cause = cause_for(view);
      out.push_back(std::move(appraisal));
    }
    return out;
  }

 private:
  /// Charges \p steps against the evaluation budget. A breach is remembered
  /// and reported once, so a deeply nested or very wide condition cannot be used
  /// to make evaluation cost unbounded.
  bool consume(std::uint64_t steps) {
    if (!overflow_.ok()) {
      return false;
    }
    if (steps > options_.limits.max_evaluation_steps - steps_used_) {
      overflow_ = Status::failure(ErrorCode::EvaluationLimitReached,
                                  "evaluation exceeded the configured step bound of " +
                                      std::to_string(options_.limits.max_evaluation_steps) + " steps");
      return false;
    }
    steps_used_ += steps;
    return true;
  }

  const FactView& view_for(const FactKey& key) {
    const auto cached = view_cache_.find(key);
    if (cached != view_cache_.end()) {
      return cached->second;
    }
    FactView view;
    const auto declared = facts_.find(key);
    if (declared != facts_.end()) {
      view.declared_type = declared->second;
    }
    const Fact* fact = inputs_.find(key);
    if (fact != nullptr) {
      view.supplied = true;
      view.fact = fact;
      view.state = fact->state;
      view.freshness = appraise_freshness(*fact, options_.as_of);
      if (fact->type.has_value() && fact->type.value() != view.declared_type) {
        view.type_conflict = true;
      }
      if (fact->state == FactState::Observed && fact->value.is_set() &&
          fact->value.type() != view.declared_type) {
        view.type_conflict = true;
      }
    }
    const auto inserted = view_cache_.emplace(key, std::move(view));
    return inserted.first->second;
  }

  static AppraisalCause cause_for(const FactView& view) {
    if (!view.supplied) {
      return AppraisalCause::PrerequisiteNotSupplied;
    }
    if (view.type_conflict) {
      return AppraisalCause::PrerequisiteTypeConflict;
    }
    switch (view.state) {
      case FactState::Missing:
        return AppraisalCause::PrerequisiteMissing;
      case FactState::Unknown:
        return AppraisalCause::PrerequisiteUnknown;
      case FactState::Stale:
        return AppraisalCause::PrerequisiteStale;
      case FactState::Observed:
        break;
    }
    switch (view.freshness) {
      case Freshness::Expired:
        return AppraisalCause::PrerequisiteExpired;
      case Freshness::Undeterminable:
        return AppraisalCause::PrerequisiteFreshnessUndeterminable;
      case Freshness::Fresh:
      case Freshness::NotObserved:
        return AppraisalCause::None;
    }
    return AppraisalCause::None;
  }

  /// True when the fact is usable as a current observation for this evaluation.
  static bool is_usable(const FactView& view) {
    return view.supplied && !view.type_conflict && view.state == FactState::Observed &&
           view.freshness == Freshness::Fresh;
  }

  ConditionOutcome evaluate_condition(const Condition& condition, std::uint32_t depth) {
    ConditionOutcome outcome;
    if (depth > options_.limits.max_condition_depth) {
      return outcome;
    }
    if (!consume(1)) {
      return outcome;
    }
    switch (condition.kind) {
      case ConditionKind::All: {
        Truth value = Truth::True;
        for (const auto& child : condition.children) {
          const ConditionOutcome child_outcome = evaluate_condition(child, depth + 1);
          if (child_outcome.value == Truth::Unknown) {
            for (const auto& key : child_outcome.unknown_facts) {
              outcome.unknown_facts.push_back(key);
            }
          }
          value = conjunction(value, child_outcome.value);
        }
        outcome.value = value;
        if (value != Truth::Unknown) {
          outcome.unknown_facts.clear();
        }
        return outcome;
      }
      case ConditionKind::Any: {
        Truth value = Truth::False;
        for (const auto& child : condition.children) {
          const ConditionOutcome child_outcome = evaluate_condition(child, depth + 1);
          if (child_outcome.value == Truth::Unknown) {
            for (const auto& key : child_outcome.unknown_facts) {
              outcome.unknown_facts.push_back(key);
            }
          }
          value = disjunction(value, child_outcome.value);
        }
        outcome.value = value;
        if (value != Truth::Unknown) {
          outcome.unknown_facts.clear();
        }
        return outcome;
      }
      case ConditionKind::Not: {
        const ConditionOutcome child_outcome = evaluate_condition(condition.children.front(), depth + 1);
        outcome.value = negate(child_outcome.value);
        if (outcome.value == Truth::Unknown) {
          outcome.unknown_facts = child_outcome.unknown_facts;
        }
        return outcome;
      }
      case ConditionKind::NamedRef: {
        const auto cached = predicate_cache_.find(condition.named);
        if (cached != predicate_cache_.end()) {
          return cached->second;
        }
        const auto found = predicate_bodies_.find(condition.named);
        if (found == predicate_bodies_.end()) {
          // Canonicalization resolved every named reference, so this cannot
          // happen for a compiled bundle. Failing closed keeps a programming
          // error from turning into a grant.
          return outcome;
        }
        if (!visiting_.insert(condition.named).second) {
          return outcome;
        }
        const ConditionOutcome body_outcome = evaluate_condition(*found->second, depth + 1);
        visiting_.erase(condition.named);
        predicate_cache_.emplace(condition.named, body_outcome);
        return body_outcome;
      }
      case ConditionKind::Test:
        return evaluate_test(condition);
    }
    return outcome;
  }

  ConditionOutcome evaluate_test(const Condition& condition) {
    ConditionOutcome outcome;
    if (!consume(1 + condition.operands.size())) {
      return outcome;
    }
    const FactView& view = view_for(condition.fact);
    const FactKey& key = condition.fact;

    const auto unknown = [&outcome, &key]() {
      outcome.value = Truth::Unknown;
      outcome.unknown_facts.push_back(key);
      return outcome;
    };
    const auto constant = [&outcome](Truth value) {
      outcome.value = value;
      return outcome;
    };

    switch (condition.op) {
      case PredicateOp::Exists: {
        if (!view.supplied) {
          return unknown();
        }
        if (view.state != FactState::Observed) {
          return constant(view.state == FactState::Unknown ? Truth::Unknown : Truth::False);
        }
        if (view.state == FactState::Unknown) {
          return unknown();
        }
        break;
      }
      case PredicateOp::NotExists: {
        if (!view.supplied) {
          return unknown();
        }
        if (view.state != FactState::Observed) {
          if (view.state == FactState::Unknown) {
            return unknown();
          }
          return constant(Truth::True);
        }
        break;
      }
      case PredicateOp::IsUnknown:
        if (!view.supplied) {
          return unknown();
        }
        return constant(view.state == FactState::Unknown ? Truth::True : Truth::False);
      case PredicateOp::IsStale:
        if (!view.supplied) {
          return unknown();
        }
        return constant(view.state == FactState::Stale ? Truth::True : Truth::False);
      case PredicateOp::IsMissing:
        if (!view.supplied) {
          return unknown();
        }
        return constant(view.state == FactState::Missing ? Truth::True : Truth::False);
      default:
        break;
    }

    // Exists / NotExists reached here with an observed fact: freshness decides.
    if (view.type_conflict) {
      return unknown();
    }
    if (view.freshness == Freshness::Undeterminable) {
      return unknown();
    }
    const bool fresh = view.freshness == Freshness::Fresh;
    if (condition.op == PredicateOp::Exists) {
      return constant(fresh ? Truth::True : Truth::False);
    }
    if (condition.op == PredicateOp::NotExists) {
      return constant(fresh ? Truth::False : Truth::True);
    }

    if (!is_usable(view)) {
      return unknown();
    }

    const FactValue& value = view.fact->value;
    switch (condition.op) {
      case PredicateOp::Equals:
        return constant(value_equals(value, condition.operands.front()));
      case PredicateOp::NotEquals:
        return constant(negate(value_equals(value, condition.operands.front())));
      case PredicateOp::LessThan:
      case PredicateOp::LessOrEqual:
      case PredicateOp::GreaterThan:
      case PredicateOp::GreaterOrEqual:
        return constant(value_ordered(value, condition.operands.front(), condition.op));
      case PredicateOp::InSet: {
        const std::string* symbol = value.as_symbol();
        if (symbol == nullptr) {
          return unknown();
        }
        for (const auto& operand : condition.operands) {
          const std::string* candidate = operand.as_string();
          if (candidate != nullptr && *candidate == *symbol) {
            return constant(Truth::True);
          }
        }
        return constant(Truth::False);
      }
      case PredicateOp::ContainsAll:
      case PredicateOp::ContainsAny: {
        const FactValue::SymbolSet* set = value.as_symbol_set();
        if (set == nullptr) {
          return unknown();
        }
        bool all_present = true;
        bool any_present = false;
        for (const auto& operand : condition.operands) {
          const std::string* candidate = operand.as_string();
          if (candidate == nullptr) {
            continue;
          }
          const bool present = std::find(set->begin(), set->end(), *candidate) != set->end();
          all_present = all_present && present;
          any_present = any_present || present;
        }
        return constant(condition.op == PredicateOp::ContainsAll
                            ? (all_present ? Truth::True : Truth::False)
                            : (any_present ? Truth::True : Truth::False));
      }
      default:
        break;
    }
    return unknown();
  }

  /// Equality over the closed value domain. A quantity comparison across two
  /// different units is Unknown: the engine performs no unit conversion, so it
  /// cannot claim the magnitudes are comparable.
  static Truth value_equals(const FactValue& value, const JsonValue& operand) {
    switch (value.type()) {
      case FactType::Boolean: {
        const bool* lhs = value.as_boolean();
        const bool* rhs = operand.as_boolean();
        if (lhs == nullptr || rhs == nullptr) {
          return Truth::Unknown;
        }
        return *lhs == *rhs ? Truth::True : Truth::False;
      }
      case FactType::Integer: {
        const std::int64_t* lhs = value.as_integer();
        const std::int64_t* rhs = operand.as_integer();
        if (lhs == nullptr || rhs == nullptr) {
          return Truth::Unknown;
        }
        return *lhs == *rhs ? Truth::True : Truth::False;
      }
      case FactType::Symbol: {
        const std::string* lhs = value.as_symbol();
        const std::string* rhs = operand.as_string();
        if (lhs == nullptr || rhs == nullptr) {
          return Truth::Unknown;
        }
        return *lhs == *rhs ? Truth::True : Truth::False;
      }
      case FactType::Text: {
        const std::string* lhs = value.as_text();
        const std::string* rhs = operand.as_string();
        if (lhs == nullptr || rhs == nullptr) {
          return Truth::Unknown;
        }
        return *lhs == *rhs ? Truth::True : Truth::False;
      }
      case FactType::Quantity: {
        const FactValue::Quantity* lhs = value.as_quantity();
        const JsonValue* magnitude = operand.member("magnitude");
        const JsonValue* unit = operand.member("unit");
        if (lhs == nullptr || magnitude == nullptr || unit == nullptr) {
          return Truth::Unknown;
        }
        const std::int64_t* rhs_magnitude = magnitude->as_integer();
        const std::string* rhs_unit = unit->as_string();
        if (rhs_magnitude == nullptr || rhs_unit == nullptr) {
          return Truth::Unknown;
        }
        if (!(lhs->unit == *rhs_unit)) {
          return Truth::Unknown;
        }
        return lhs->magnitude == *rhs_magnitude ? Truth::True : Truth::False;
      }
      case FactType::SymbolSet:
        return Truth::Unknown;
    }
    return Truth::Unknown;
  }

  static Truth value_ordered(const FactValue& value, const JsonValue& operand, PredicateOp op) {
    std::int64_t lhs = 0;
    std::int64_t rhs = 0;
    if (value.type() == FactType::Integer) {
      const std::int64_t* left = value.as_integer();
      const std::int64_t* right = operand.as_integer();
      if (left == nullptr || right == nullptr) {
        return Truth::Unknown;
      }
      lhs = *left;
      rhs = *right;
    } else if (value.type() == FactType::Quantity) {
      const FactValue::Quantity* left = value.as_quantity();
      const JsonValue* magnitude = operand.member("magnitude");
      const JsonValue* unit = operand.member("unit");
      if (left == nullptr || magnitude == nullptr || unit == nullptr) {
        return Truth::Unknown;
      }
      const std::int64_t* right = magnitude->as_integer();
      const std::string* right_unit = unit->as_string();
      if (right == nullptr || right_unit == nullptr) {
        return Truth::Unknown;
      }
      if (!(left->unit == *right_unit)) {
        return Truth::Unknown;
      }
      lhs = left->magnitude;
      rhs = *right;
    } else {
      return Truth::Unknown;
    }

    const int order = lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
    switch (op) {
      case PredicateOp::LessThan:
        return order < 0 ? Truth::True : Truth::False;
      case PredicateOp::LessOrEqual:
        return order <= 0 ? Truth::True : Truth::False;
      case PredicateOp::GreaterThan:
        return order > 0 ? Truth::True : Truth::False;
      case PredicateOp::GreaterOrEqual:
        return order >= 0 ? Truth::True : Truth::False;
      default:
        return Truth::Unknown;
    }
  }

  void fill_identity(DecisionArtifact& artifact) const {
    const Bundle& source = bundle_.bundle();
    artifact.schema_version = kArtifactSchemaVersion;
    artifact.evaluator_revision = kEvaluatorRevision;
    artifact.bundle = source.id;
    artifact.bundle_revision = source.revision;
    artifact.bundle_digest = bundle_.digest();
    artifact.policy_generation = options_.binding.generation;
    artifact.control_epoch = options_.binding.control_epoch;
    artifact.input_digest = inputs_.digest();
    artifact.authorities = inputs_.authorities();
    artifact.evaluation_steps = 0;
  }

  Status appraise_rules(const Bundle& source, DecisionArtifact& artifact) {
    artifact.rules.reserve(source.rules.size());
    for (const auto& rule : source.rules) {
      if (!consume(1)) {
        return overflow_;
      }
      RuleOutcome record;
      record.id = rule.id;
      record.priority = rule.priority;
      record.effect = rule.effect;
      record.on_unknown = rule.on_unknown;
      record.reason = rule.reason;

      std::set<FactKey> unresolved;
      AppraisalCause cause = AppraisalCause::None;
      for (const auto& key : rule.prerequisites) {
        const FactView& view = view_for(key);
        if (is_usable(view)) {
          continue;
        }
        unresolved.insert(key);
        if (cause == AppraisalCause::None) {
          const AppraisalCause candidate = cause_for(view);
          cause = candidate == AppraisalCause::None ? AppraisalCause::PrerequisiteUnknown : candidate;
        }
      }

      if (!unresolved.empty()) {
        record.unresolved.assign(unresolved.begin(), unresolved.end());
        switch (rule.on_unknown) {
          case UnknownPolicy::FailClosed:
            record.disposition = RuleDisposition::Undecided;
            record.cause = cause;
            record.detail = Text::parse("a declared prerequisite is not a fresh observation",
                                        options_.limits.max_text_bytes, true)
                                .value();
            break;
          case UnknownPolicy::Refuse:
            record.disposition = RuleDisposition::RefusedByUnknown;
            record.cause = AppraisalCause::RefusedByUnknownPolicy;
            record.detail = Text::parse("refused because a declared prerequisite is not a fresh observation",
                                        options_.limits.max_text_bytes, true)
                                .value();
            break;
          case UnknownPolicy::Skip:
            record.disposition = RuleDisposition::Skipped;
            record.cause = AppraisalCause::SkippedByUnknownPolicy;
            record.detail = Text::parse("skipped because a declared prerequisite is not a fresh observation",
                                        options_.limits.max_text_bytes, true)
                                .value();
            break;
        }
        artifact.rules.push_back(std::move(record));
        continue;
      }

      const ConditionOutcome condition = evaluate_condition(rule.applicability, 1);
      switch (condition.value) {
        case Truth::True:
          record.disposition = RuleDisposition::Matched;
          record.cause = AppraisalCause::None;
          break;
        case Truth::False:
          record.disposition = RuleDisposition::NotApplicable;
          record.cause = AppraisalCause::ConditionFalse;
          break;
        case Truth::Unknown:
          record.unresolved = condition.unknown_facts;
          std::sort(record.unresolved.begin(), record.unresolved.end());
          record.unresolved.erase(std::unique(record.unresolved.begin(), record.unresolved.end()),
                                  record.unresolved.end());
          if (!record.unresolved.empty()) {
            // Name the concrete reason the fact could not be used, so a
            // refusal or an unknown is attributable to an input condition
            // rather than to a generic "unknown".
            const AppraisalCause fact_cause = cause_for(view_for(record.unresolved.front()));
            if (fact_cause != AppraisalCause::None) {
              record.cause = fact_cause;
            }
          }
          switch (rule.on_unknown) {
            case UnknownPolicy::FailClosed:
              record.disposition = RuleDisposition::Undecided;
              if (record.cause == AppraisalCause::None) {
                record.cause = AppraisalCause::ConditionUnknown;
              }
              record.detail =
                  Text::parse("applicability could not be established", options_.limits.max_text_bytes, true)
                      .value();
              break;
            case UnknownPolicy::Refuse:
              record.disposition = RuleDisposition::RefusedByUnknown;
              record.cause = AppraisalCause::RefusedByUnknownPolicy;
              record.detail = Text::parse("refused because applicability could not be established",
                                          options_.limits.max_text_bytes, true)
                                  .value();
              break;
            case UnknownPolicy::Skip:
              record.disposition = RuleDisposition::Skipped;
              record.cause = AppraisalCause::SkippedByUnknownPolicy;
              record.detail = Text::parse("skipped because applicability could not be established",
                                          options_.limits.max_text_bytes, true)
                                  .value();
              break;
          }
          break;
      }
      artifact.rules.push_back(std::move(record));
    }
    artifact.evaluation_steps = steps_used_;
    return overflow_;
  }

  void compose(const Bundle& source, DecisionArtifact& artifact) {
    for (const auto& record : artifact.rules) {
      switch (record.disposition) {
        case RuleDisposition::Matched:
          artifact.matched_rules.push_back(record.id);
          break;
        case RuleDisposition::RefusedByUnknown:
          artifact.matched_rules.push_back(record.id);
          break;
        case RuleDisposition::Skipped:
          artifact.failed_open_rules.push_back(record.id);
          break;
        case RuleDisposition::Undecided:
          artifact.undecided_rules.push_back(record.id);
          break;
        case RuleDisposition::NotApplicable:
          break;
      }
      if (record.disposition == RuleDisposition::Matched ||
          record.disposition == RuleDisposition::RefusedByUnknown) {
        switch (record.effect) {
          case Effect::Refuse:
            artifact.refused_rules.push_back(record.id);
            break;
          case Effect::Allow:
            artifact.allowed_rules.push_back(record.id);
            break;
          case Effect::Defer:
            artifact.deferred_rules.push_back(record.id);
            break;
        }
      }
    }
    if (!artifact.failed_open_rules.empty()) {
      artifact.failed_open = true;
    }

    // Only one band can decide: the highest priority among rules that are not
    // provably inapplicable. A rule below a band that decided never overrides
    // it, which is exactly what makes the result independent of rule order.
    std::optional<std::int32_t> deciding_band;
    for (const auto& record : artifact.rules) {
      if (record.disposition == RuleDisposition::NotApplicable ||
          record.disposition == RuleDisposition::Skipped) {
        continue;
      }
      const std::int32_t band = record.priority.raw();
      if (!deciding_band.has_value() || band > deciding_band.value()) {
        deciding_band = band;
      }
    }

    if (!deciding_band.has_value()) {
      artifact.deciding_priority.reset();
      if (!artifact.unresolved_requirements.empty()) {
        artifact.outcome = Outcome::Unknown;
        return;
      }
      artifact.outcome =
          source.default_outcome == DefaultOutcome::Refuse ? Outcome::Refuse : Outcome::Unknown;
      return;
    }

    const std::int32_t band = deciding_band.value();
    std::vector<const RuleOutcome*> refusals;
    std::vector<const RuleOutcome*> allowances;
    std::vector<const RuleOutcome*> deferrals;
    std::vector<const RuleOutcome*> undecided;
    for (const auto& record : artifact.rules) {
      if (record.priority.raw() != band) {
        continue;
      }
      switch (record.disposition) {
        case RuleDisposition::Matched:
          if (record.effect == Effect::Refuse) {
            refusals.push_back(&record);
          } else if (record.effect == Effect::Allow) {
            allowances.push_back(&record);
          } else {
            deferrals.push_back(&record);
          }
          break;
        case RuleDisposition::RefusedByUnknown:
          refusals.push_back(&record);
          break;
        case RuleDisposition::Undecided:
          undecided.push_back(&record);
          break;
        case RuleDisposition::NotApplicable:
        case RuleDisposition::Skipped:
          break;
      }
    }

    artifact.deciding_priority = Priority::from_raw(band);
    if (!refusals.empty()) {
      // A refusal is safe even when other rules of the band are undecided, and
      // a band that both allows and refuses never resolves to allow.
      artifact.outcome = Outcome::Refuse;
      artifact.contradictory_hard_rules = !allowances.empty();
      return;
    }
    if (!deferrals.empty()) {
      if (!undecided.empty()) {
        artifact.outcome = Outcome::Unknown;
        return;
      }
      artifact.outcome = Outcome::Defer;
      artifact.deciding_priority.reset();
      return;
    }
    if (!allowances.empty()) {
      if (!undecided.empty() || !artifact.unresolved_requirements.empty()) {
        // Permission is not granted while a rule in this band could still
        // refuse, nor while the bundle's own required inputs are unresolved.
        artifact.outcome = Outcome::Unknown;
        return;
      }
      artifact.outcome = Outcome::Allow;
      std::set<ObligationCode> obligations;
      for (const RuleOutcome* record : allowances) {
        const Rule* rule = find_rule(source, record->id);
        if (rule == nullptr) {
          continue;
        }
        for (const auto& code : rule->obligations) {
          obligations.insert(code);
        }
      }
      artifact.obligations.assign(obligations.begin(), obligations.end());
      return;
    }

    // The deciding band holds only undecided rules, so nothing is established.
    artifact.outcome = Outcome::Unknown;
  }

  void explain(const Bundle& source, DecisionArtifact& artifact) {
    std::vector<std::string>& lines = artifact.explanation;
    const auto append = [this, &artifact, &lines](std::string line) {
      if (lines.size() >= options_.limits.max_explanation_entries) {
        artifact.explanation_truncated = true;
        return;
      }
      if (line.size() > options_.limits.max_text_bytes) {
        line.resize(options_.limits.max_text_bytes);
      }
      lines.push_back(std::move(line));
    };

    std::string headline = "outcome ";
    headline.append(outcome_name(artifact.outcome));
    if (artifact.deciding_priority.has_value()) {
      headline.append(" decided at priority ");
      headline.append(std::to_string(artifact.deciding_priority->raw()));
    } else {
      headline.append(" decided by the bundle default");
    }
    append(std::move(headline));

    if (artifact.contradictory_hard_rules) {
      append("a hard allow and a hard refuse matched at the same priority; the decision is refuse");
    }
    for (const auto& record : artifact.rules) {
      if (record.disposition == RuleDisposition::NotApplicable) {
        continue;
      }
      std::string line = "rule '";
      line.append(record.id.str());
      line.append("' priority ");
      line.append(std::to_string(record.priority.raw()));
      line.append(" effect ");
      line.append(effect_name(record.effect));
      line.append(" -> ");
      line.append(rule_disposition_name(record.disposition));
      line.append(" (");
      line.append(appraisal_cause_name(record.cause));
      line.append(") reason ");
      line.append(record.reason.str());
      if (!record.unresolved.empty()) {
        line.append(" unresolved ");
        for (std::size_t i = 0; i < record.unresolved.size(); ++i) {
          if (i > 0) {
            line.append(",");
          }
          line.append(record.unresolved[i].str());
        }
      }
      if (!record.detail.empty()) {
        line.append("; ");
        line.append(record.detail.str());
      }
      append(std::move(line));
    }
    for (const auto& key : artifact.unresolved_requirements) {
      const FactView& view = view_for(key);
      std::string line = "required fact '";
      line.append(key.str());
      line.append("' is not a fresh observation (");
      line.append(appraisal_cause_name(cause_for(view)));
      line.append(")");
      append(std::move(line));
    }
    for (const auto& binding : artifact.authorities) {
      std::string line = "authority '";
      line.append(binding.authority.str());
      line.append("' generation ");
      line.append(std::to_string(binding.generation.raw()));
      line.append(" digest ");
      line.append(binding.digest.to_hex());
      append(std::move(line));
    }
    (void)source;
  }

  static const Rule* find_rule(const Bundle& source, const RuleId& id) {
    const auto found = std::lower_bound(
        source.rules.begin(), source.rules.end(), id,
        [](const Rule& rule, const RuleId& probe) { return rule.id < probe; });
    if (found == source.rules.end() || !(found->id == id)) {
      return nullptr;
    }
    return &*found;
  }

  const CanonicalBundle& bundle_;
  const InputSet& inputs_;
  const EvaluationOptions& options_;
  const std::map<FactKey, FactType>& facts_;
  std::map<FactKey, FactView> view_cache_;
  std::map<PredicateId, const Condition*> predicate_bodies_;
  std::map<PredicateId, ConditionOutcome> predicate_cache_;
  std::set<PredicateId> visiting_;
  std::uint64_t steps_used_ = 0;
  Status overflow_;
};

}  // namespace

std::string_view freshness_name(Freshness freshness) noexcept {
  switch (freshness) {
    case Freshness::NotObserved:
      return "not-observed";
    case Freshness::Fresh:
      return "fresh";
    case Freshness::Expired:
      return "expired";
    case Freshness::Undeterminable:
      return "undeterminable";
  }
  return "unknown";
}

Freshness appraise_freshness(const Fact& fact, std::optional<TimestampNanos> as_of) noexcept {
  if (fact.state != FactState::Observed) {
    return Freshness::NotObserved;
  }
  if (!fact.valid_until.has_value()) {
    return Freshness::Fresh;
  }
  if (!as_of.has_value()) {
    return Freshness::Undeterminable;
  }
  return as_of.value() <= fact.valid_until.value() ? Freshness::Fresh : Freshness::Expired;
}

Result<DecisionArtifact> evaluate(const CanonicalBundle& bundle, const InputSet& inputs,
                                  const EvaluationOptions& options) {
  if (auto limits_failure = validate_limits(options.limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (!(options.binding.generation.has_value() == options.binding.control_epoch.has_value())) {
    return Status::failure(ErrorCode::InvalidState,
                           "a policy binding must supply both a generation and a control epoch, or neither");
  }
  Evaluator evaluator(bundle, inputs, options);
  return evaluator.run();
}

Result<std::vector<FactAppraisal>> appraise_inputs(const CanonicalBundle& bundle, const InputSet& inputs,
                                                   const EvaluationOptions& options) {
  if (auto limits_failure = validate_limits(options.limits); !limits_failure.ok()) {
    return limits_failure;
  }
  Evaluator evaluator(bundle, inputs, options);
  return evaluator.appraisals();
}

}  // namespace fpe
