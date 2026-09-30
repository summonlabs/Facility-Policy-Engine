#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "fpe/decision.hpp"
#include "fpe/engine.hpp"
#include "fpe/limits.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::AppraisalCause;
using fpe::ErrorCode;
using fpe::Limits;
using fpe::Outcome;
using fpe::RuleDisposition;
using fpe::Status;

namespace {

fpe::Result<fpe::DecisionArtifact> run(std::string_view bundle_json, std::string_view input_json,
                                       std::optional<fpe::TimestampNanos> as_of = std::nullopt,
                                       Limits limits = Limits::defaults()) {
  auto compiled = fpe::test::compile_json(bundle_json, limits);
  if (!compiled) {
    return compiled.status();
  }
  auto inputs = fpe::test::inputs_from_json(input_json, limits);
  if (!inputs) {
    return inputs.status();
  }
  fpe::EvaluationOptions options;
  options.as_of = as_of;
  options.limits = limits;
  return fpe::evaluate(compiled.value(), inputs.value(), options);
}

/// A bundle with one integer fact and the rules given by \p rules_json.
std::string bundle_with_rules(std::string_view rules_json, std::string_view extra_facts = "") {
  return std::string("{\"schema\":1,\"bundle\":\"engine.test\",\"revision\":1,\"facts\":["
                     "{\"key\":\"f.n\",\"type\":\"integer\"},{\"key\":\"f.m\",\"type\":\"integer\"}") +
         std::string(extra_facts) + "],\"rules\":" + std::string(rules_json) + "}";
}

std::string allow_rule(std::string_view id, int priority, std::string_view when) {
  return "{\"id\":\"" + std::string(id) + "\",\"priority\":" + std::to_string(priority) +
         ",\"effect\":\"allow\",\"when\":" + std::string(when) + ",\"reason\":\"test.allow\"}";
}

/// Rule records are emitted in canonical identity order, not insertion order,
/// so a test must look one up by identity rather than by position.
const fpe::RuleOutcome* rule_of(const fpe::DecisionArtifact& artifact, std::string_view id) {
  for (const auto& record : artifact.rules) {
    if (record.id.str() == id) {
      return &record;
    }
  }
  return nullptr;
}

std::string refuse_rule(std::string_view id, int priority, std::string_view when) {
  return "{\"id\":\"" + std::string(id) + "\",\"priority\":" + std::to_string(priority) +
         ",\"effect\":\"refuse\",\"when\":" + std::string(when) + ",\"reason\":\"test.refuse\"}";
}

constexpr std::string_view kAlways = R"json({"all":[]})json";
// A condition that is provably false for the fixtures in this file: f.n is
// always observed as a small integer, so it never equals this.
constexpr std::string_view kNever = R"json({"test":{"fact":"f.n","op":"equals","operands":[999999]}})json";

}  // namespace

FPE_TEST(engine_allow_when_a_permission_rule_matches) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Allow);
  FPE_CHECK_EQ(artifact.value().allowed_rules.size(), std::size_t{1});
  FPE_CHECK(!artifact.value().failed_open);
  FPE_CHECK(!artifact.value().contradictory_hard_rules);
  FPE_CHECK(artifact.value().deciding_priority.has_value());
  FPE_CHECK_EQ(artifact.value().deciding_priority->raw(), std::int32_t{10});
}

FPE_TEST(engine_refuse_when_a_prohibition_rule_matches) {
  const std::string bundle = bundle_with_rules("[" + refuse_rule("r.refuse", 10, kAlways) + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Refuse);
  FPE_CHECK_EQ(artifact.value().refused_rules.size(), std::size_t{1});
}

FPE_TEST(engine_unknown_when_no_rule_applies) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kNever) + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Unknown);
  FPE_CHECK(!artifact.value().deciding_priority.has_value());
}

FPE_TEST(engine_declared_default_outcome_is_never_allow) {
  const std::string bundle =
      "{\"schema\":1,\"bundle\":\"engine.test\",\"revision\":1,\"default_outcome\":\"refuse\",\"rules\":[]}";
  auto artifact = run(bundle, fpe::test::input_document(""));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Refuse);

  // "allow" is not an accepted default, so a document cannot declare one.
  const std::string forbidden =
      "{\"schema\":1,\"bundle\":\"engine.test\",\"revision\":1,\"default_outcome\":\"allow\",\"rules\":[]}";
  auto refused = run(forbidden, fpe::test::input_document(""));
  FPE_CHECK(!refused.has_value());
}

FPE_TEST(engine_contradictory_hard_rules_never_resolve_to_allow) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                                               refuse_rule("r.refuse", 10, kAlways) + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Refuse);
  FPE_CHECK(artifact.value().contradictory_hard_rules);
  FPE_CHECK_EQ(artifact.value().allowed_rules.size(), std::size_t{1});
  FPE_CHECK_EQ(artifact.value().refused_rules.size(), std::size_t{1});
}

FPE_TEST(engine_priority_orders_rules_and_lower_priority_never_overrides) {
  const std::string refuse_wins = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                                                    refuse_rule("r.refuse", 20, kAlways) + "]");
  auto refused = run(refuse_wins, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(refused.has_value());
  FPE_CHECK_EQ(refused.value().outcome, Outcome::Refuse);
  FPE_CHECK(!refused.value().contradictory_hard_rules);
  FPE_CHECK_EQ(refused.value().deciding_priority->raw(), std::int32_t{20});

  const std::string allow_wins = bundle_with_rules("[" + refuse_rule("r.refuse", 10, kAlways) + "," +
                                                   allow_rule("r.allow", 20, kAlways) + "]");
  auto allowed = run(allow_wins, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(allowed.has_value());
  FPE_CHECK_EQ(allowed.value().outcome, Outcome::Allow);
  FPE_CHECK_EQ(allowed.value().deciding_priority->raw(), std::int32_t{20});
}

FPE_TEST(engine_undecided_rule_above_a_permission_blocks_it) {
  const std::string at_same_priority =
      bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                        refuse_rule("r.refuse", 10, R"json({"test":{"fact":"f.m","op":"exists"}})json") + "]");
  auto blocked = run(at_same_priority, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(blocked.has_value());
  FPE_CHECK_EQ(blocked.value().outcome, Outcome::Unknown);
  FPE_CHECK_EQ(blocked.value().undecided_rules.size(), std::size_t{1});

  const std::string above =
      bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                        refuse_rule("r.refuse", 30, R"json({"test":{"fact":"f.m","op":"exists"}})json") + "]");
  auto blocked_above = run(above, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(blocked_above.has_value());
  FPE_CHECK_EQ(blocked_above.value().outcome, Outcome::Unknown);

  const std::string below =
      bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                        refuse_rule("r.refuse", 5, R"json({"test":{"fact":"f.m","op":"exists"}})json") + "]");
  auto still_allowed = run(below, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(still_allowed.has_value());
  FPE_CHECK_EQ(still_allowed.value().outcome, Outcome::Allow);
}

FPE_TEST(engine_undecided_rule_never_grants_permission) {
  const std::string bundle =
      bundle_with_rules("[" + allow_rule("r.allow", 10, R"json({"test":{"fact":"f.m","op":"exists"}})json") + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Unknown);
  FPE_CHECK(artifact.value().allowed_rules.empty());
  FPE_CHECK_EQ(artifact.value().undecided_rules.size(), std::size_t{1});
}

FPE_TEST(engine_unknown_policy_refuse_turns_uncertainty_into_an_explicit_refusal) {
  const std::string rule =
      "{\"id\":\"r.refuse\",\"priority\":10,\"effect\":\"refuse\",\"on_unknown\":\"refuse\","
      "\"when\":{\"test\":{\"fact\":\"f.m\",\"op\":\"exists\"}},\"reason\":\"test.refuse\"}";
  auto artifact = run(bundle_with_rules("[" + rule + "]"),
                      fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Refuse);
  const fpe::RuleOutcome* refused_rule = rule_of(artifact.value(), "r.refuse");
  FPE_REQUIRE(refused_rule != nullptr);
  FPE_CHECK_EQ(refused_rule->disposition, RuleDisposition::RefusedByUnknown);
  FPE_CHECK_EQ(refused_rule->cause, AppraisalCause::RefusedByUnknownPolicy);
}

FPE_TEST(engine_fail_open_is_explicit_and_always_reported) {
  const std::string rule =
      "{\"id\":\"r.skip\",\"priority\":10,\"effect\":\"refuse\",\"on_unknown\":\"skip\","
      "\"when\":{\"test\":{\"fact\":\"f.m\",\"op\":\"exists\"}},\"reason\":\"test.skip\"}";
  auto artifact = run(bundle_with_rules("[" + rule + "," + allow_rule("r.allow", 10, kAlways) + "]"),
                      fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Allow);
  FPE_CHECK(artifact.value().failed_open);
  FPE_CHECK_EQ(artifact.value().failed_open_rules.size(), std::size_t{1});
  const fpe::RuleOutcome* skipped_rule = rule_of(artifact.value(), "r.skip");
  FPE_REQUIRE(skipped_rule != nullptr);
  FPE_CHECK_EQ(skipped_rule->disposition, RuleDisposition::Skipped);
}

FPE_TEST(engine_unknown_is_preserved_and_never_coerced) {
  // A fact that was never supplied is undetermined, not missing.
  auto unsupplied = run(bundle_with_rules("[" + refuse_rule("r.refuse", 10,
                                                            R"json({"test":{"fact":"f.m","op":"exists"}})json") + "]"),
                        fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(unsupplied.has_value());
  FPE_CHECK_EQ(unsupplied.value().outcome, Outcome::Unknown);
  const fpe::RuleOutcome* unsupplied_rule = rule_of(unsupplied.value(), "r.refuse");
  FPE_REQUIRE(unsupplied_rule != nullptr);
  FPE_CHECK_EQ(unsupplied_rule->cause, AppraisalCause::PrerequisiteNotSupplied);

  // Explicitly unknown.
  auto unknown = run(bundle_with_rules("[" + refuse_rule("r.refuse", 10,
                                                         R"json({"test":{"fact":"f.m","op":"equals","operands":[1]}})json") + "]"),
                     fpe::test::input_document(fpe::test::stateless_fact("f.m", "integer", "unknown")));
  FPE_REQUIRE(unknown.has_value());
  FPE_CHECK_EQ(unknown.value().outcome, Outcome::Unknown);

  // Explicitly missing: exists is false, but a comparison stays unknown.
  auto missing_exists = run(bundle_with_rules("[" + allow_rule("r.allow", 10,
                                                              R"json({"test":{"fact":"f.m","op":"not-exists"}})json") + "]"),
                            fpe::test::input_document(fpe::test::stateless_fact("f.m", "integer", "missing")));
  FPE_REQUIRE(missing_exists.has_value());
  FPE_CHECK_EQ(missing_exists.value().outcome, Outcome::Allow);

  auto missing_compare = run(bundle_with_rules("[" + allow_rule("r.allow", 10,
                                                               R"json({"test":{"fact":"f.m","op":"equals","operands":[1]}})json") + "]"),
                             fpe::test::input_document(fpe::test::stateless_fact("f.m", "integer", "missing")));
  FPE_REQUIRE(missing_compare.has_value());
  FPE_CHECK_EQ(missing_compare.value().outcome, Outcome::Unknown);

  // Explicitly stale.
  auto stale = run(bundle_with_rules("[" + allow_rule("r.allow", 10,
                                                      R"json({"test":{"fact":"f.m","op":"equals","operands":[1]}})json") + "]"),
                   fpe::test::input_document(fpe::test::stateless_fact("f.m", "integer", "stale")));
  FPE_REQUIRE(stale.has_value());
  FPE_CHECK_EQ(stale.value().outcome, Outcome::Unknown);
  const fpe::RuleOutcome* stale_rule = rule_of(stale.value(), "r.allow");
  FPE_REQUIRE(stale_rule != nullptr);
  FPE_CHECK_EQ(stale_rule->cause, AppraisalCause::PrerequisiteStale);
}

FPE_TEST(engine_freshness_decides_observation_validity) {
  const std::string bundle = bundle_with_rules(
      "[" + refuse_rule("r.refuse", 10, R"json({"test":{"fact":"f.n","op":"greater-than","operands":[0]}})json") + "]");
  const std::string fact =
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":5,"
      "\"observed_at\":1000,\"valid_until\":2000}";
  const std::string input = fpe::test::input_document(fact);

  auto inside = run(bundle, input, fpe::TimestampNanos::from_unix_nanos(1500));
  FPE_REQUIRE(inside.has_value());
  FPE_CHECK_EQ(inside.value().outcome, Outcome::Refuse);

  auto at_deadline = run(bundle, input, fpe::TimestampNanos::from_unix_nanos(2000));
  FPE_REQUIRE(at_deadline.has_value());
  FPE_CHECK_EQ(at_deadline.value().outcome, Outcome::Refuse);

  auto after = run(bundle, input, fpe::TimestampNanos::from_unix_nanos(2001));
  FPE_REQUIRE(after.has_value());
  FPE_CHECK_EQ(after.value().outcome, Outcome::Unknown);
  const fpe::RuleOutcome* expired_rule = rule_of(after.value(), "r.refuse");
  FPE_REQUIRE(expired_rule != nullptr);
  FPE_CHECK_EQ(expired_rule->cause, AppraisalCause::PrerequisiteExpired);

  auto no_instant = run(bundle, input);
  FPE_REQUIRE(no_instant.has_value());
  FPE_CHECK_EQ(no_instant.value().outcome, Outcome::Unknown);
  const fpe::RuleOutcome* no_instant_rule = rule_of(no_instant.value(), "r.refuse");
  FPE_REQUIRE(no_instant_rule != nullptr);
  FPE_CHECK_EQ(no_instant_rule->cause, AppraisalCause::PrerequisiteFreshnessUndeterminable);

  // An observation with no declared deadline is fresh whenever it is observed.
  auto open_ended = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 5)));
  FPE_REQUIRE(open_ended.has_value());
  FPE_CHECK_EQ(open_ended.value().outcome, Outcome::Refuse);
}

FPE_TEST(engine_type_conflict_is_unknown_not_false) {
  const std::string bundle = bundle_with_rules(
      "[" + allow_rule("r.allow", 10, R"json({"test":{"fact":"f.n","op":"equals","operands":[1]}})json") + "]");
  const std::string mismatched =
      "{\"key\":\"f.n\",\"type\":\"symbol\",\"state\":\"observed\",\"value\":\"one\"}";
  auto artifact = run(bundle, fpe::test::input_document(mismatched));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Unknown);
  const fpe::RuleOutcome* conflicted_rule = rule_of(artifact.value(), "r.allow");
  FPE_REQUIRE(conflicted_rule != nullptr);
  FPE_CHECK_EQ(conflicted_rule->cause, AppraisalCause::PrerequisiteTypeConflict);
}

FPE_TEST(engine_quantity_comparison_requires_matching_units) {
  const std::string bundle =
      "{\"schema\":1,\"bundle\":\"engine.units\",\"revision\":1,\"facts\":[{\"key\":\"f.temp\",\"type\":\"quantity\"}],"
      "\"rules\":[{\"id\":\"r.hot\",\"priority\":10,\"effect\":\"refuse\",\"when\":{\"test\":{\"fact\":\"f.temp\","
      "\"op\":\"greater-or-equal\",\"operands\":[{\"magnitude\":35,\"unit\":\"celsius\"}]}},\"reason\":\"test.hot\"}]}";

  const std::string celsius =
      "{\"key\":\"f.temp\",\"type\":\"quantity\",\"state\":\"observed\",\"value\":{\"magnitude\":38,\"unit\":\"celsius\"}}";
  auto matching = run(bundle, fpe::test::input_document(celsius));
  FPE_REQUIRE(matching.has_value());
  FPE_CHECK_EQ(matching.value().outcome, Outcome::Refuse);

  const std::string fahrenheit =
      "{\"key\":\"f.temp\",\"type\":\"quantity\",\"state\":\"observed\",\"value\":{\"magnitude\":100,\"unit\":\"fahrenheit\"}}";
  auto mismatched = run(bundle, fpe::test::input_document(fahrenheit));
  FPE_REQUIRE(mismatched.has_value());
  FPE_CHECK_EQ(mismatched.value().outcome, Outcome::Unknown);
}

FPE_TEST(engine_defer_is_reported_and_never_becomes_allow) {
  const std::string defer_rule =
      "{\"id\":\"r.defer\",\"priority\":10,\"effect\":\"defer\",\"when\":{\"all\":[]},\"reason\":\"test.defer\"}";
  auto artifact = run(bundle_with_rules("[" + defer_rule + "]"),
                      fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Defer);
  FPE_CHECK_EQ(artifact.value().deferred_rules.size(), std::size_t{1});
  FPE_CHECK(artifact.value().allowed_rules.empty());
}

FPE_TEST(engine_refusal_outranks_defer_at_the_same_priority) {
  const std::string defer_rule =
      "{\"id\":\"r.defer\",\"priority\":10,\"effect\":\"defer\",\"when\":{\"all\":[]},\"reason\":\"test.defer\"}";
  auto artifact = run(bundle_with_rules("[" + defer_rule + "," + refuse_rule("r.refuse", 10, kAlways) + "]"),
                      fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Refuse);
}

FPE_TEST(engine_obligations_are_unioned_from_the_deciding_permission_rules) {
  const std::string first =
      "{\"id\":\"r.a\",\"priority\":10,\"effect\":\"allow\",\"when\":{\"all\":[]},\"obligations\":[\"notify.tenant\"],\"reason\":\"x\"}";
  const std::string second =
      "{\"id\":\"r.b\",\"priority\":10,\"effect\":\"allow\",\"when\":{\"all\":[]},\"obligations\":[\"audit.write\",\"notify.tenant\"],\"reason\":\"y\"}";
  auto artifact = run(bundle_with_rules("[" + first + "," + second + "]"),
                      fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Allow);
  FPE_REQUIRE(artifact.value().obligations.size() == 2);
  FPE_CHECK_EQ(artifact.value().obligations[0].str(), std::string("audit.write"));
  FPE_CHECK_EQ(artifact.value().obligations[1].str(), std::string("notify.tenant"));
}

FPE_TEST(engine_required_fact_prevents_a_grant) {
  const std::string bundle =
      "{\"schema\":1,\"bundle\":\"engine.required\",\"revision\":1,\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\",\"required\":true}],"
      "\"rules\":[{\"id\":\"r.allow\",\"priority\":10,\"effect\":\"allow\",\"when\":{\"all\":[]},\"reason\":\"x\"}]}";
  auto artifact = run(bundle, fpe::test::input_document(""));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, Outcome::Unknown);
  FPE_CHECK_EQ(artifact.value().unresolved_requirements.size(), std::size_t{1});

  // A refusal stands even when a required input is unresolved.
  const std::string refusing =
      "{\"schema\":1,\"bundle\":\"engine.required\",\"revision\":1,\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\",\"required\":true}],"
      "\"rules\":[{\"id\":\"r.refuse\",\"priority\":10,\"effect\":\"refuse\",\"when\":{\"all\":[]},\"reason\":\"x\"}]}";
  auto refused = run(refusing, fpe::test::input_document(""));
  FPE_REQUIRE(refused.has_value());
  FPE_CHECK_EQ(refused.value().outcome, Outcome::Refuse);
}

FPE_TEST(engine_outcome_is_invariant_under_rule_permutation) {
  fpe::test::Random random(fpe::test::global_seed() ^ 0x51u);
  const std::string rules[] = {
      allow_rule("r.a", 30, kAlways),
      refuse_rule("r.b", 20, R"json({"test":{"fact":"f.n","op":"greater-than","operands":[3]}})json"),
      allow_rule("r.c", 20, R"json({"test":{"fact":"f.n","op":"less-than","operands":[9]}})json"),
      refuse_rule("r.d", 40, kNever),
      "{\"id\":\"r.e\",\"priority\":35,\"effect\":\"defer\",\"when\":{\"all\":[]},\"reason\":\"test.defer\"}"};
  const std::size_t rule_count = sizeof(rules) / sizeof(rules[0]);

  const std::string input = fpe::test::input_document(fpe::test::observed_integer("f.n", 5));
  auto baseline = run(bundle_with_rules("[" + rules[0] + "," + rules[1] + "," + rules[2] + "," + rules[3] + "," +
                                        rules[4] + "]"),
                      input);
  FPE_REQUIRE(baseline.has_value());

  std::vector<std::size_t> order(rule_count);
  for (std::size_t i = 0; i < rule_count; ++i) {
    order[i] = i;
  }
  for (int trial = 0; trial < 24; ++trial) {
    for (std::size_t i = rule_count; i > 1; --i) {
      const std::size_t j = random.index(i);
      std::swap(order[i - 1], order[j]);
    }
    std::string joined;
    for (std::size_t i = 0; i < rule_count; ++i) {
      if (i > 0) {
        joined.push_back(',');
      }
      joined.append(rules[order[i]]);
    }
    auto permuted = run(bundle_with_rules("[" + joined + "]"), input);
    FPE_REQUIRE(permuted.has_value());
    FPE_CHECK_EQ(permuted.value().outcome, baseline.value().outcome);
    FPE_CHECK_EQ(permuted.value().bundle_digest, baseline.value().bundle_digest);
  }
}

FPE_TEST(engine_evaluation_step_bound_is_enforced) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "]");
  const std::string input = fpe::test::input_document(fpe::test::observed_integer("f.n", 1));

  // One step covers the rule itself, so a bound of one leaves nothing for the
  // condition: the breach is reported and no artifact is produced.
  Limits one_step = Limits::defaults();
  one_step.max_evaluation_steps = 1;
  auto breached = run(bundle, input, std::nullopt, one_step);
  FPE_CHECK(!breached.has_value());
  FPE_CHECK_EQ(breached.status().code(), ErrorCode::EvaluationLimitReached);

  // The bound covers the condition tree, not only the rule list, so a wide or
  // deep condition cannot be used to make evaluation cost unbounded.
  const std::string nested =
      bundle_with_rules("[" + allow_rule("r.allow", 10,
                                         R"json({"all":[{"all":[{"all":[{"test":{"fact":"f.n","op":"exists"}}]}]}]})json") +
                        "]");
  Limits shallow = Limits::defaults();
  shallow.max_evaluation_steps = 4;
  auto deep = run(nested, input, std::nullopt, shallow);
  FPE_CHECK(!deep.has_value());
  FPE_CHECK_EQ(deep.status().code(), ErrorCode::EvaluationLimitReached);

  // The same policy inside a generous bound evaluates normally, which shows the
  // bound, and not the policy, is what changed.
  auto generous = run(nested, input);
  FPE_REQUIRE(generous.has_value());
  FPE_CHECK_EQ(generous.value().outcome, Outcome::Allow);
}

FPE_TEST(engine_artifact_binds_policy_inputs_and_authorities) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "]");
  const std::string fact =
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":1,"
      "\"authority\":\"capacity-fabric\",\"generation\":7,"
      "\"evidence\":\"3333333333333333333333333333333333333333333333333333333333333333\"}";
  auto artifact = run(bundle, fpe::test::input_document(fact));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK(!artifact.value().bundle_digest.is_zero());
  FPE_CHECK(!artifact.value().input_digest.is_zero());
  FPE_REQUIRE(artifact.value().authorities.size() == 1);
  FPE_CHECK_EQ(artifact.value().authorities[0].authority.str(), std::string("capacity-fabric"));
  FPE_CHECK_EQ(artifact.value().authorities[0].generation.raw(), std::uint64_t{7});
  FPE_CHECK(!artifact.value().policy_generation.has_value());
  FPE_CHECK(!artifact.value().control_epoch.has_value());
  FPE_CHECK(fpe::verify_artifact(artifact.value()).ok());
}

FPE_TEST(engine_explanation_is_bounded_and_attributable) {
  const std::string bundle = bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "," +
                                               refuse_rule("r.refuse", 5, kNever) + "]");
  auto artifact = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK(!artifact.value().explanation.empty());
  FPE_CHECK(!artifact.value().explanation_truncated);
  for (const std::string& line : artifact.value().explanation) {
    FPE_CHECK(line.size() <= Limits::defaults().max_text_bytes);
  }

  Limits tiny = Limits::defaults();
  tiny.max_explanation_entries = 1;
  auto bounded = run(bundle, fpe::test::input_document(fpe::test::observed_integer("f.n", 1)), std::nullopt,
                     tiny);
  FPE_REQUIRE(bounded.has_value());
  FPE_CHECK(bounded.value().explanation_truncated);
  FPE_CHECK_EQ(bounded.value().explanation.size(), std::size_t{1});
}

FPE_TEST(engine_appraisal_reports_every_declared_fact) {
  const std::string bundle =
      "{\"schema\":1,\"bundle\":\"engine.appraise\",\"revision\":1,\"facts\":["
      "{\"key\":\"f.a\",\"type\":\"integer\"},{\"key\":\"f.b\",\"type\":\"integer\"},{\"key\":\"f.c\",\"type\":\"integer\"}],"
      "\"rules\":[]}";
  auto compiled = fpe::test::compile_json(bundle);
  FPE_REQUIRE(compiled.has_value());
  const std::string facts = fpe::test::observed_integer("f.a", 1) + "," +
                            fpe::test::stateless_fact("f.b", "integer", "unknown");
  auto inputs = fpe::test::inputs_from_json(fpe::test::input_document(facts));
  FPE_REQUIRE(inputs.has_value());

  fpe::EvaluationOptions options;
  auto appraisals = fpe::appraise_inputs(compiled.value(), inputs.value(), options);
  FPE_REQUIRE(appraisals.has_value());
  FPE_REQUIRE(appraisals.value().size() == 3);
  FPE_CHECK_EQ(appraisals.value()[0].cause, AppraisalCause::None);
  FPE_CHECK_EQ(appraisals.value()[0].freshness, fpe::Freshness::Fresh);
  FPE_CHECK_EQ(appraisals.value()[1].cause, AppraisalCause::PrerequisiteUnknown);
  FPE_CHECK_EQ(appraisals.value()[2].cause, AppraisalCause::PrerequisiteNotSupplied);
}

FPE_TEST(engine_rejects_a_binding_with_only_one_of_generation_and_epoch) {
  auto compiled = fpe::test::compile_json(bundle_with_rules("[" + allow_rule("r.allow", 10, kAlways) + "]"));
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(fpe::test::input_document(fpe::test::observed_integer("f.n", 1)));
  FPE_REQUIRE(inputs.has_value());

  fpe::EvaluationOptions options;
  options.binding.generation = fpe::Generation::from_raw(3);
  auto artifact = fpe::evaluate(compiled.value(), inputs.value(), options);
  FPE_CHECK(!artifact.has_value());
  FPE_CHECK_EQ(artifact.status().code(), ErrorCode::InvalidState);
}
