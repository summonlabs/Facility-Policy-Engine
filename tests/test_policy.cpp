#include <string>
#include <string_view>
#include <vector>

#include "fpe/policy.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::ErrorCode;
using fpe::Limits;
using fpe::Status;

namespace {

constexpr std::string_view kMinimalBundle =
    R"json({"schema":1,"bundle":"facility.minimal","revision":1,"facts":[{"key":"zone.temperature","type":"integer"}],"rules":[{"id":"r.one","priority":10,"effect":"allow","when":{"test":{"fact":"zone.temperature","op":"equals","operands":[1]}},"reason":"test.one"}]})json";

/// The same policy written with every list in a different order.
constexpr std::string_view kPermutedBundle =
    R"json({"rules":[{"reason":"test.one","when":{"test":{"operands":[1],"fact":"zone.temperature","op":"equals"}},"effect":"allow","priority":10,"id":"r.one"}],"facts":[{"type":"integer","key":"zone.temperature"}],"revision":1,"schema":1,"bundle":"facility.minimal"})json";

}  // namespace

FPE_TEST(policy_minimal_bundle_compiles_and_reports_identity) {
  auto compiled = fpe::test::compile_json(kMinimalBundle);
  FPE_REQUIRE(compiled.has_value());
  FPE_CHECK_EQ(compiled.value().id().str(), std::string("facility.minimal"));
  FPE_CHECK_EQ(compiled.value().revision().raw(), std::uint64_t{1});
  FPE_CHECK(!compiled.value().digest().is_zero());
  FPE_CHECK(!compiled.value().canonical_bytes().empty());
}

FPE_TEST(policy_digest_is_invariant_under_insertion_order) {
  auto canonical = fpe::test::compile_json(kMinimalBundle);
  auto permuted = fpe::test::compile_json(kPermutedBundle);
  FPE_REQUIRE(canonical.has_value());
  FPE_REQUIRE(permuted.has_value());
  FPE_CHECK(canonical.value().digest() == permuted.value().digest());
  FPE_CHECK_EQ(canonical.value().canonical_bytes(), permuted.value().canonical_bytes());
}

FPE_TEST(policy_digest_changes_when_meaning_changes) {
  auto base = fpe::test::compile_json(kMinimalBundle);
  FPE_REQUIRE(base.has_value());
  const std::string changed_priority =
      std::string(kMinimalBundle).replace(std::string(kMinimalBundle).find("\"priority\":10"),
                                          std::string("\"priority\":10").size(), "\"priority\":11");
  auto modified = fpe::test::compile_json(changed_priority);
  FPE_REQUIRE(modified.has_value());
  FPE_CHECK(!(base.value().digest() == modified.value().digest()));
}

FPE_TEST(policy_canonical_bytes_round_trip_exactly) {
  auto compiled = fpe::test::compile_json(kMinimalBundle);
  FPE_REQUIRE(compiled.has_value());
  auto document = fpe::parse_json(compiled.value().canonical_bytes(), Limits::defaults());
  FPE_REQUIRE(document.has_value());
  auto bundle = fpe::bundle_from_json(document.value(), Limits::defaults());
  FPE_REQUIRE(bundle.has_value());
  auto recompiled = fpe::compile_standalone_bundle(std::move(bundle).value(), Limits::defaults());
  FPE_REQUIRE(recompiled.has_value());
  FPE_CHECK(recompiled.value().digest() == compiled.value().digest());
  FPE_CHECK_EQ(recompiled.value().canonical_bytes(), compiled.value().canonical_bytes());
}

FPE_TEST(policy_duplicate_identities_are_refused) {
  const std::string duplicate_rules = R"json({"schema":1,"bundle":"b","revision":1,"rules":[
    {"id":"r.a","priority":1,"effect":"allow","reason":"x"},
    {"id":"r.a","priority":2,"effect":"refuse","reason":"y"}]})json";
  auto rules = fpe::test::compile_json(duplicate_rules);
  FPE_CHECK(!rules.has_value());
  FPE_CHECK_EQ(rules.status().code(), ErrorCode::DuplicateIdentity);

  const std::string duplicate_facts = R"json({"schema":1,"bundle":"b","revision":1,"facts":[
    {"key":"f.a","type":"integer"},{"key":"f.a","type":"symbol"}]})json";
  auto facts = fpe::test::compile_json(duplicate_facts);
  FPE_CHECK(!facts.has_value());
  FPE_CHECK_EQ(facts.status().code(), ErrorCode::DuplicateIdentity);
}

FPE_TEST(policy_unknown_references_are_refused) {
  const std::string undeclared_fact = R"json({"schema":1,"bundle":"b","revision":1,
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"test":{"fact":"f.missing","op":"exists"}},"reason":"x"}]})json";
  auto fact = fpe::test::compile_json(undeclared_fact);
  FPE_CHECK(!fact.has_value());
  FPE_CHECK_EQ(fact.status().code(), ErrorCode::UnknownReference);

  const std::string undeclared_predicate = R"json({"schema":1,"bundle":"b","revision":1,
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"named":"p.missing"},"reason":"x"}]})json";
  auto predicate = fpe::test::compile_json(undeclared_predicate);
  FPE_CHECK(!predicate.has_value());
  FPE_CHECK_EQ(predicate.status().code(), ErrorCode::UnknownReference);

  const std::string undeclared_prerequisite = R"json({"schema":1,"bundle":"b","revision":1,
    "rules":[{"id":"r.a","priority":1,"effect":"allow","prerequisites":["f.missing"],"reason":"x"}]})json";
  auto prerequisite = fpe::test::compile_json(undeclared_prerequisite);
  FPE_CHECK(!prerequisite.has_value());
  FPE_CHECK_EQ(prerequisite.status().code(), ErrorCode::UnknownReference);
}

FPE_TEST(policy_named_predicate_cycles_are_detected) {
  const std::string direct = R"json({"schema":1,"bundle":"b","revision":1,
    "predicates":[{"id":"p.a","body":{"named":"p.a"}}],
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"named":"p.a"},"reason":"x"}]})json";
  auto self = fpe::test::compile_json(direct);
  FPE_CHECK(!self.has_value());
  FPE_CHECK_EQ(self.status().code(), ErrorCode::CycleDetected);

  const std::string mutual = R"json({"schema":1,"bundle":"b","revision":1,
    "predicates":[{"id":"p.a","body":{"named":"p.b"}},{"id":"p.b","body":{"named":"p.c"}},{"id":"p.c","body":{"named":"p.a"}}],
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"named":"p.a"},"reason":"x"}]})json";
  auto cycle = fpe::test::compile_json(mutual);
  FPE_CHECK(!cycle.has_value());
  FPE_CHECK_EQ(cycle.status().code(), ErrorCode::CycleDetected);
  FPE_CHECK(cycle.status().message().find("p.a") != std::string_view::npos);
}

FPE_TEST(policy_acyclic_predicate_graph_is_accepted) {
  const std::string acyclic = R"json({"schema":1,"bundle":"b","revision":1,"facts":[{"key":"f.a","type":"integer"}],
    "predicates":[{"id":"p.a","body":{"named":"p.b"}},{"id":"p.b","body":{"test":{"fact":"f.a","op":"exists"}}}],
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"named":"p.a"},"reason":"x"}]})json";
  auto compiled = fpe::test::compile_json(acyclic);
  FPE_REQUIRE(compiled.has_value());
  FPE_CHECK_EQ(compiled.value().bundle().predicates.size(), std::size_t{2});
}

FPE_TEST(policy_operand_types_are_checked_against_the_declared_fact_type) {
  const auto with_rule = [](std::string_view fact_type, std::string_view op, std::string_view operands) {
    return std::string("{\"schema\":1,\"bundle\":\"b\",\"revision\":1,\"facts\":[{\"key\":\"f.a\",\"type\":\"") +
           std::string(fact_type) + "\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":{\"test\":{\"fact\":\"f.a\",\"op\":\"" +
           std::string(op) + "\",\"operands\":" + std::string(operands) + "}},\"reason\":\"x\"}]}";
  };

  FPE_CHECK(fpe::test::compile_json(with_rule("integer", "equals", "[1]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("integer", "equals", "[\"one\"]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("integer", "equals", "[]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("integer", "exists", "[1]")).has_value());
  FPE_CHECK(fpe::test::compile_json(with_rule("integer", "exists", "[]")).has_value());
  FPE_CHECK(fpe::test::compile_json(with_rule("integer", "less-than", "[1]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("symbol", "less-than", "[\"a\"]")).has_value());
  FPE_CHECK(fpe::test::compile_json(with_rule("symbol", "in-set", "[\"a\",\"b\"]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("symbol", "in-set", "[]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("symbol-set", "equals", "[\"a\"]")).has_value());
  FPE_CHECK(fpe::test::compile_json(with_rule("symbol-set", "contains-any", "[\"a\"]")).has_value());
  FPE_CHECK(fpe::test::compile_json(with_rule("quantity", "greater-than", "[{\"magnitude\":1,\"unit\":\"kw\"}]"))
                .has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("quantity", "greater-than", "[{\"magnitude\":1}]")).has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("quantity", "greater-than", "[{\"magnitude\":1,\"unit\":\"kw\",\"x\":1}]"))
                 .has_value());
  FPE_CHECK(!fpe::test::compile_json(with_rule("boolean", "equals", "[1]")).has_value());
}

FPE_TEST(policy_bounds_are_enforced_at_compile_time) {
  Limits limits = Limits::defaults();
  limits.max_rules = 2;

  const std::string three_rules = R"json({"schema":1,"bundle":"b","revision":1,"rules":[
    {"id":"r.a","priority":1,"effect":"allow","reason":"x"},
    {"id":"r.b","priority":1,"effect":"allow","reason":"x"},
    {"id":"r.c","priority":1,"effect":"allow","reason":"x"}]})json";
  auto too_many = fpe::test::compile_json(three_rules, limits);
  FPE_CHECK(!too_many.has_value());
  FPE_CHECK_EQ(too_many.status().code(), ErrorCode::LimitExceeded);

  Limits shallow = Limits::defaults();
  shallow.max_condition_depth = 2;
  const std::string deep = R"json({"schema":1,"bundle":"b","revision":1,"facts":[{"key":"f.a","type":"integer"}],
    "rules":[{"id":"r.a","priority":1,"effect":"allow","when":{"all":[{"all":[{"all":[{"test":{"fact":"f.a","op":"exists"}}]}]}]},"reason":"x"}]})json";
  auto too_deep = fpe::test::compile_json(deep, shallow);
  FPE_CHECK(!too_deep.has_value());
  FPE_CHECK_EQ(too_deep.status().code(), ErrorCode::LimitExceeded);

  Limits few_obligations = Limits::defaults();
  few_obligations.max_obligations_per_rule = 1;
  const std::string many = R"json({"schema":1,"bundle":"b","revision":1,"rules":[
    {"id":"r.a","priority":1,"effect":"allow","obligations":["o.one","o.two"],"reason":"x"}]})json";
  auto too_many_obligations = fpe::test::compile_json(many, few_obligations);
  FPE_CHECK(!too_many_obligations.has_value());
  FPE_CHECK_EQ(too_many_obligations.status().code(), ErrorCode::LimitExceeded);
}

FPE_TEST(policy_schema_version_and_unknown_fields_are_refused) {
  auto wrong_schema = fpe::test::compile_json(
      R"json({"schema":2,"bundle":"b","revision":1,"rules":[]})json");
  FPE_CHECK(!wrong_schema.has_value());
  FPE_CHECK_EQ(wrong_schema.status().code(), ErrorCode::UnsupportedVersion);

  auto unknown_field = fpe::test::compile_json(
      R"json({"schema":1,"bundle":"b","revision":1,"rules":[],"surprise":true})json");
  FPE_CHECK(!unknown_field.has_value());
  FPE_CHECK_EQ(unknown_field.status().code(), ErrorCode::JsonUnknownField);

  auto missing_identity = fpe::test::compile_json(R"json({"schema":1,"revision":1,"rules":[]})json");
  FPE_CHECK(!missing_identity.has_value());
  FPE_CHECK_EQ(missing_identity.status().code(), ErrorCode::JsonMissingField);
}

FPE_TEST(policy_obligations_and_prerequisites_are_canonicalised) {
  const std::string messy = R"json({"schema":1,"bundle":"b","revision":1,"facts":[{"key":"f.a","type":"integer"}],
    "rules":[{"id":"r.a","priority":1,"effect":"allow","prerequisites":["f.a","f.a"],"obligations":["o.b","o.a","o.b"],"reason":"x"}]})json";
  auto compiled = fpe::test::compile_json(messy);
  FPE_REQUIRE(compiled.has_value());
  const fpe::Rule& rule = compiled.value().bundle().rules.front();
  FPE_CHECK_EQ(rule.prerequisites.size(), std::size_t{1});
  FPE_REQUIRE(rule.obligations.size() == 2);
  FPE_CHECK_EQ(rule.obligations[0].str(), std::string("o.a"));
  FPE_CHECK_EQ(rule.obligations[1].str(), std::string("o.b"));
}

FPE_TEST(policy_imports_are_resolved_by_exact_digest) {
  const std::string leaf = R"json({"schema":1,"bundle":"leaf","revision":1,"facts":[{"key":"f.shared","type":"integer"}]})json";
  auto leaf_bundle = fpe::test::parse_bundle(leaf);
  FPE_REQUIRE(leaf_bundle.has_value());

  fpe::BundleCompiler compiler(Limits::defaults());
  FPE_REQUIRE(compiler.provide(std::move(leaf_bundle).value()).ok());
  auto compiled_leaf = compiler.compile(fpe::BundleId::parse("leaf", 128).value());
  FPE_REQUIRE(compiled_leaf.has_value());
  const std::string leaf_digest = compiled_leaf.value()->digest().to_hex();

  const std::string root = "{\"schema\":1,\"bundle\":\"root\",\"revision\":1,"
                           "\"imports\":[{\"bundle\":\"leaf\",\"digest\":\"" + leaf_digest + "\"}],"
                           "\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\","
                           "\"when\":{\"test\":{\"fact\":\"f.shared\",\"op\":\"exists\"}},\"reason\":\"x\"}]}";
  auto root_bundle = fpe::test::parse_bundle(root);
  FPE_REQUIRE(root_bundle.has_value());
  FPE_REQUIRE(compiler.provide(std::move(root_bundle).value()).ok());
  auto compiled_root = compiler.compile(fpe::BundleId::parse("root", 128).value());
  FPE_REQUIRE(compiled_root.has_value());
  FPE_CHECK_EQ(compiled_root.value()->imports().size(), std::size_t{1});
  FPE_CHECK_EQ(compiled_root.value()->imports().front()->id().str(), std::string("leaf"));

  // A different digest for the same import identity must be refused.
  const std::string wrong_digest = "{\"schema\":1,\"bundle\":\"root2\",\"revision\":1,"
                                   "\"imports\":[{\"bundle\":\"leaf\",\"digest\":\"" + std::string(64, '9') + "\"}],"
                                   "\"rules\":[]}";
  auto root2 = fpe::test::parse_bundle(wrong_digest);
  FPE_REQUIRE(root2.has_value());
  FPE_REQUIRE(compiler.provide(std::move(root2).value()).ok());
  auto mismatch = compiler.compile(fpe::BundleId::parse("root2", 128).value());
  FPE_CHECK(!mismatch.has_value());
  FPE_CHECK_EQ(mismatch.status().code(), ErrorCode::IncompatibleBundle);
}

FPE_TEST(policy_import_cycles_are_detected) {
  // Each document names the other, so no compilation order can satisfy both.
  const std::string a = R"json({"schema":1,"bundle":"a","revision":1,"imports":[{"bundle":"b","digest":"1111111111111111111111111111111111111111111111111111111111111111"}],"rules":[]})json";
  const std::string b = R"json({"schema":1,"bundle":"b","revision":1,"imports":[{"bundle":"a","digest":"2222222222222222222222222222222222222222222222222222222222222222"}],"rules":[]})json";
  fpe::BundleCompiler compiler(Limits::defaults());
  auto bundle_a = fpe::test::parse_bundle(a);
  auto bundle_b = fpe::test::parse_bundle(b);
  FPE_REQUIRE(bundle_a.has_value());
  FPE_REQUIRE(bundle_b.has_value());
  FPE_REQUIRE(compiler.provide(std::move(bundle_a).value()).ok());
  FPE_REQUIRE(compiler.provide(std::move(bundle_b).value()).ok());
  auto compiled = compiler.compile(fpe::BundleId::parse("a", 128).value());
  FPE_CHECK(!compiled.has_value());
  FPE_CHECK_EQ(compiled.status().code(), ErrorCode::CycleDetected);
}

FPE_TEST(policy_self_import_is_refused) {
  const std::string selfish = R"json({"schema":1,"bundle":"b","revision":1,"imports":[{"bundle":"b","digest":"1111111111111111111111111111111111111111111111111111111111111111"}],"rules":[]})json";
  auto compiled = fpe::test::compile_json(selfish);
  FPE_CHECK(!compiled.has_value());
  FPE_CHECK_EQ(compiled.status().code(), ErrorCode::ImportConflict);
}

FPE_TEST(policy_standalone_compile_refuses_declared_imports) {
  const std::string with_import = R"json({"schema":1,"bundle":"b","revision":1,"imports":[{"bundle":"other","digest":"1111111111111111111111111111111111111111111111111111111111111111"}],"rules":[]})json";
  auto compiled = fpe::test::compile_json(with_import);
  FPE_CHECK(!compiled.has_value());
  FPE_CHECK_EQ(compiled.status().code(), ErrorCode::ImportConflict);
}

FPE_TEST(policy_all_zero_import_digest_is_refused) {
  const std::string zero = R"json({"schema":1,"bundle":"b","revision":1,"imports":[{"bundle":"other","digest":"0000000000000000000000000000000000000000000000000000000000000000"}],"rules":[]})json";
  auto parsed = fpe::test::parse_bundle(zero);
  FPE_CHECK(!parsed.has_value());
  FPE_CHECK_EQ(parsed.status().code(), ErrorCode::PolicySchema);
}
