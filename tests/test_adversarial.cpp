#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/policy.hpp"
#include "fpe/store.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::ErrorCode;
using fpe::Limits;
using fpe::Status;

namespace {

constexpr std::string_view kGoodPolicy =
    R"json({"schema":1,"bundle":"adv.bundle","revision":1,"facts":[{"key":"f.n","type":"integer"}],"rules":[{"id":"r.a","priority":1,"effect":"refuse","when":{"test":{"fact":"f.n","op":"equals","operands":[1]}},"reason":"adv.refuse"}]})json";

std::string bundle_text(std::string_view body) {
  return "{\"schema\":1,\"bundle\":\"adv.bundle\",\"revision\":1," + std::string(body) + "}";
}

}  // namespace

FPE_TEST(adversarial_impossible_enum_values_are_refused) {
  const auto rejected = [](const std::string& text) {
    auto compiled = fpe::test::compile_json(text);
    FPE_CHECK(!compiled.has_value());
  };
  rejected(bundle_text("\"default_outcome\":\"permit\",\"rules\":[]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"quaternion\"}],\"rules\":[]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"permit\",\"reason\":\"x\"}]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"on_unknown\":\"maybe\",\"reason\":\"x\"}]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":{\"test\":{\"fact\":\"f.n\",\"op\":\"approximately\",\"operands\":[1]}},\"reason\":\"x\"}]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":{\"sometimes\":[]},\"reason\":\"x\"}]"));
  rejected(bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":{\"all\":[],\"any\":[]},\"reason\":\"x\"}]"));
}

FPE_TEST(adversarial_absurd_declared_sizes_are_refused_before_use) {
  // A rule list longer than the configured maximum is refused, and the refusal
  // names the bound rather than failing during evaluation.
  Limits limits = Limits::defaults();
  limits.max_rules = 3;
  std::string rules;
  for (int i = 0; i < 4; ++i) {
    if (i > 0) {
      rules.push_back(',');
    }
    rules += "{\"id\":\"r." + std::to_string(i) + "\",\"priority\":1,\"effect\":\"allow\",\"reason\":\"x\"}";
  }
  auto too_many = fpe::test::compile_json(bundle_text("\"rules\":[" + rules + "]"), limits);
  FPE_CHECK(!too_many.has_value());
  FPE_CHECK_EQ(too_many.status().code(), ErrorCode::LimitExceeded);

  // A symbol set above the collection bound is refused by the input builder.
  Limits small = Limits::defaults();
  small.max_collection_items = 2;
  const std::string wide_set =
      "{\"key\":\"f.set\",\"type\":\"symbol-set\",\"state\":\"observed\",\"value\":[\"a\",\"b\",\"c\"]}";
  auto inputs = fpe::test::inputs_from_json(fpe::test::input_document(wide_set), small);
  FPE_CHECK(!inputs.has_value());
  FPE_CHECK_EQ(inputs.status().code(), ErrorCode::LimitExceeded);

  // Limits above the hard caps are refused, so no caller can raise them.
  Limits raised = Limits::defaults();
  raised.max_rules = fpe::HardCaps::kRules + 1;
  FPE_CHECK(!fpe::validate_limits(raised).ok());
  FPE_CHECK_EQ(fpe::validate_limits(raised).code(), ErrorCode::LimitExceeded);
  // And the caps themselves are accepted.
  FPE_CHECK(fpe::validate_limits(Limits::hard_caps()).ok());
}

FPE_TEST(adversarial_integer_boundaries_never_wrap) {
  FPE_CHECK(fpe::test::compile_json(bundle_text(
                "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":2147483647,\"effect\":\"allow\",\"reason\":\"x\"}]"))
                .has_value());
  FPE_CHECK(fpe::test::compile_json(bundle_text(
                "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":-2147483648,\"effect\":\"allow\",\"reason\":\"x\"}]"))
                .has_value());
  FPE_CHECK(!fpe::test::compile_json(bundle_text(
                 "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":2147483648,\"effect\":\"allow\",\"reason\":\"x\"}]"))
                 .has_value());
  FPE_CHECK(!fpe::test::compile_json(bundle_text(
                 "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":-2147483649,\"effect\":\"allow\",\"reason\":\"x\"}]"))
                 .has_value());
  FPE_CHECK(!fpe::test::compile_json(bundle_text(
                 "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"reason\":\"x\"}],\"revision\":-1}"))
                 .has_value());

  // A revision above the signed 64-bit range cannot even be written as JSON.
  FPE_CHECK(!fpe::test::compile_json(
                 bundle_text("\"facts\":[],\"rules\":[],\"revision\":9223372036854775808"))
                 .has_value());

  const std::string extreme = fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":9223372036854775807}");
  auto inputs = fpe::test::inputs_from_json(extreme);
  FPE_REQUIRE(inputs.has_value());
  FPE_CHECK(inputs.value().find(fpe::FactKey::parse("f.n", 128).value()) != nullptr);
}

FPE_TEST(adversarial_malformed_digests_are_refused) {
  const std::string short_digest = bundle_text(
      "\"imports\":[{\"bundle\":\"other\",\"digest\":\"abcd\"}],\"rules\":[]");
  auto compiled = fpe::test::compile_json(short_digest);
  FPE_CHECK(!compiled.has_value());

  const std::string non_hex = bundle_text(
      "\"imports\":[{\"bundle\":\"other\",\"digest\":\"" + std::string(64, 'z') + "\"}],\"rules\":[]");
  FPE_CHECK(!fpe::test::compile_json(non_hex).has_value());

  const std::string wrong_length = bundle_text(
      "\"imports\":[{\"bundle\":\"other\",\"digest\":\"" + std::string(63, 'a') + "\"}],\"rules\":[]");
  FPE_CHECK(!fpe::test::compile_json(wrong_length).has_value());
}

FPE_TEST(adversarial_duplicate_identities_across_every_collection) {
  FPE_CHECK(!fpe::test::compile_json(bundle_text(
                 "\"predicates\":[{\"id\":\"p.a\",\"body\":{\"all\":[]}},{\"id\":\"p.a\",\"body\":{\"all\":[]}}],\"rules\":[]"))
                 .has_value());
  FPE_CHECK(!fpe::test::compile_json(bundle_text(
                 "\"imports\":[{\"bundle\":\"x\",\"digest\":\"" + std::string(64, 'a') +
                 "\"},{\"bundle\":\"x\",\"digest\":\"" + std::string(64, 'b') + "\"}],\"rules\":[]"))
                 .has_value());
}

FPE_TEST(adversarial_input_documents_are_validated_at_every_boundary) {
  const auto rejected = [](const std::string& document) {
    auto inputs = fpe::test::inputs_from_json(document);
    FPE_CHECK(!inputs.has_value());
  };

  // A value on a fact that is not observed must not be accepted.
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"unknown\",\"value\":1}"));
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"stale\",\"value\":1}"));
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"missing\",\"value\":1}"));
  // An observed fact must carry a value and a type.
  rejected(fpe::test::input_document("{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\"}"));
  rejected(fpe::test::input_document("{\"key\":\"f.n\",\"state\":\"observed\",\"value\":1}"));
  // Declared type must match the value.
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":\"one\"}"));
  // Provenance must be complete or absent.
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":1,\"authority\":\"a\"}"));
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":1,\"generation\":1}"));
  // Impossible ordering of the observation window.
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":1,\"observed_at\":200,\"valid_until\":100}"));
  // Duplicate keys.
  rejected(fpe::test::input_document(fpe::test::observed_integer("f.n", 1) + "," +
                                     fpe::test::observed_integer("f.n", 2)));
  // Unknown fields.
  rejected("{\"schema\":1,\"facts\":[],\"surprise\":1}");
  // Impossible states and types.
  rejected(fpe::test::input_document("{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"maybe\"}"));
  rejected(fpe::test::input_document("{\"key\":\"f.n\",\"type\":\"quantum\",\"state\":\"observed\",\"value\":1}"));
  // A zero evidence digest is reserved and must not be accepted.
  rejected(fpe::test::input_document(
      "{\"key\":\"f.n\",\"type\":\"integer\",\"state\":\"observed\",\"value\":1,\"authority\":\"a\",\"generation\":1,\"evidence\":\"" +
      std::string(64, '0') + "\"}"));
}

FPE_TEST(adversarial_hostile_identifiers_and_text_never_reach_the_model) {
  for (const std::string_view key : {"../../etc/passwd", "CON", "a\\b", "..", "with space", "nul.txt"}) {
    const std::string document = "{\"schema\":1,\"bundle\":\"adv.bundle\",\"revision\":1,\"facts\":[{\"key\":\"" +
                                 std::string(key) + "\",\"type\":\"integer\"}],\"rules\":[]}";
    FPE_CHECK(!fpe::test::compile_json(document).has_value());
  }

  const std::string long_key(5000, 'k');
  FPE_CHECK(!fpe::test::compile_json(bundle_text("\"facts\":[{\"key\":\"" + long_key +
                                                 "\",\"type\":\"integer\"}],\"rules\":[]"))
                 .has_value());

  const std::string description =
      bundle_text("\"facts\":[],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"reason\":\"x\","
                  "\"description\":\"line\nbreak\"}]");
  FPE_CHECK(!fpe::test::compile_json(description).has_value());
}

FPE_TEST(adversarial_deeply_nested_conditions_do_not_exhaust_the_stack) {
  // The document parser bounds nesting before the condition validator ever sees
  // it, so a hostile depth is refused cheaply.
  std::string document = "{\"schema\":1,\"bundle\":\"adv.bundle\",\"revision\":1,\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":";
  const int depth = 400;
  for (int i = 0; i < depth; ++i) {
    document += "{\"not\":";
  }
  document += "{\"test\":{\"fact\":\"f.n\",\"op\":\"exists\"}}";
  for (int i = 0; i < depth; ++i) {
    document += "}";
  }
  document += ",\"reason\":\"x\"}]}";

  auto compiled = fpe::test::compile_json(document);
  FPE_CHECK(!compiled.has_value());
  FPE_CHECK(compiled.status().code() == ErrorCode::JsonDepthExceeded ||
            compiled.status().code() == ErrorCode::LimitExceeded);
}

FPE_TEST(adversarial_store_refuses_bytes_that_are_not_a_manifest) {
  auto directory = fpe::test::TempDirectory::create("adv-store");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  const std::filesystem::path manifest =
      directory.value().path() / std::filesystem::path(fpe::StoreFormat::kManifestName);

  const std::vector<std::string> replacements = {
      std::string(),                                    // empty file
      std::string(fpe::StoreFormat::kManifestBytes, '\0'),   // all zeroes
      "FPEMANI1",                                       // magic only
      std::string(fpe::StoreFormat::kManifestBytes, 'x'),    // garbage of the right size
  };
  for (const std::string& replacement : replacements) {
    std::ofstream stream(manifest, std::ios::binary | std::ios::trunc);
    stream.write(replacement.data(), static_cast<std::streamsize>(replacement.size()));
    stream.flush();
    stream.close();
    auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
    FPE_CHECK(!reader.has_value());
  }
}

FPE_TEST(adversarial_engine_never_returns_allow_for_an_unknown_heavy_policy) {
  // Twelve rules, all refusing, every one undecided because the fact they need
  // was never supplied: the engine must not grant anything.
  std::string rules;
  for (int i = 0; i < 12; ++i) {
    if (i > 0) {
      rules.push_back(',');
    }
    rules += "{\"id\":\"r." + std::to_string(i) +
             "\",\"priority\":" + std::to_string(i) +
             ",\"effect\":\"refuse\",\"when\":{\"test\":{\"fact\":\"f.n\",\"op\":\"equals\",\"operands\":[" +
             std::to_string(i) + "]}},\"reason\":\"adv.refuse\"}";
  }
  const std::string policy = bundle_text(
      "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[" + rules + "]");
  auto compiled = fpe::test::compile_json(policy);
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(fpe::test::input_document(""));
  FPE_REQUIRE(inputs.has_value());
  auto artifact = fpe::evaluate(compiled.value(), inputs.value(), fpe::EvaluationOptions{});
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, fpe::Outcome::Unknown);
  FPE_CHECK(artifact.value().allowed_rules.empty());
  FPE_CHECK_EQ(artifact.value().undecided_rules.size(), std::size_t{12});
}
