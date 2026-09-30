#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/store.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::Limits;

namespace {

constexpr std::string_view kPolicy =
    R"json({"schema":1,"bundle":"cli.bundle","revision":3,"facts":[{"key":"f.n","type":"integer"}],"rules":[{"id":"r.refuse","priority":10,"effect":"refuse","when":{"test":{"fact":"f.n","op":"greater-than","operands":[10]}},"reason":"cli.refuse"}]})json";

void write_text(const std::filesystem::path& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(text.data(), static_cast<std::streamsize>(text.size()));
  stream.flush();
}

fpe::test::ProcessResult run_cli(const std::filesystem::path& log,
                                 const std::vector<std::string>& arguments) {
  auto result = fpe::test::run_process(fpe::test::cli_executable_path(), arguments, log);
  if (!result) {
    fpe::test::record_failure("cannot run the CLI: " + std::string(result.status().to_string()), __FILE__,
                              __LINE__);
    return fpe::test::ProcessResult{};
  }
  return result.value();
}

}  // namespace

FPE_TEST(cli_reports_version_and_usage) {
  auto directory = fpe::test::TempDirectory::create("cli-version");
  FPE_REQUIRE(directory.has_value());

  const auto version = run_cli(directory.value().child("version.log"), {"--version"});
  FPE_CHECK_EQ(version.exit_code, 0);
  FPE_CHECK(version.output.find("Facility Policy Engine") != std::string::npos);
  FPE_CHECK(version.output.find("1.0.0") != std::string::npos);

  const auto usage = run_cli(directory.value().child("help.log"), {"--help"});
  FPE_CHECK_EQ(usage.exit_code, 0);
  FPE_CHECK(usage.output.find("Exit codes") != std::string::npos);

  const auto unknown = run_cli(directory.value().child("unknown.log"), {"frobnicate"});
  FPE_CHECK_EQ(unknown.exit_code, 1);
  FPE_CHECK(unknown.output.find("unrecognized command") != std::string::npos);
}

FPE_TEST(cli_selftest_passes_from_the_installed_binary) {
  auto directory = fpe::test::TempDirectory::create("cli-selftest");
  FPE_REQUIRE(directory.has_value());
  const auto result = run_cli(directory.value().child("selftest.log"), {"selftest"});
  FPE_CHECK_EQ(result.exit_code, 0);
  FPE_CHECK(result.output.find("selftest passed") != std::string::npos);
  FPE_CHECK(result.output.find("FAIL") == std::string::npos);
}

FPE_TEST(cli_policy_check_and_digest_are_deterministic) {
  auto directory = fpe::test::TempDirectory::create("cli-policy");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path policy = directory.value().child("policy.json");
  write_text(policy, std::string(kPolicy));

  const auto check = run_cli(directory.value().child("check.log"),
                             {"policy", "check", fpe::test::path_text(policy)});
  FPE_CHECK_EQ(check.exit_code, 0);
  FPE_CHECK(check.output.find("cli.bundle") != std::string::npos);

  const auto first = run_cli(directory.value().child("digest1.log"),
                             {"policy", "digest", fpe::test::path_text(policy)});
  const auto second = run_cli(directory.value().child("digest2.log"),
                              {"policy", "digest", fpe::test::path_text(policy)});
  FPE_CHECK_EQ(first.exit_code, 0);
  FPE_CHECK_EQ(first.output, second.output);
  std::string trimmed = first.output;
  while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
    trimmed.pop_back();
  }
  FPE_CHECK_EQ(trimmed.size(), std::size_t{64});

  const std::filesystem::path broken = directory.value().child("broken.json");
  write_text(broken, "{\"schema\":1,\"bundle\":\"cli.bundle\"}");
  const auto failure = run_cli(directory.value().child("broken.log"),
                               {"policy", "check", fpe::test::path_text(broken)});
  FPE_CHECK_EQ(failure.exit_code, 1);
  FPE_CHECK(failure.output.find("missing") != std::string::npos);
}

FPE_TEST(cli_store_lifecycle_and_exit_codes) {
  auto directory = fpe::test::TempDirectory::create("cli-store");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path store = directory.value().child("store");
  const std::filesystem::path policy = directory.value().child("policy.json");
  write_text(policy, std::string(kPolicy));

  const auto created = run_cli(directory.value().child("create.log"),
                               {"store", "create", fpe::test::path_text(store)});
  FPE_CHECK_EQ(created.exit_code, 0);
  FPE_CHECK(created.output.find("generation       0") != std::string::npos);

  const auto published =
      run_cli(directory.value().child("publish.log"),
              {"store", "publish", fpe::test::path_text(store), "--root", "cli.bundle",
               fpe::test::path_text(policy)});
  FPE_CHECK_EQ(published.exit_code, 0);
  FPE_CHECK(published.output.find("generation 1") != std::string::npos);

  const auto shown = run_cli(directory.value().child("show.log"),
                             {"store", "show", fpe::test::path_text(store)});
  FPE_CHECK_EQ(shown.exit_code, 0);
  FPE_CHECK(shown.output.find("cli.bundle") != std::string::npos);

  const auto verified = run_cli(directory.value().child("verify.log"),
                                {"store", "verify", fpe::test::path_text(store)});
  FPE_CHECK_EQ(verified.exit_code, 0);
  FPE_CHECK(verified.output.find("verified 1 generation") != std::string::npos);

  // Above the threshold the policy refuses, and the exit code says so without
  // anyone parsing the output.
  const std::filesystem::path hot = directory.value().child("hot.json");
  write_text(hot, fpe::test::input_document(fpe::test::observed_integer("f.n", 20)));
  const auto refused = run_cli(directory.value().child("hot.log"),
                               {"eval", fpe::test::path_text(store), "--input",
                                fpe::test::path_text(hot), "--json"});
  FPE_CHECK_EQ(refused.exit_code, 2);

  // A decision that cannot be established exits 3.
  const std::filesystem::path empty_facts = directory.value().child("empty.json");
  write_text(empty_facts, fpe::test::input_document(""));
  const auto undetermined = run_cli(directory.value().child("empty.log"),
                                    {"eval", fpe::test::path_text(store), "--input",
                                     fpe::test::path_text(empty_facts)});
  FPE_CHECK_EQ(undetermined.exit_code, 3);

  // Below the threshold the rule does not apply, so the outcome is unknown
  // rather than allow: the bundle declares no default.
  const std::filesystem::path cool = directory.value().child("cool.json");
  write_text(cool, fpe::test::input_document(fpe::test::observed_integer("f.n", 5)));
  const auto cool_result = run_cli(directory.value().child("cool.log"),
                                   {"eval", fpe::test::path_text(store), "--input",
                                    fpe::test::path_text(cool)});
  FPE_CHECK_EQ(cool_result.exit_code, 3);
}

FPE_TEST(cli_eval_json_output_round_trips_through_the_library) {
  auto directory = fpe::test::TempDirectory::create("cli-json");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path store = directory.value().child("store");
  const std::filesystem::path policy = directory.value().child("policy.json");
  write_text(policy, std::string(kPolicy));
  FPE_REQUIRE(run_cli(directory.value().child("c.log"), {"store", "create", fpe::test::path_text(store)})
                  .exit_code == 0);
  FPE_REQUIRE(run_cli(directory.value().child("p.log"),
                      {"store", "publish", fpe::test::path_text(store), "--root", "cli.bundle",
                       fpe::test::path_text(policy)})
                  .exit_code == 0);

  const std::filesystem::path facts = directory.value().child("facts.json");
  write_text(facts, fpe::test::input_document(fpe::test::observed_integer("f.n", 20)));
  const auto result = run_cli(directory.value().child("eval.log"),
                              {"eval", fpe::test::path_text(store), "--input",
                               fpe::test::path_text(facts), "--json"});
  FPE_REQUIRE(result.exit_code == 2);

  // The document the CLI printed must parse back into the same artifact, which
  // proves the command line output is a real decision artifact and not a summary.
  const fpe::Limits limits = Limits::defaults();
  auto document = fpe::parse_json(result.output, limits);
  FPE_REQUIRE(document.has_value());
  auto artifact = fpe::artifact_from_json(document.value(), limits);
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK_EQ(artifact.value().outcome, fpe::Outcome::Refuse);
  FPE_CHECK(fpe::verify_artifact(artifact.value()).ok());

  const std::filesystem::path artifact_path = directory.value().child("artifact.json");
  write_text(artifact_path, result.output);
  const auto verified = run_cli(directory.value().child("verify-artifact.log"),
                                {"decision", "verify", fpe::test::path_text(artifact_path), "--store",
                                 fpe::test::path_text(store)});
  FPE_CHECK_EQ(verified.exit_code, 0);
  FPE_CHECK(verified.output.find("current") != std::string::npos);

  // A decision checked against a store that has moved on is not current.
  const std::filesystem::path other_policy = directory.value().child("other.json");
  write_text(other_policy, std::string(kPolicy).insert(0, "").replace(
                               std::string(kPolicy).find("\"revision\":3"), std::string("\"revision\":3").size(),
                               "\"revision\":4"));
  FPE_REQUIRE(run_cli(directory.value().child("p2.log"),
                      {"store", "publish", fpe::test::path_text(store), "--root", "cli.bundle",
                       fpe::test::path_text(other_policy)})
                  .exit_code == 0);
  const auto stale = run_cli(directory.value().child("stale.log"),
                             {"decision", "verify", fpe::test::path_text(artifact_path), "--store",
                              fpe::test::path_text(store)});
  FPE_CHECK_EQ(stale.exit_code, 2);
  FPE_CHECK(stale.output.find("bundle-changed") != std::string::npos);
}

FPE_TEST(cli_store_anchor_detects_a_rollback) {
  auto directory = fpe::test::TempDirectory::create("cli-anchor");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path store = directory.value().child("store");
  const std::filesystem::path policy = directory.value().child("policy.json");
  const std::filesystem::path anchor = directory.value().child("anchor.json");
  write_text(policy, std::string(kPolicy));

  FPE_REQUIRE(run_cli(directory.value().child("c.log"), {"store", "create", fpe::test::path_text(store)})
                  .exit_code == 0);
  FPE_REQUIRE(run_cli(directory.value().child("p.log"),
                      {"store", "publish", fpe::test::path_text(store), "--root", "cli.bundle",
                       fpe::test::path_text(policy)})
                  .exit_code == 0);

  const auto anchored = run_cli(directory.value().child("a.log"),
                                {"store", "anchor", fpe::test::path_text(store), "--out",
                                 fpe::test::path_text(anchor)});
  FPE_CHECK_EQ(anchored.exit_code, 0);

  const auto checked = run_cli(directory.value().child("v.log"),
                               {"store", "verify", fpe::test::path_text(store), "--anchor",
                                fpe::test::path_text(anchor)});
  FPE_CHECK_EQ(checked.exit_code, 0);

  // Destroy the whole store and recreate it empty: every byte is internally
  // consistent, so only the out-of-band anchor can reveal the rollback.
  std::error_code error;
  std::filesystem::remove_all(store, error);
  FPE_REQUIRE(!error);
  FPE_REQUIRE(run_cli(directory.value().child("c2.log"), {"store", "create", fpe::test::path_text(store)})
                  .exit_code == 0);

  const auto detected = run_cli(directory.value().child("v2.log"),
                                {"store", "verify", fpe::test::path_text(store), "--anchor",
                                 fpe::test::path_text(anchor)});
  FPE_CHECK_EQ(detected.exit_code, 1);
  FPE_CHECK(detected.output.find("digest-binding-mismatch") != std::string::npos ||
            detected.output.find("rollback-detected") != std::string::npos);
}

FPE_TEST(cli_rejects_a_non_canonical_document_when_canonical_form_is_required) {
  auto directory = fpe::test::TempDirectory::create("cli-canonical");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path messy = directory.value().child("messy.json");
  write_text(messy, std::string(kPolicy) + "\n\n");

  const auto accepted = run_cli(directory.value().child("ok.log"),
                                {"policy", "check", fpe::test::path_text(messy)});
  FPE_CHECK_EQ(accepted.exit_code, 0);

  const std::filesystem::path spaced = directory.value().child("spaced.json");
  write_text(spaced, std::string("{ \"schema\" : 1 , \"bundle\" : \"cli.bundle\" , \"revision\" : 3 , "
                                 "\"facts\" : [ { \"key\" : \"f.n\" , \"type\" : \"integer\" } ] , "
                                 "\"rules\" : [] }"));
  const auto rejected = run_cli(directory.value().child("reject.log"),
                                {"policy", "check", fpe::test::path_text(spaced), "--canonical"});
  FPE_CHECK_EQ(rejected.exit_code, 1);
  FPE_CHECK(rejected.output.find("canonical") != std::string::npos);
}

FPE_TEST(cli_appraise_reports_every_declared_fact) {
  auto directory = fpe::test::TempDirectory::create("cli-appraise");
  FPE_REQUIRE(directory.has_value());
  const std::filesystem::path store = directory.value().child("store");
  const std::filesystem::path policy = directory.value().child("policy.json");
  write_text(policy, std::string(kPolicy));
  FPE_REQUIRE(run_cli(directory.value().child("c.log"), {"store", "create", fpe::test::path_text(store)})
                  .exit_code == 0);
  FPE_REQUIRE(run_cli(directory.value().child("p.log"),
                      {"store", "publish", fpe::test::path_text(store), "--root", "cli.bundle",
                       fpe::test::path_text(policy)})
                  .exit_code == 0);

  const std::filesystem::path facts = directory.value().child("facts.json");
  write_text(facts, fpe::test::input_document(fpe::test::stateless_fact("f.n", "integer", "unknown")));
  const auto result = run_cli(directory.value().child("appraise.log"),
                              {"appraise", fpe::test::path_text(store), "--input",
                               fpe::test::path_text(facts)});
  FPE_CHECK_EQ(result.exit_code, 0);
  FPE_CHECK(result.output.find("f.n") != std::string::npos);
  FPE_CHECK(result.output.find("prerequisite-unknown") != std::string::npos);
}
