// A downstream facility-policy gate.
//
// It exercises the installed public API the way an adjacent runtime would: it
// loads a published policy generation from a durable store, evaluates typed
// authoritative facts, binds a decision to the policy generation and control
// epoch, and fences that decision against the policy state it trusts. It links
// only FacilityPolicyEngine::fpe and includes only installed headers.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "fpe/decision.hpp"
#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/policy.hpp"
#include "fpe/runtime.hpp"
#include "fpe/store.hpp"
#include "fpe/version.hpp"

namespace {

constexpr const char* kPolicy =
    R"json({"schema":1,"bundle":"gate.bundle","revision":1,"scope":"site.alpha","default_outcome":"refuse","facts":[{"key":"zone.temperature","type":"quantity","authority":"thermal-control"},{"key":"tenant.class","type":"symbol","authority":"tenant-registry"}],"predicates":[{"id":"zone.hot","body":{"test":{"fact":"zone.temperature","op":"greater-or-equal","operands":[{"magnitude":32,"unit":"celsius"}]}}}],"rules":[{"id":"refuse.hot","priority":100,"effect":"refuse","when":{"named":"zone.hot"},"prerequisites":["zone.temperature"],"reason":"thermal.zone-too-hot"},{"id":"allow.standard","priority":50,"effect":"allow","when":{"test":{"fact":"tenant.class","op":"in-set","operands":["tenant.standard","tenant.gold"]}},"obligations":["notify.tenant"],"reason":"tenancy.standard-occupant"}]})json";

/// Builds an input document. When \p tenant_unknown is set, the tenant class is
/// delivered as an unreadable fact rather than as a value the policy does not
/// list, which is the difference between "not permitted by this rule" and "not
/// established at all".
std::string facts_document(int temperature, const char* tenant, bool tenant_unknown) {
  const std::string tenant_fact =
      tenant_unknown
          ? std::string("{\"key\":\"tenant.class\",\"type\":\"symbol\",\"state\":\"unknown\","
                        "\"authority\":\"tenant-registry\",\"generation\":3,"
                        "\"evidence\":\"5555555555555555555555555555555555555555555555555555555555555555\"}")
          : std::string("{\"key\":\"tenant.class\",\"type\":\"symbol\",\"state\":\"observed\","
                        "\"value\":\"") +
                tenant +
                "\",\"authority\":\"tenant-registry\",\"generation\":3,"
                "\"evidence\":\"5555555555555555555555555555555555555555555555555555555555555555\"}";
  return std::string("{\"schema\":1,\"facts\":["
                     "{\"key\":\"zone.temperature\",\"type\":\"quantity\",\"state\":\"observed\","
                     "\"value\":{\"magnitude\":") +
         std::to_string(temperature) +
         ",\"unit\":\"celsius\"},\"authority\":\"thermal-control\",\"generation\":11,"
         "\"evidence\":\"4444444444444444444444444444444444444444444444444444444444444444\"}," +
         tenant_fact + "]}";
}

int fail(const std::string& message, const fpe::Status& status) {
  std::cerr << "facility_policy_gate: " << message << ": " << status.to_string() << "\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: facility_policy_gate <allow|refuse|unknown|stale>\n";
    return 2;
  }
  const std::string mode = argv[1];
  const fpe::Limits limits = fpe::Limits::defaults();

  std::error_code error;
  const std::filesystem::path root = std::filesystem::temp_directory_path(error) / "facility-policy-gate";
  if (error) {
    std::cerr << "facility_policy_gate: no temporary directory available\n";
    return 2;
  }
  std::filesystem::remove_all(root, error);

  auto created = fpe::create_store(root, limits);
  if (!created) {
    return fail("cannot create a store", created.status());
  }

  auto document = fpe::parse_json(kPolicy, limits);
  if (!document) {
    return fail("cannot parse the policy document", document.status());
  }
  auto bundle = fpe::bundle_from_json(document.value(), limits);
  if (!bundle) {
    return fail("cannot read the policy bundle", bundle.status());
  }
  auto compiled = fpe::compile_standalone_bundle(std::move(bundle).value(), limits);
  if (!compiled) {
    return fail("cannot compile the policy bundle", compiled.status());
  }

  auto writer = fpe::open_writer(root, limits);
  if (!writer) {
    return fail("cannot open the store for writing", writer.status());
  }
  auto generation = writer.value().publish(compiled.value());
  if (!generation) {
    return fail("cannot publish the policy", generation.status());
  }
  writer.value().close();

  auto runtime = fpe::PolicyRuntime::open(root, limits);
  if (!runtime) {
    return fail("cannot open the published policy", runtime.status());
  }

  int temperature = 20;
  const char* tenant = "tenant.standard";
  bool tenant_unknown = false;
  if (mode == "refuse") {
    temperature = 40;
  } else if (mode == "unknown") {
    // The tenant class is not established, so the permission rule cannot decide
    // and nothing may be granted.
    tenant_unknown = true;
  } else if (mode != "allow" && mode != "stale") {
    std::cerr << "facility_policy_gate: unrecognized mode '" << mode << "'\n";
    return 2;
  }

  auto inputs = fpe::input_set_from_json(
      fpe::parse_json(facts_document(temperature, tenant, tenant_unknown), limits).value(), limits);
  if (!inputs) {
    return fail("cannot build the input set", inputs.status());
  }

  fpe::EvaluationOptions options;
  options.limits = limits;
  options.as_of = fpe::TimestampNanos::from_unix_nanos(1000);

  auto artifact = runtime.value().decide(inputs.value(), options);
  if (!artifact) {
    return fail("cannot evaluate the policy", artifact.status());
  }

  std::printf("policy %s revision %llu generation %llu epoch %llu\n",
              artifact.value().bundle.str().c_str(),
              static_cast<unsigned long long>(artifact.value().bundle_revision.raw()),
              static_cast<unsigned long long>(artifact.value().policy_generation->raw()),
              static_cast<unsigned long long>(artifact.value().control_epoch->raw()));
  std::printf("policy digest %s\n", artifact.value().bundle_digest.to_hex().c_str());
  std::printf("input digest  %s\n", artifact.value().input_digest.to_hex().c_str());
  std::printf("artifact      %s\n", artifact.value().artifact_digest.to_hex().c_str());
  std::printf("outcome       %s\n", std::string(fpe::outcome_name(artifact.value().outcome)).c_str());
  for (const auto& line : artifact.value().explanation) {
    std::printf("  %s\n", line.c_str());
  }

  if (mode == "stale") {
    // Publish a second generation and show that the earlier decision is fenced
    // rather than silently inherited.
    const std::string revised = std::string(kPolicy).replace(
        std::string(kPolicy).find("\"revision\":1"), std::strlen("\"revision\":1"), "\"revision\":2");
    auto second_document = fpe::parse_json(revised, limits);
    if (!second_document) {
      return fail("cannot parse the revised policy", second_document.status());
    }
    auto second_bundle = fpe::bundle_from_json(second_document.value(), limits);
    if (!second_bundle) {
      return fail("cannot read the revised policy", second_bundle.status());
    }
    auto second = fpe::compile_standalone_bundle(std::move(second_bundle).value(), limits);
    if (!second) {
      return fail("cannot compile the revised policy", second.status());
    }
    auto second_writer = fpe::open_writer(root, limits);
    if (!second_writer) {
      return fail("cannot reopen the store", second_writer.status());
    }
    auto published = second_writer.value().publish(second.value());
    if (!published) {
      return fail("cannot publish the revised policy", published.status());
    }
    second_writer.value().close();

    auto reloaded = runtime.value().reload();
    if (!reloaded) {
      return fail("cannot reload the policy", reloaded.status());
    }
    auto fence = runtime.value().fence(artifact.value());
    if (!fence) {
      return fail("cannot fence the decision", fence.status());
    }
    std::printf("fence         %s\n", std::string(fpe::fence_status_name(fence.value().status)).c_str());
    std::printf("fence detail  %s\n", fence.value().detail.c_str());
    std::filesystem::remove_all(root, error);
    return fence.value().is_current() ? 1 : 0;
  }

  const fpe::Outcome expected = mode == "allow"   ? fpe::Outcome::Allow
                                : mode == "refuse" ? fpe::Outcome::Refuse
                                                   : fpe::Outcome::Unknown;
  std::filesystem::remove_all(root, error);
  if (artifact.value().outcome != expected) {
    std::cerr << "facility_policy_gate: expected a different outcome for mode " << mode << "\n";
    return 1;
  }
  return 0;
}
