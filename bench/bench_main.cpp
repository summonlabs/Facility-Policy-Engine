// Facility Policy Engine benchmarks.
//
// Rules this harness follows, because a benchmark that is not honest is worse
// than no benchmark:
//
//   * only completed operations are timed. Nothing here reports submission or
//     enqueue latency as if it were work;
//   * the durable publish benchmark includes the whole durable path: staging,
//     flush, read back and verify, and the atomic manifest replacement. That
//     path is the guarantee, so it is what gets measured;
//   * every line is labelled SYNTHETIC or REAL. SYNTHETIC means the workload was
//     generated in memory by this program. REAL means the work went through the
//     operating system on this host's local file system;
//   * no hardware claim is made. These are single-host, single-process
//     measurements on the machine the harness ran on, and the harness prints
//     that machine's identity rather than implying anything broader.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "fpe/digest.hpp"
#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/policy.hpp"
#include "fpe/runtime.hpp"
#include "fpe/store.hpp"
#include "fpe/version.hpp"

namespace {

std::string host_description() {
  std::string description;
#ifdef _WIN32
  description = "Windows";
#elif defined(__linux__)
  description = "Linux";
#elif defined(__APPLE__)
  description = "macOS";
#else
  description = "unknown platform";
#endif
  description += " ";
  description += sizeof(void*) == 8 ? "64-bit" : "32-bit";
  description += ", hardware concurrency ";
  description += std::to_string(std::thread::hardware_concurrency());
  return description;
}

std::string policy_document(int rules, int facts) {
  std::string facts_json;
  for (int i = 0; i < facts; ++i) {
    if (i > 0) {
      facts_json.push_back(',');
    }
    facts_json += "{\"key\":\"f." + std::to_string(i) + "\",\"type\":\"integer\"}";
  }
  std::string rules_json;
  for (int i = 0; i < rules; ++i) {
    if (i > 0) {
      rules_json.push_back(',');
    }
    rules_json += "{\"id\":\"r." + std::to_string(i) + "\",\"priority\":" + std::to_string(i % 512) +
                  ",\"effect\":\"" + ((i % 3) == 0 ? std::string("refuse") : std::string("allow")) +
                  "\",\"when\":{\"test\":{\"fact\":\"f." + std::to_string(i % facts) +
                  "\",\"op\":\"greater-than\",\"operands\":[" + std::to_string(i % 100) +
                  "]}},\"reason\":\"bench.rule\"}";
  }
  return "{\"schema\":1,\"bundle\":\"bench.bundle\",\"revision\":1,\"facts\":[" + facts_json +
         "],\"rules\":[" + rules_json + "]}";
}

std::string input_document(int facts) {
  std::string facts_json;
  for (int i = 0; i < facts; ++i) {
    if (i > 0) {
      facts_json.push_back(',');
    }
    facts_json += "{\"key\":\"f." + std::to_string(i) + "\",\"type\":\"integer\",\"state\":\"observed\",\"value\":" +
                  std::to_string(i % 100) + "}";
  }
  return "{\"schema\":1,\"facts\":[" + facts_json + "]}";
}

void report(std::string_view provenance, std::string_view name, double operations, double seconds,
            std::string_view unit, bool byte_oriented = false) {
  const double per_second = seconds > 0.0 ? operations / seconds : 0.0;
  if (byte_oriented) {
    // A "per byte" cost is the meaningful figure for a streaming operation;
    // printing a per-operation figure here would be a number with no meaning.
    const double nanoseconds_per_byte = operations > 0.0 ? (seconds * 1e9) / operations : 0.0;
    std::printf("%-10s %-38s %10.0f %-10s %15.3f ns/byte %10.2f s total\n",
                std::string(provenance).c_str(), std::string(name).c_str(), per_second,
                std::string(unit).c_str(), nanoseconds_per_byte, seconds);
    return;
  }
  const double per_operation = operations > 0.0 ? seconds / operations : 0.0;
  std::printf("%-10s %-38s %10.0f %-10s %12.2f us/op  %10.2f s total\n", std::string(provenance).c_str(),
              std::string(name).c_str(), per_second, std::string(unit).c_str(), per_operation * 1e6, seconds);
}

}  // namespace

int main(int argc, char** argv) {
  const fpe::Limits limits = fpe::Limits::defaults();
  int iterations = 200;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--iterations" && i + 1 < argc) {
      iterations = std::max(1, std::atoi(argv[++i]));
    }
  }

  std::printf("%s %s benchmark harness\n", std::string(fpe::kProductName).c_str(),
              std::string(fpe::engine_version()).c_str());
  std::printf("host: %s\n", host_description().c_str());
  std::printf("provenance: SYNTHETIC = generated in memory by this harness; REAL = went through the\n");
  std::printf("            operating system on this host's local file system.\n");
  std::printf("methodology: single host, single process, no background load was introduced or measured.\n");
  std::printf("             Only completed operations are timed. Warm-up runs are excluded.\n\n");
  std::printf("%-10s %-38s %10s %-10s %16s %16s\n", "PROVENANCE", "OPERATION", "PER SECOND", "UNIT",
              "PER OPERATION", "TOTAL");
  std::printf("%s\n", std::string(102, '-').c_str());

  // ---- Digest -------------------------------------------------------------
  {
    const std::string message(4096, 'p');
    for (int i = 0; i < 50; ++i) {
      (void)fpe::Digest256::of(message);
    }
    const int rounds = iterations * 50;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      (void)fpe::Digest256::of(message);
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    report("SYNTHETIC", "sha256 over 4 KiB", static_cast<double>(rounds) * 4096.0, elapsed, "bytes/s",
           true);
  }

  // ---- Policy compilation -------------------------------------------------
  {
    auto document = fpe::parse_json(policy_document(512, 64), limits);
    if (!document) {
      std::cerr << "benchmark fixture failed to parse: " << document.status().to_string() << "\n";
      return 1;
    }
    auto bundle = fpe::bundle_from_json(document.value(), limits);
    if (!bundle) {
      std::cerr << "benchmark fixture failed to compile: " << bundle.status().to_string() << "\n";
      return 1;
    }
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
      auto compiled = fpe::compile_standalone_bundle(bundle.value(), limits);
      if (!compiled) {
        std::cerr << "compile failed: " << compiled.status().to_string() << "\n";
        return 1;
      }
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    report("SYNTHETIC", "compile 512-rule bundle", static_cast<double>(iterations), elapsed, "bundles");
  }

  // ---- Evaluation ---------------------------------------------------------
  {
    auto compiled = fpe::compile_standalone_bundle(
        fpe::bundle_from_json(fpe::parse_json(policy_document(512, 64), limits).value(), limits).value(),
        limits);
    if (!compiled) {
      std::cerr << "evaluation fixture failed: " << compiled.status().to_string() << "\n";
      return 1;
    }
    auto inputs = fpe::input_set_from_json(fpe::parse_json(input_document(64), limits).value(), limits);
    if (!inputs) {
      std::cerr << "input fixture failed: " << inputs.status().to_string() << "\n";
      return 1;
    }
    fpe::EvaluationOptions options;
    options.limits = limits;
    for (int i = 0; i < 20; ++i) {
      (void)fpe::evaluate(compiled.value(), inputs.value(), options);
    }
    const int rounds = iterations * 10;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      auto artifact = fpe::evaluate(compiled.value(), inputs.value(), options);
      if (!artifact) {
        std::cerr << "evaluation failed: " << artifact.status().to_string() << "\n";
        return 1;
      }
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    report("SYNTHETIC", "evaluate 512 rules over 64 facts", static_cast<double>(rounds), elapsed,
           "decisions");
  }

  // ---- JSON canonicalisation ---------------------------------------------
  {
    const std::string text = policy_document(512, 64);
    auto document = fpe::parse_json(text, limits);
    if (!document) {
      std::cerr << "canonicalisation fixture failed\n";
      return 1;
    }
    for (int i = 0; i < 20; ++i) {
      (void)fpe::to_canonical_json(document.value());
    }
    const int rounds = iterations * 10;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      (void)fpe::to_canonical_json(document.value());
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    report("SYNTHETIC", "canonical JSON serialisation",
           static_cast<double>(rounds) * static_cast<double>(text.size()), elapsed, "bytes/s", true);
  }

  // ---- Durable publication (REAL) ----------------------------------------
  {
    std::error_code error;
    std::filesystem::path root = std::filesystem::temp_directory_path(error) / "fpe-bench-store";
    if (error) {
      std::cerr << "cannot locate a temporary directory\n";
      return 1;
    }
    std::filesystem::remove_all(root, error);
    auto head = fpe::create_store(root, limits);
    if (!head) {
      std::cerr << "cannot create the benchmark store: " << head.status().to_string() << "\n";
      return 1;
    }
    auto compiled = fpe::compile_standalone_bundle(
        fpe::bundle_from_json(fpe::parse_json(policy_document(64, 16), limits).value(), limits).value(),
        limits);
    if (!compiled) {
      std::cerr << "benchmark policy failed to compile\n";
      return 1;
    }
    auto writer = fpe::open_writer(root, limits);
    if (!writer) {
      std::cerr << "cannot open the benchmark store for writing\n";
      return 1;
    }
    const int rounds = std::max(10, iterations / 2);
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      auto published = writer.value().publish(compiled.value());
      if (!published) {
        std::cerr << "publication failed: " << published.status().to_string() << "\n";
        return 1;
      }
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    writer.value().close();
    report("REAL", "durable publish (stage+flush+verify+swap)", static_cast<double>(rounds), elapsed,
           "generations");

    // Reader path: verify the manifest and resolve the published policy set.
    auto reader = fpe::open_reader(root, limits);
    if (!reader) {
      std::cerr << "cannot open the benchmark store for reading\n";
      return 1;
    }
    const auto read_start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      auto reopened = fpe::open_reader(root, limits);
      if (!reopened) {
        std::cerr << "reader open failed\n";
        return 1;
      }
      auto policy = reopened.value().policy();
      if (!policy) {
        std::cerr << "policy resolution failed\n";
        return 1;
      }
    }
    const auto read_elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - read_start).count();
    report("REAL", "open+verify+resolve published policy", static_cast<double>(rounds), read_elapsed,
           "reads");

    std::filesystem::remove_all(root, error);
  }

  std::printf("\nnotes:\n");
  std::printf("  * the durable publish figure is the cost of the guarantee, not of an enqueue: it includes\n");
  std::printf("    writing the generation record, flushing it, reading it back and verifying it, then\n");
  std::printf("    replacing the manifest atomically and flushing again;\n");
  std::printf("  * no speedup or before/after claim is made here, and none may be derived from a single\n");
  std::printf("    run of this harness on one machine.\n");
  return 0;
}
