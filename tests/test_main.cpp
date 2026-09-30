#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/policy.hpp"
#include "fpe/runtime.hpp"
#include "fpe/store.hpp"
#include "test_support.hpp"

namespace {

using fpe::ErrorCode;
using fpe::Limits;
using fpe::Status;

std::string read_file_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

fpe::Result<fpe::CanonicalBundle> compile_document(const std::filesystem::path& path, const Limits& limits) {
  const std::string text = read_file_text(path);
  auto document = fpe::parse_json(text, limits);
  if (!document) {
    return document.status();
  }
  auto bundle = fpe::bundle_from_json(document.value(), limits);
  if (!bundle) {
    return bundle.status();
  }
  return fpe::compile_standalone_bundle(std::move(bundle).value(), limits);
}

// ---- Child modes -----------------------------------------------------------
//
// These run in a separate process so that the parent can kill, restart, and
// race them. They are part of the test binary, never of the shipped library.

int child_publish_loop(const std::vector<std::string>& arguments) {
  if (arguments.size() != 4) {
    return 90;
  }
  const std::filesystem::path store_root(arguments[0]);
  const Limits limits = Limits::defaults();
  auto bundle_id = fpe::BundleId::parse(arguments[1], limits.max_identifier_bytes);
  if (!bundle_id) {
    return 91;
  }
  auto compiled = compile_document(std::filesystem::path(arguments[2]), limits);
  if (!compiled) {
    return 92;
  }
  const unsigned long count = std::stoul(arguments[3]);
  for (unsigned long i = 0; i < count; ++i) {
    auto writer = fpe::open_writer(store_root, limits);
    if (!writer) {
      return 93;
    }
    auto published = writer.value().publish(compiled.value());
    if (!published) {
      return 94;
    }
  }
  return 0;
}

int child_hold_writer(const std::vector<std::string>& arguments) {
  if (arguments.size() != 2) {
    return 90;
  }
  const std::filesystem::path store_root(arguments[0]);
  const unsigned long millis = std::stoul(arguments[1]);
  auto writer = fpe::open_writer(store_root, Limits::defaults());
  if (!writer) {
    std::cout << "writer-unavailable" << std::endl;
    return 1;
  }
  // Announced before sleeping, so the parent knows the lock is held rather than
  // merely that the child started.
  std::cout << "writer-held" << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(millis));
  return 0;
}

int child_eval_loop(const std::vector<std::string>& arguments) {
  if (arguments.size() != 3) {
    return 90;
  }
  const std::filesystem::path store_root(arguments[0]);
  const Limits limits = Limits::defaults();
  const std::string input_text = read_file_text(std::filesystem::path(arguments[1]));
  auto input_document = fpe::parse_json(input_text, limits);
  if (!input_document) {
    return 91;
  }
  auto inputs = fpe::input_set_from_json(input_document.value(), limits);
  if (!inputs) {
    return 92;
  }
  const unsigned long count = std::stoul(arguments[2]);
  for (unsigned long i = 0; i < count; ++i) {
    auto runtime = fpe::PolicyRuntime::open(store_root, limits);
    if (!runtime) {
      std::cout << "reader-failed " << runtime.status().to_string() << "\n";
      return 93;
    }
    fpe::EvaluationOptions options;
    options.limits = limits;
    auto artifact = runtime.value().decide(inputs.value(), options);
    if (!artifact) {
      std::cout << "evaluate-failed " << artifact.status().to_string() << "\n";
      return 94;
    }
    if (auto verified = fpe::verify_artifact(artifact.value()); !verified.ok()) {
      std::cout << "artifact-unverified " << verified.to_string() << "\n";
      return 95;
    }
  }
  std::cout << "eval-loop-ok\n";
  return 0;
}

int run_child_mode(const std::vector<std::string>& arguments) {
  const std::string& mode = arguments[0];
  const std::vector<std::string> rest(arguments.begin() + 1, arguments.end());
  if (mode == "publish-loop") {
    return child_publish_loop(rest);
  }
  if (mode == "hold-writer") {
    return child_hold_writer(rest);
  }
  if (mode == "eval-loop") {
    return child_eval_loop(rest);
  }
  std::cerr << "unknown child mode '" << mode << "'\n";
  return 89;
}

std::filesystem::path resolve_executable(const char* argv0) {
  std::error_code error;
  std::filesystem::path candidate = std::filesystem::weakly_canonical(std::filesystem::path(argv0), error);
  if (error || candidate.empty()) {
    candidate = std::filesystem::absolute(std::filesystem::path(argv0), error);
    if (error) {
      return std::filesystem::path(argv0);
    }
  }
  return candidate;
}

void print_usage() {
  std::cout << "fpe_tests [--list] [--filter <substring>] [--seed <n>] [--child <mode> ...]\n";
}

int run_suite(const std::vector<std::string>& arguments) {
  std::string filter;
  bool list_only = false;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string& argument = arguments[i];
    if (argument == "--list") {
      list_only = true;
    } else if (argument == "--filter" && i + 1 < arguments.size()) {
      filter = arguments[++i];
    } else if (argument == "--seed" && i + 1 < arguments.size()) {
      fpe::test::set_global_seed(std::stoull(arguments[++i]));
    } else if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    } else {
      std::cerr << "unrecognized test argument '" << argument << "'\n";
      print_usage();
      return 1;
    }
  }

  std::size_t selected = 0;
  std::size_t passed = 0;
  std::vector<std::string> failures;

  for (const auto& test_case : fpe::test::registry()) {
    if (!filter.empty() && test_case.name.find(filter) == std::string::npos) {
      continue;
    }
    selected += 1;
    if (list_only) {
      std::cout << test_case.name << "\n";
      continue;
    }
    std::cout << "[ RUN  ] " << test_case.name << "\n";
    bool failed = false;
    fpe::test::reset_case_failures();
    try {
      test_case.body();
    } catch (const fpe::test::AssertionFailure& failure) {
      std::cout << "    FAIL " << failure.what() << "\n";
      failed = true;
    } catch (const std::exception& error) {
      std::cout << "    FAIL unexpected exception: " << error.what() << "\n";
      failed = true;
    } catch (...) {
      std::cout << "    FAIL unexpected non-standard exception\n";
      failed = true;
    }
    if (fpe::test::case_failures() > 0) {
      failed = true;
    }
    if (failed) {
      failures.push_back(test_case.name);
      std::cout << "[ FAIL ] " << test_case.name << "\n";
    } else {
      passed += 1;
      std::cout << "[  OK  ] " << test_case.name << "\n";
    }
  }

  if (list_only) {
    return 0;
  }
  std::cout << "\n" << passed << "/" << selected << " test cases passed (seed "
            << fpe::test::global_seed() << ")\n";
  if (!failures.empty()) {
    std::cout << "failed cases:\n";
    for (const std::string& name : failures) {
      std::cout << "  " << name << "\n";
    }
    return 1;
  }
  return selected == 0 ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }

  const std::filesystem::path test_executable = resolve_executable(argv[0]);
  fpe::test::set_executable_paths(test_executable, std::filesystem::path(FPE_CLI_EXECUTABLE_PATH));

  if (!arguments.empty() && arguments[0] == "--child") {
    const std::vector<std::string> child(arguments.begin() + 1, arguments.end());
    if (child.empty()) {
      std::cerr << "--child requires a mode\n";
      return 89;
    }
    return run_child_mode(child);
  }
  return run_suite(arguments);
}
