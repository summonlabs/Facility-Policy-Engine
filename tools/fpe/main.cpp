// Facility Policy Engine command line interface.
//
// The CLI is an ordinary consumer of the installed library: it includes only
// the public headers, links only FacilityPolicyEngine::fpe, and reaches no
// internal API. Everything it can do, a downstream program can do.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/digest.hpp"
#include "fpe/engine.hpp"
#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/runtime.hpp"
#include "fpe/status.hpp"
#include "fpe/store.hpp"
#include "fpe/types.hpp"
#include "fpe/version.hpp"

namespace {

/// Exit codes are part of the interface: a decision that is not a grant must be
/// distinguishable from a tool failure by a script that never parses output.
enum ExitCode : int {
  kExitSuccess = 0,
  kExitFailure = 1,
  kExitRefused = 2,
  kExitUndetermined = 3,
};

void print_usage(std::ostream& out) {
  out << fpe::kProductName << " " << fpe::engine_version() << "\n"
      << "\n"
      << "Usage: fpe <command> [options]\n"
      << "\n"
      << "Policy documents\n"
      << "  policy check <document.json>            Compile and report identity and digest\n"
      << "  policy digest <document.json>           Print the canonical policy digest\n"
      << "  policy canonicalize <document.json>     Print the canonical JSON form\n"
      << "  policy compile --root <id> <doc>...     Compile a set with imports\n"
      << "\n"
      << "Durable store\n"
      << "  store create <dir>                      Create an empty store\n"
      << "  store publish <dir> --root <id> <doc>...  Publish a new policy generation\n"
      << "  store show <dir>                        Report the current generation\n"
      << "  store verify <dir>                      Verify the manifest and history\n"
      << "  store recover <dir> --generation <n>    Rebuild the manifest from one generation\n"
      << "  store floor <dir> --generation <n>      Raise the rollback floor\n"
      << "  store anchor <dir> --out <file>         Write an out-of-band anchor\n"
      << "\n"
      << "Decisions\n"
      << "  eval <dir> --input <facts.json>         Evaluate the current generation\n"
      << "  appraise <dir> --input <facts.json>     Report how every declared fact is seen\n"
      << "  decision verify <artifact.json>         Verify a decision artifact\n"
      << "  selftest                                Run built-in known-answer checks\n"
      << "\n"
      << "Common options\n"
      << "  --json                 Emit machine-readable output\n"
      << "  --as-of <unix-nanos>   Evaluation instant used for fact freshness\n"
      << "  --anchor <file>        Out-of-band anchor to check the store against\n"
      << "  --help, -h             Show this help\n"
      << "  --version              Show the version\n"
      << "\n"
      << "Exit codes\n"
      << "  0  the command completed and the decision, if any, was allow\n"
      << "  1  the command failed: usage, I/O, validation, or integrity\n"
      << "  2  the decision was refuse, or a checked decision is no longer current\n"
      << "  3  the decision was unknown or defer\n";
}

/// Parsed command line. Options are stored without their leading dashes.
struct Arguments {
  std::vector<std::string> positional;
  std::map<std::string, std::string> options;
  std::set<std::string> flags;
};

Arguments parse_arguments(const std::vector<std::string>& tokens, const std::set<std::string>& valued_options,
                          const std::set<std::string>& flag_options) {
  Arguments arguments;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    const std::string& token = tokens[i];
    if (token.size() >= 2 && token[0] == '-' && token[1] == '-') {
      const std::string name = token.substr(2);
      if (valued_options.find(name) != valued_options.end()) {
        if (i + 1 >= tokens.size()) {
          arguments.options[name] = std::string();
          continue;
        }
        arguments.options[name] = tokens[++i];
        continue;
      }
      if (flag_options.find(name) != flag_options.end()) {
        arguments.flags.insert(name);
        continue;
      }
      arguments.flags.insert(name);
      continue;
    }
    arguments.positional.push_back(token);
  }
  return arguments;
}

[[nodiscard]] bool has_flag(const Arguments& arguments, std::string_view name) {
  return arguments.flags.find(std::string(name)) != arguments.flags.end();
}

[[nodiscard]] std::optional<std::string> option_value(const Arguments& arguments, std::string_view name) {
  const auto found = arguments.options.find(std::string(name));
  if (found == arguments.options.end() || found->second.empty()) {
    return std::nullopt;
  }
  return found->second;
}

int report_failure(std::string_view command, const fpe::Status& status) {
  std::cerr << command << ": " << status.to_string() << "\n";
  return kExitFailure;
}

int report_usage(std::string_view message) {
  std::cerr << "fpe: " << message << "\n";
  std::cerr << "Run 'fpe --help' for usage.\n";
  return kExitFailure;
}

std::filesystem::path to_path(const std::string& text) {
  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
}

std::string path_to_text(const std::filesystem::path& path) {
  const std::u8string utf8 = path.u8string();
  return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

fpe::Result<std::string> read_text_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return fpe::Status::failure(fpe::ErrorCode::NotFound,
                                "cannot open '" + path_to_text(path) + "' for reading");
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    return fpe::Status::failure(fpe::ErrorCode::IoFailure,
                                "cannot determine the size of '" + path_to_text(path) + "'");
  }
  if (static_cast<std::uint64_t>(size) > max_bytes) {
    return fpe::Status::failure(fpe::ErrorCode::BadDeclaredLength,
                                "'" + path_to_text(path) + "' is " + std::to_string(size) +
                                    " bytes, above the permitted maximum of " + std::to_string(max_bytes));
  }
  stream.seekg(0, std::ios::beg);
  std::string text(static_cast<std::size_t>(size), '\0');
  if (!text.empty()) {
    stream.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (!stream) {
      return fpe::Status::failure(fpe::ErrorCode::IoFailure,
                                  "reading '" + path_to_text(path) + "' did not return every byte");
    }
  }
  return text;
}

fpe::Status write_text_file(const std::filesystem::path& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return fpe::Status::failure(fpe::ErrorCode::IoFailure,
                                "cannot open '" + path_to_text(path) + "' for writing");
  }
  stream.write(text.data(), static_cast<std::streamsize>(text.size()));
  stream.flush();
  if (!stream) {
    return fpe::Status::failure(fpe::ErrorCode::IoFailure, "writing '" + path_to_text(path) + "' failed");
  }
  return fpe::Status::success();
}

fpe::Result<fpe::JsonValue> read_document(const std::filesystem::path& path, const fpe::Limits& limits) {
  auto text = read_text_file(path, limits.max_bundle_bytes);
  if (!text) {
    return text.status();
  }
  return fpe::parse_json(text.value(), limits);
}

/// Compiles a set of documents into one canonical bundle.
fpe::Result<std::shared_ptr<const fpe::CanonicalBundle>> compile_set(const std::vector<std::string>& paths,
                                                                    const std::string& root_id,
                                                                    const fpe::Limits& limits) {
  auto root_key = fpe::BundleId::parse(root_id, limits.max_identifier_bytes);
  if (!root_key) {
    return root_key.status();
  }
  fpe::BundleCompiler compiler(limits);
  for (const std::string& path : paths) {
    auto document = read_document(to_path(path), limits);
    if (!document) {
      return document.status();
    }
    auto bundle = fpe::bundle_from_json(document.value(), limits);
    if (!bundle) {
      return bundle.status();
    }
    if (auto provided = compiler.provide(std::move(bundle).value()); !provided.ok()) {
      return provided;
    }
  }
  return compiler.compile(root_key.value());
}

void print_bundle_summary(const fpe::CanonicalBundle& bundle, bool json) {
  if (json) {
    fpe::JsonValue::Object summary;
    summary.emplace("bundle", fpe::JsonValue::string(bundle.id().str()));
    summary.emplace("revision", fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.revision().raw())));
    summary.emplace("digest", fpe::JsonValue::string(bundle.digest().to_hex()));
    summary.emplace("canonical_bytes",
                    fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.canonical_bytes().size())));
    summary.emplace("rules", fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.bundle().rules.size())));
    summary.emplace("facts", fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.bundle().facts.size())));
    summary.emplace("predicates",
                    fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.bundle().predicates.size())));
    summary.emplace("imports", fpe::JsonValue::integer(static_cast<std::int64_t>(bundle.imports().size())));
    std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
    return;
  }
  std::cout << "bundle          " << bundle.id().str() << "\n"
            << "revision        " << bundle.revision().raw() << "\n"
            << "digest          " << bundle.digest().to_hex() << "\n"
            << "canonical bytes " << bundle.canonical_bytes().size() << "\n"
            << "rules           " << bundle.bundle().rules.size() << "\n"
            << "facts           " << bundle.bundle().facts.size() << "\n"
            << "predicates      " << bundle.bundle().predicates.size() << "\n"
            << "imports         " << bundle.imports().size() << "\n";
}

int command_policy(const std::vector<std::string>& tokens) {
  if (tokens.empty()) {
    return report_usage("policy requires a subcommand");
  }
  const fpe::Limits limits = fpe::Limits::defaults();
  const std::string& subcommand = tokens.front();
  const std::vector<std::string> rest(tokens.begin() + 1, tokens.end());

  if (subcommand == "check" || subcommand == "digest" || subcommand == "canonicalize") {
    const Arguments arguments = parse_arguments(rest, {}, {"json", "canonical"});
    if (arguments.positional.size() != 1) {
      return report_usage("policy " + subcommand + " takes exactly one document");
    }
    const std::filesystem::path path = to_path(arguments.positional.front());
    auto text = read_text_file(path, limits.max_bundle_bytes);
    if (!text) {
      return report_failure("policy " + subcommand, text.status());
    }
    if (subcommand == "canonicalize") {
      auto document = fpe::parse_json(text.value(), limits);
      if (!document) {
        return report_failure("policy canonicalize", document.status());
      }
      std::cout << fpe::to_canonical_json(document.value()) << "\n";
      return kExitSuccess;
    }
    if (has_flag(arguments, "canonical")) {
      if (auto canonical = fpe::require_canonical_json(text.value(), limits); !canonical.ok()) {
        return report_failure("policy " + subcommand, canonical);
      }
    }
    auto document = fpe::parse_json(text.value(), limits);
    if (!document) {
      return report_failure("policy " + subcommand, document.status());
    }
    auto bundle = fpe::bundle_from_json(document.value(), limits);
    if (!bundle) {
      return report_failure("policy " + subcommand, bundle.status());
    }
    auto canonical = fpe::compile_standalone_bundle(std::move(bundle).value(), limits);
    if (!canonical) {
      return report_failure("policy " + subcommand, canonical.status());
    }
    if (subcommand == "digest") {
      std::cout << canonical.value().digest().to_hex() << "\n";
      return kExitSuccess;
    }
    print_bundle_summary(canonical.value(), has_flag(arguments, "json"));
    return kExitSuccess;
  }

  if (subcommand == "compile") {
    const Arguments arguments = parse_arguments(rest, {"root"}, {"json"});
    auto root = option_value(arguments, "root");
    if (!root.has_value()) {
      return report_usage("policy compile requires --root <bundle-id>");
    }
    if (arguments.positional.empty()) {
      return report_usage("policy compile requires at least one document");
    }
    auto compiled = compile_set(arguments.positional, root.value(), limits);
    if (!compiled) {
      return report_failure("policy compile", compiled.status());
    }
    print_bundle_summary(*compiled.value(), has_flag(arguments, "json"));
    return kExitSuccess;
  }

  return report_usage("unrecognized policy subcommand '" + subcommand + "'");
}

void print_head(const fpe::StoreHead& head, bool json) {
  if (json) {
    fpe::JsonValue::Object summary;
    summary.emplace("store_id", fpe::JsonValue::string(head.store_id.to_hex()));
    summary.emplace("generation", fpe::JsonValue::integer(static_cast<std::int64_t>(head.generation.raw())));
    summary.emplace("control_epoch",
                    fpe::JsonValue::integer(static_cast<std::int64_t>(head.control_epoch.raw())));
    summary.emplace("sequence", fpe::JsonValue::integer(static_cast<std::int64_t>(head.sequence.raw())));
    summary.emplace("floor_generation",
                    fpe::JsonValue::integer(static_cast<std::int64_t>(head.floor_generation.raw())));
    summary.emplace("manifest_digest", fpe::JsonValue::string(head.manifest_digest.to_hex()));
    summary.emplace("record_digest", fpe::JsonValue::string(head.record_digest.to_hex()));
    summary.emplace("bundle_digest", fpe::JsonValue::string(head.bundle_digest.to_hex()));
    std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
    return;
  }
  std::cout << "store            " << head.store_id.to_hex() << "\n"
            << "generation       " << head.generation.raw() << "\n"
            << "control epoch    " << head.control_epoch.raw() << "\n"
            << "sequence         " << head.sequence.raw() << "\n"
            << "rollback floor   " << head.floor_generation.raw() << "\n"
            << "manifest digest  " << head.manifest_digest.to_hex() << "\n"
            << "record digest    " << head.record_digest.to_hex() << "\n"
            << "policy digest    " << head.bundle_digest.to_hex() << "\n";
}

int command_store(const std::vector<std::string>& tokens) {
  if (tokens.empty()) {
    return report_usage("store requires a subcommand");
  }
  const fpe::Limits limits = fpe::Limits::defaults();
  const std::string& subcommand = tokens.front();
  const std::vector<std::string> rest(tokens.begin() + 1, tokens.end());

  if (subcommand == "create") {
    const Arguments arguments = parse_arguments(rest, {}, {"json"});
    if (arguments.positional.size() != 1) {
      return report_usage("store create takes exactly one directory");
    }
    auto head = fpe::create_store(to_path(arguments.positional.front()), limits);
    if (!head) {
      return report_failure("store create", head.status());
    }
    print_head(head.value(), has_flag(arguments, "json"));
    return kExitSuccess;
  }

  if (subcommand == "publish") {
    const Arguments arguments = parse_arguments(rest, {"root"}, {"json"});
    auto root = option_value(arguments, "root");
    if (!root.has_value()) {
      return report_usage("store publish requires --root <bundle-id>");
    }
    if (arguments.positional.empty()) {
      return report_usage("store publish requires a store directory and at least one document");
    }
    const std::filesystem::path store_root = to_path(arguments.positional.front());
    const std::vector<std::string> documents(arguments.positional.begin() + 1, arguments.positional.end());
    auto compiled = compile_set(documents, root.value(), limits);
    if (!compiled) {
      return report_failure("store publish", compiled.status());
    }
    auto writer = fpe::open_writer(store_root, limits);
    if (!writer) {
      return report_failure("store publish", writer.status());
    }
    auto generation = writer.value().publish(*compiled.value());
    if (!generation) {
      return report_failure("store publish", generation.status());
    }
    if (has_flag(arguments, "json")) {
      fpe::JsonValue::Object summary;
      summary.emplace("generation", fpe::JsonValue::integer(static_cast<std::int64_t>(generation.value().raw())));
      summary.emplace("bundle", fpe::JsonValue::string(compiled.value()->id().str()));
      summary.emplace("digest", fpe::JsonValue::string(compiled.value()->digest().to_hex()));
      std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
    } else {
      std::cout << "published generation " << generation.value().raw() << " bundle "
                << compiled.value()->id().str() << " digest " << compiled.value()->digest().to_hex() << "\n";
    }
    writer.value().close();
    return kExitSuccess;
  }

  if (subcommand == "show") {
    const Arguments arguments = parse_arguments(rest, {"anchor"}, {"json"});
    if (arguments.positional.size() != 1) {
      return report_usage("store show takes exactly one directory");
    }
    auto reader = fpe::open_reader(to_path(arguments.positional.front()), limits);
    if (!reader) {
      return report_failure("store show", reader.status());
    }
    if (auto anchor_path = option_value(arguments, "anchor")) {
      auto anchor = fpe::read_anchor(to_path(anchor_path.value()), limits);
      if (!anchor) {
        return report_failure("store show", anchor.status());
      }
      if (auto checked = fpe::check_anchor(reader.value(), anchor.value()); !checked.ok()) {
        return report_failure("store show", checked);
      }
    }
    print_head(reader.value().head(), has_flag(arguments, "json"));
    if (reader.value().has_policy()) {
      auto policy = reader.value().policy();
      if (!policy) {
        return report_failure("store show", policy.status());
      }
      if (has_flag(arguments, "json")) {
        print_bundle_summary(*policy.value(), true);
      } else {
        std::cout << "policy bundle    " << policy.value()->id().str() << " revision "
                  << policy.value()->revision().raw() << " digest " << policy.value()->digest().to_hex() << "\n";
      }
    } else {
      std::cout << "policy           none published\n";
    }
    return kExitSuccess;
  }

  if (subcommand == "verify") {
    const Arguments arguments = parse_arguments(rest, {"history", "anchor"}, {"json"});
    if (arguments.positional.size() != 1) {
      return report_usage("store verify takes exactly one directory");
    }
    auto reader = fpe::open_reader(to_path(arguments.positional.front()), limits);
    if (!reader) {
      return report_failure("store verify", reader.status());
    }
    if (auto anchor_path = option_value(arguments, "anchor")) {
      auto anchor = fpe::read_anchor(to_path(anchor_path.value()), limits);
      if (!anchor) {
        return report_failure("store verify", anchor.status());
      }
      if (auto checked = fpe::check_anchor(reader.value(), anchor.value()); !checked.ok()) {
        return report_failure("store verify", checked);
      }
    }
    std::uint32_t depth = 1000000;
    if (auto history = option_value(arguments, "history")) {
      try {
        const unsigned long parsed = std::stoul(history.value());
        depth = static_cast<std::uint32_t>(parsed);
      } catch (const std::exception&) {
        return report_usage("--history must be a non-negative integer");
      }
    }
    std::vector<fpe::GenerationInfo> history;
    if (auto verified = reader.value().verify_history(depth, history); !verified.ok()) {
      return report_failure("store verify", verified);
    }
    if (has_flag(arguments, "json")) {
      fpe::JsonValue::Array items;
      for (const auto& entry : history) {
        fpe::JsonValue::Object item;
        item.emplace("generation", fpe::JsonValue::integer(static_cast<std::int64_t>(entry.generation.raw())));
        item.emplace("sequence", fpe::JsonValue::integer(static_cast<std::int64_t>(entry.sequence.raw())));
        item.emplace("control_epoch",
                     fpe::JsonValue::integer(static_cast<std::int64_t>(entry.control_epoch.raw())));
        item.emplace("record_digest", fpe::JsonValue::string(entry.record_digest.to_hex()));
        item.emplace("bundle_digest", fpe::JsonValue::string(entry.bundle_digest.to_hex()));
        items.push_back(fpe::JsonValue::object(std::move(item)));
      }
      fpe::JsonValue::Object summary;
      summary.emplace("verified_generations", fpe::JsonValue::integer(static_cast<std::int64_t>(history.size())));
      summary.emplace("generations", fpe::JsonValue::array(std::move(items)));
      std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
    } else {
      std::cout << "verified " << history.size() << " generation record(s)\n";
      for (const auto& entry : history) {
        std::cout << "  generation " << entry.generation.raw() << " sequence " << entry.sequence.raw()
                  << " epoch " << entry.control_epoch.raw() << " record "
                  << entry.record_digest.to_hex().substr(0, 16) << " policy "
                  << entry.bundle_digest.to_hex().substr(0, 16) << "\n";
      }
    }
    return kExitSuccess;
  }

  if (subcommand == "recover" || subcommand == "floor") {
    const Arguments arguments = parse_arguments(rest, {"generation"}, {"json"});
    auto generation_text = option_value(arguments, "generation");
    if (!generation_text.has_value()) {
      return report_usage("store " + subcommand + " requires --generation <n>");
    }
    std::uint64_t generation_value = 0;
    try {
      generation_value = std::stoull(generation_text.value());
    } catch (const std::exception&) {
      return report_usage("--generation must be a non-negative integer");
    }
    if (arguments.positional.size() != 1) {
      return report_usage("store " + subcommand + " takes exactly one directory");
    }
    auto writer = fpe::open_writer(to_path(arguments.positional.front()), limits);
    if (!writer) {
      return report_failure("store " + subcommand, writer.status());
    }
    const fpe::Generation generation = fpe::Generation::from_raw(generation_value);
    const fpe::Status status = subcommand == "recover" ? writer.value().recover_to(generation)
                                                       : writer.value().raise_floor(generation);
    if (!status.ok()) {
      return report_failure("store " + subcommand, status);
    }
    print_head(writer.value().head(), has_flag(arguments, "json"));
    writer.value().close();
    return kExitSuccess;
  }

  if (subcommand == "anchor") {
    const Arguments arguments = parse_arguments(rest, {"out"}, {"json"});
    auto out = option_value(arguments, "out");
    if (!out.has_value()) {
      return report_usage("store anchor requires --out <file>");
    }
    if (arguments.positional.size() != 1) {
      return report_usage("store anchor takes exactly one directory");
    }
    auto reader = fpe::open_reader(to_path(arguments.positional.front()), limits);
    if (!reader) {
      return report_failure("store anchor", reader.status());
    }
    if (!reader.value().has_policy()) {
      return report_failure("store anchor",
                            fpe::Status::failure(fpe::ErrorCode::StoreEmpty,
                                                 "an anchor can only record a published generation"));
    }
    fpe::StoreAnchor anchor;
    anchor.store_id = reader.value().head().store_id;
    anchor.generation = reader.value().head().generation;
    anchor.sequence = reader.value().head().sequence;
    anchor.manifest_digest = reader.value().head().manifest_digest;
    if (auto written = fpe::write_anchor(to_path(out.value()), anchor, limits); !written.ok()) {
      return report_failure("store anchor", written);
    }
    if (has_flag(arguments, "json")) {
      std::cout << fpe::to_canonical_json(fpe::anchor_to_json(anchor)) << "\n";
    } else {
      std::cout << "anchored generation " << anchor.generation.raw() << " sequence " << anchor.sequence.raw()
                << " manifest " << anchor.manifest_digest.to_hex() << " to " << out.value() << "\n";
    }
    return kExitSuccess;
  }

  return report_usage("unrecognized store subcommand '" + subcommand + "'");
}

fpe::Result<fpe::EvaluationOptions> evaluation_options(const Arguments& arguments, const fpe::Limits& limits) {
  fpe::EvaluationOptions options;
  options.limits = limits;
  options.include_explanation = !has_flag(arguments, "no-explanation");
  if (auto as_of = option_value(arguments, "as-of")) {
    try {
      const long long value = std::stoll(as_of.value());
      options.as_of = fpe::TimestampNanos::from_unix_nanos(static_cast<std::int64_t>(value));
    } catch (const std::exception&) {
      return fpe::Status::failure(fpe::ErrorCode::OutOfRange, "--as-of must be a signed 64-bit nanosecond value");
    }
  }
  return options;
}

fpe::Result<fpe::InputSet> load_inputs(const std::string& path, const fpe::Limits& limits) {
  auto text = read_text_file(to_path(path), limits.max_artifact_bytes);
  if (!text) {
    return text.status();
  }
  auto document = fpe::parse_json(text.value(), limits);
  if (!document) {
    return document.status();
  }
  return fpe::input_set_from_json(document.value(), limits);
}

int outcome_exit_code(fpe::Outcome outcome) {
  switch (outcome) {
    case fpe::Outcome::Allow:
      return kExitSuccess;
    case fpe::Outcome::Refuse:
      return kExitRefused;
    case fpe::Outcome::Defer:
    case fpe::Outcome::Unknown:
      return kExitUndetermined;
  }
  return kExitUndetermined;
}

int command_eval(const std::vector<std::string>& tokens, bool appraise_only) {
  const fpe::Limits limits = fpe::Limits::defaults();
  const Arguments arguments =
      parse_arguments(tokens, {"input", "as-of"}, {"json", "no-explanation"});
  auto input_path = option_value(arguments, "input");
  if (!input_path.has_value()) {
    return report_usage(std::string(appraise_only ? "appraise" : "eval") + " requires --input <facts.json>");
  }
  if (arguments.positional.size() != 1) {
    return report_usage(std::string(appraise_only ? "appraise" : "eval") +
                        " takes exactly one store directory");
  }
  auto inputs = load_inputs(input_path.value(), limits);
  if (!inputs) {
    return report_failure(appraise_only ? "appraise" : "eval", inputs.status());
  }
  auto runtime = fpe::PolicyRuntime::open(to_path(arguments.positional.front()), limits);
  if (!runtime) {
    return report_failure(appraise_only ? "appraise" : "eval", runtime.status());
  }
  auto options = evaluation_options(arguments, limits);
  if (!options) {
    return report_failure(appraise_only ? "appraise" : "eval", options.status());
  }
  auto policy = runtime.value().has_policy() ? fpe::Result<const fpe::CanonicalBundle*>(
                                                   nullptr)
                                             : fpe::Result<const fpe::CanonicalBundle*>(
                                                   fpe::Status::failure(fpe::ErrorCode::StoreEmpty,
                                                                        "the store has no published policy"));
  (void)policy;
  if (!runtime.value().has_policy()) {
    return report_failure(appraise_only ? "appraise" : "eval",
                          fpe::Status::failure(fpe::ErrorCode::StoreEmpty,
                                               "the store has no published policy generation"));
  }

  if (appraise_only) {
    auto reader = fpe::open_reader(to_path(arguments.positional.front()), limits);
    if (!reader) {
      return report_failure("appraise", reader.status());
    }
    auto canonical = reader.value().policy();
    if (!canonical) {
      return report_failure("appraise", canonical.status());
    }
    auto appraisals = fpe::appraise_inputs(*canonical.value(), inputs.value(), options.value());
    if (!appraisals) {
      return report_failure("appraise", appraisals.status());
    }
    if (has_flag(arguments, "json")) {
      fpe::JsonValue::Array items;
      for (const auto& appraisal : appraisals.value()) {
        fpe::JsonValue::Object item;
        item.emplace("fact", fpe::JsonValue::string(appraisal.key.str()));
        item.emplace("declared_type", fpe::JsonValue::string(std::string(fpe::fact_type_name(appraisal.declared_type))));
        item.emplace("supplied", fpe::JsonValue::boolean(appraisal.supplied));
        item.emplace("state", fpe::JsonValue::string(std::string(fpe::fact_state_name(appraisal.state))));
        item.emplace("freshness", fpe::JsonValue::string(std::string(fpe::freshness_name(appraisal.freshness))));
        item.emplace("type_conflict", fpe::JsonValue::boolean(appraisal.type_conflict));
        item.emplace("cause", fpe::JsonValue::string(std::string(fpe::appraisal_cause_name(appraisal.cause))));
        items.push_back(fpe::JsonValue::object(std::move(item)));
      }
      std::cout << fpe::to_canonical_json(fpe::JsonValue::array(std::move(items))) << "\n";
    } else {
      for (const auto& appraisal : appraisals.value()) {
        std::cout << appraisal.key.str() << " type " << fpe::fact_type_name(appraisal.declared_type)
                  << (appraisal.supplied ? " supplied" : " not-supplied") << " state "
                  << fpe::fact_state_name(appraisal.state) << " freshness "
                  << fpe::freshness_name(appraisal.freshness)
                  << (appraisal.type_conflict ? " type-conflict" : "") << " cause "
                  << fpe::appraisal_cause_name(appraisal.cause) << "\n";
      }
    }
    return kExitSuccess;
  }

  auto artifact = runtime.value().decide(inputs.value(), options.value());
  if (!artifact) {
    return report_failure("eval", artifact.status());
  }
  if (has_flag(arguments, "json")) {
    std::cout << fpe::to_canonical_json(fpe::artifact_document(artifact.value())) << "\n";
  } else {
    std::cout << fpe::artifact_summary(artifact.value()) << "\n";
    std::cout << "artifact digest  " << artifact.value().artifact_digest.to_hex() << "\n";
    for (const auto& line : artifact.value().explanation) {
      std::cout << "  " << line << "\n";
    }
  }
  return outcome_exit_code(artifact.value().outcome);
}

int command_decision(const std::vector<std::string>& tokens) {
  if (tokens.empty() || tokens.front() != "verify") {
    return report_usage("decision requires the 'verify' subcommand");
  }
  const fpe::Limits limits = fpe::Limits::defaults();
  const std::vector<std::string> rest(tokens.begin() + 1, tokens.end());
  const Arguments arguments = parse_arguments(rest, {"store"}, {"json"});
  if (arguments.positional.size() != 1) {
    return report_usage("decision verify takes exactly one artifact document");
  }
  auto text = read_text_file(to_path(arguments.positional.front()), limits.max_artifact_bytes);
  if (!text) {
    return report_failure("decision verify", text.status());
  }
  auto document = fpe::parse_json(text.value(), limits);
  if (!document) {
    return report_failure("decision verify", document.status());
  }
  auto artifact = fpe::artifact_from_json(document.value(), limits);
  if (!artifact) {
    return report_failure("decision verify", artifact.status());
  }
  std::optional<fpe::FenceResult> fence;
  if (auto store = option_value(arguments, "store")) {
    auto reader = fpe::open_reader(to_path(store.value()), limits);
    if (!reader) {
      return report_failure("decision verify", reader.status());
    }
    auto current = reader.value().current_policy();
    if (!current) {
      return report_failure("decision verify", current.status());
    }
    fence = fpe::fence_decision(artifact.value(), current.value());
  }
  if (has_flag(arguments, "json")) {
    fpe::JsonValue::Object summary;
    summary.emplace("outcome", fpe::JsonValue::string(std::string(fpe::outcome_name(artifact.value().outcome))));
    summary.emplace("artifact_digest", fpe::JsonValue::string(artifact.value().artifact_digest.to_hex()));
    summary.emplace("bundle", fpe::JsonValue::string(artifact.value().bundle.str()));
    summary.emplace("bundle_digest", fpe::JsonValue::string(artifact.value().bundle_digest.to_hex()));
    summary.emplace("input_digest", fpe::JsonValue::string(artifact.value().input_digest.to_hex()));
    if (fence.has_value()) {
      summary.emplace("fence", fpe::JsonValue::string(std::string(fpe::fence_status_name(fence->status))));
      summary.emplace("fence_detail", fpe::JsonValue::string(fence->detail));
    }
    std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
  } else {
    std::cout << "artifact digest  " << artifact.value().artifact_digest.to_hex() << "\n"
              << "outcome          " << fpe::outcome_name(artifact.value().outcome) << "\n"
              << "bundle           " << artifact.value().bundle.str() << "\n"
              << "bundle digest    " << artifact.value().bundle_digest.to_hex() << "\n"
              << "input digest     " << artifact.value().input_digest.to_hex() << "\n";
    if (fence.has_value()) {
      std::cout << "fence            " << fpe::fence_status_name(fence->status) << "\n"
                << "fence detail     " << fence->detail << "\n";
    }
  }
  if (fence.has_value() && !fence->is_current()) {
    return kExitRefused;
  }
  return kExitSuccess;
}

/// Built-in known-answer checks against fixed standards. These are the same
/// vectors the test suite uses; running them from the installed binary is what
/// makes an installed artifact self-verifying.
int command_selftest(const std::vector<std::string>& tokens) {
  const Arguments arguments = parse_arguments(tokens, {}, {"json"});
  const fpe::Limits limits = fpe::Limits::defaults();
  std::vector<std::pair<std::string, bool>> results;

  const auto check = [&results](std::string name, bool passed) {
    results.emplace_back(std::move(name), passed);
  };

  check("sha256-empty",
        fpe::Digest256::of("").to_hex() ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("sha256-abc",
        fpe::Digest256::of("abc").to_hex() ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("sha256-two-block",
        fpe::Digest256::of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_hex() ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  check("crc32-check-value", fpe::crc32("123456789") == 0xCBF43926u);

  const fpe::JsonValue canonical_source = [] {
    fpe::JsonValue::Object members;
    members.emplace("b", fpe::JsonValue::integer(2));
    members.emplace("a", fpe::JsonValue::string("x"));
    return fpe::JsonValue::object(std::move(members));
  }();
  check("json-canonical-order", fpe::to_canonical_json(canonical_source) == "{\"a\":\"x\",\"b\":2}");

  const std::string policy_text =
      R"({"schema":1,"bundle":"selftest.bundle","revision":1,"facts":[{"key":"a","type":"integer"},{"key":"b","type":"integer"}],"rules":[{"id":"r1","priority":10,"effect":"allow","when":{"test":{"fact":"a","op":"equals","operands":[1]}},"reason":"selftest.allow"},{"id":"r2","priority":10,"effect":"refuse","when":{"test":{"fact":"b","op":"equals","operands":[1]}},"reason":"selftest.refuse"}]})";
  const std::string permuted_text =
      R"({"rules":[{"reason":"selftest.refuse","effect":"refuse","priority":10,"id":"r2","when":{"test":{"operands":[1],"op":"equals","fact":"b"}}},{"when":{"test":{"fact":"a","op":"equals","operands":[1]}},"reason":"selftest.allow","id":"r1","priority":10,"effect":"allow"}],"revision":1,"bundle":"selftest.bundle","schema":1,"facts":[{"type":"integer","key":"b"},{"key":"a","type":"integer"}]})";

  const auto compile_text = [&limits](const std::string& text) {
    auto document = fpe::parse_json(text, limits);
    if (!document) {
      return fpe::Result<fpe::CanonicalBundle>(document.status());
    }
    auto bundle = fpe::bundle_from_json(document.value(), limits);
    if (!bundle) {
      return fpe::Result<fpe::CanonicalBundle>(bundle.status());
    }
    return fpe::compile_standalone_bundle(std::move(bundle).value(), limits);
  };

  auto compiled = compile_text(policy_text);
  auto permuted = compile_text(permuted_text);
  check("bundle-compiles", compiled.has_value());
  check("bundle-insertion-order-invariant",
        compiled.has_value() && permuted.has_value() &&
            compiled.value().digest() == permuted.value().digest());

  if (compiled.has_value()) {
    fpe::JsonValue::Object input_document;
    input_document.emplace("schema", fpe::JsonValue::integer(1));
    fpe::JsonValue::Array facts;
    fpe::JsonValue::Object observed;
    observed.emplace("key", fpe::JsonValue::string("a"));
    observed.emplace("type", fpe::JsonValue::string("integer"));
    observed.emplace("state", fpe::JsonValue::string("observed"));
    observed.emplace("value", fpe::JsonValue::integer(1));
    facts.push_back(fpe::JsonValue::object(std::move(observed)));
    fpe::JsonValue::Object absent;
    absent.emplace("key", fpe::JsonValue::string("b"));
    absent.emplace("type", fpe::JsonValue::string("integer"));
    absent.emplace("state", fpe::JsonValue::string("missing"));
    facts.push_back(fpe::JsonValue::object(std::move(absent)));
    input_document.emplace("facts", fpe::JsonValue::array(std::move(facts)));

    auto inputs = fpe::input_set_from_json(fpe::JsonValue::object(input_document), limits);
    check("input-set-builds", inputs.has_value());
    if (inputs.has_value()) {
      fpe::EvaluationOptions options;
      options.limits = limits;
      auto artifact = fpe::evaluate(compiled.value(), inputs.value(), options);
      check("evaluation-runs", artifact.has_value());
      if (artifact.has_value()) {
        // Rule r1 allows and rule r2 is undecided at the same priority, so the
        // engine must not grant permission.
        check("undecided-refusal-blocks-allow", artifact.value().outcome == fpe::Outcome::Unknown);
      }
    }
  }

  bool all_passed = true;
  for (const auto& entry : results) {
    if (!entry.second) {
      all_passed = false;
    }
  }
  if (has_flag(arguments, "json")) {
    fpe::JsonValue::Array items;
    for (const auto& entry : results) {
      fpe::JsonValue::Object item;
      item.emplace("check", fpe::JsonValue::string(entry.first));
      item.emplace("passed", fpe::JsonValue::boolean(entry.second));
      items.push_back(fpe::JsonValue::object(std::move(item)));
    }
    fpe::JsonValue::Object summary;
    summary.emplace("passed", fpe::JsonValue::boolean(all_passed));
    summary.emplace("checks", fpe::JsonValue::array(std::move(items)));
    std::cout << fpe::to_canonical_json(fpe::JsonValue::object(std::move(summary))) << "\n";
  } else {
    for (const auto& entry : results) {
      std::cout << (entry.second ? "PASS " : "FAIL ") << entry.first << "\n";
    }
    std::cout << (all_passed ? "selftest passed" : "selftest failed") << "\n";
  }
  return all_passed ? kExitSuccess : kExitFailure;
}

int run(const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    print_usage(std::cout);
    return kExitSuccess;
  }
  const std::string& command = arguments.front();
  const std::vector<std::string> rest(arguments.begin() + 1, arguments.end());

  if (command == "--help" || command == "-h" || command == "help") {
    print_usage(std::cout);
    return kExitSuccess;
  }
  if (command == "--version" || command == "version") {
    std::cout << fpe::kProductName << " " << fpe::engine_version() << " (evaluator revision "
              << fpe::kEvaluatorRevision << ", store format " << fpe::kStoreFormatVersion << ")\n";
    return kExitSuccess;
  }
  if (command == "policy") {
    return command_policy(rest);
  }
  if (command == "store") {
    return command_store(rest);
  }
  if (command == "eval") {
    return command_eval(rest, false);
  }
  if (command == "appraise") {
    return command_eval(rest, true);
  }
  if (command == "decision") {
    return command_decision(rest);
  }
  if (command == "selftest") {
    return command_selftest(rest);
  }
  return report_usage("unrecognized command '" + command + "'");
}

std::vector<std::string> to_utf8_arguments(int argc, const char* const* argv) {
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }
  return arguments;
}

#ifdef _WIN32
std::vector<std::string> to_utf8_arguments(int argc, const wchar_t* const* argv) {
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    const std::u8string utf8 = std::filesystem::path(argv[i]).u8string();
    arguments.emplace_back(reinterpret_cast<const char*>(utf8.data()), utf8.size());
  }
  return arguments;
}
#endif

}  // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) { return run(to_utf8_arguments(argc, argv)); }
#else
int main(int argc, char** argv) { return run(to_utf8_arguments(argc, argv)); }
#endif
