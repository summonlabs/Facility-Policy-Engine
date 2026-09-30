#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "fpe/policy.hpp"
#include "fpe/version.hpp"

namespace fpe {
namespace {

Status schema_error(std::string_view path, std::string message) {
  return Status::failure(ErrorCode::PolicySchema, std::string(path) + ": " + std::move(message));
}

Status limit_error(std::string_view what, std::size_t actual, std::uint64_t maximum) {
  return Status::failure(ErrorCode::LimitExceeded, std::string(what) + " (" + std::to_string(actual) +
                                                         ") exceeds the maximum of " +
                                                         std::to_string(maximum));
}

/// Sorts by identity and refuses duplicates, which is what makes the digest of
/// a bundle independent of the order its rules were written in.
template <class T, class Projection>
Status sort_unique(std::vector<T>& items, Projection project, std::string_view what) {
  std::sort(items.begin(), items.end(),
            [&project](const T& a, const T& b) { return project(a) < project(b); });
  for (std::size_t i = 1; i < items.size(); ++i) {
    if (project(items[i - 1]) == project(items[i])) {
      return Status::failure(ErrorCode::DuplicateIdentity,
                             "duplicate " + std::string(what) + " '" + project(items[i]).str() + "'");
    }
  }
  return Status::success();
}

std::string cycle_text(const std::vector<PredicateId>& cycle) {
  std::string out;
  for (std::size_t i = 0; i < cycle.size(); ++i) {
    if (i > 0) {
      out.append(" -> ");
    }
    out.append(cycle[i].str());
  }
  return out;
}

}  // namespace

Result<CanonicalBundle> canonicalize_bundle(Bundle document,
                                            std::vector<std::shared_ptr<const CanonicalBundle>> imports,
                                            const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (document.schema_version != kBundleSchemaVersion) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "bundle schema revision " + std::to_string(document.schema_version) +
                               " is not supported by this build (expected " +
                               std::to_string(kBundleSchemaVersion) + ")");
  }
  if (!document.id.is_set()) {
    return Status::failure(ErrorCode::PolicySchema, "bundle identity is not set");
  }

  if (document.rules.size() > limits.max_rules) {
    return limit_error("bundle rule count", document.rules.size(), limits.max_rules);
  }
  if (document.facts.size() > limits.max_facts) {
    return limit_error("bundle fact count", document.facts.size(), limits.max_facts);
  }
  if (document.predicates.size() > limits.max_predicates) {
    return limit_error("bundle named-predicate count", document.predicates.size(), limits.max_predicates);
  }
  if (document.imports.size() > limits.max_imports) {
    return limit_error("bundle import count", document.imports.size(), limits.max_imports);
  }

  auto imports_status =
      sort_unique(document.imports, [](const ImportDecl& entry) -> const BundleId& { return entry.bundle; },
                  "import");
  if (!imports_status.ok()) {
    return imports_status;
  }
  for (const auto& entry : document.imports) {
    if (entry.bundle == document.id) {
      return Status::failure(ErrorCode::ImportConflict,
                             "bundle '" + document.id.str() + "' imports itself");
    }
    if (entry.digest.is_zero()) {
      return Status::failure(ErrorCode::ImportConflict, "bundle '" + document.id.str() + "' imports '" +
                                                            entry.bundle.str() +
                                                            "' at the reserved all-zero digest");
    }
  }

  auto facts_status =
      sort_unique(document.facts, [](const FactDecl& entry) -> const FactKey& { return entry.key; },
                  "fact declaration");
  if (!facts_status.ok()) {
    return facts_status;
  }
  auto predicates_status =
      sort_unique(document.predicates,
                  [](const NamedPredicate& entry) -> const PredicateId& { return entry.id; },
                  "named predicate");
  if (!predicates_status.ok()) {
    return predicates_status;
  }
  auto rules_status =
      sort_unique(document.rules, [](const Rule& entry) -> const RuleId& { return entry.id; }, "rule");
  if (!rules_status.ok()) {
    return rules_status;
  }

  for (auto& rule : document.rules) {
    if (!rule.reason.is_set()) {
      return schema_error("rules." + rule.id.str(), "rule reason code is not set");
    }
    if (rule.obligations.size() > limits.max_obligations_per_rule) {
      return limit_error("rule '" + rule.id.str() + "' obligation count", rule.obligations.size(),
                         limits.max_obligations_per_rule);
    }
    if (rule.prerequisites.size() > limits.max_facts) {
      return limit_error("rule '" + rule.id.str() + "' prerequisite count", rule.prerequisites.size(),
                         limits.max_facts);
    }
    std::sort(rule.obligations.begin(), rule.obligations.end());
    rule.obligations.erase(std::unique(rule.obligations.begin(), rule.obligations.end()),
                           rule.obligations.end());
    std::sort(rule.prerequisites.begin(), rule.prerequisites.end());
    rule.prerequisites.erase(std::unique(rule.prerequisites.begin(), rule.prerequisites.end()),
                             rule.prerequisites.end());
  }

  PolicyIndex closure;
  if (auto added = closure.add(document); !added.ok()) {
    return added;
  }
  for (const auto& imported : imports) {
    if (imported == nullptr) {
      return Status::failure(ErrorCode::InternalError, "null bundle supplied as a resolved import");
    }
    if (auto merged = closure.merge(imported->declaration_closure()); !merged.ok()) {
      return merged;
    }
  }

  for (const auto& rule : document.rules) {
    for (const auto& key : rule.prerequisites) {
      if (closure.facts.find(key) == closure.facts.end()) {
        return Status::failure(ErrorCode::UnknownReference,
                               "rule '" + rule.id.str() + "' requires fact '" + key.str() +
                                   "', which no resolved bundle declares");
      }
    }
  }

  if (auto conditions = validate_bundle_conditions(document, closure, limits); !conditions.ok()) {
    return conditions;
  }

  auto cycle = find_predicate_cycle(document);
  if (!cycle) {
    return cycle.status();
  }
  if (!cycle.value().empty()) {
    return Status::failure(ErrorCode::CycleDetected,
                           "named predicate reference cycle: " + cycle_text(cycle.value()));
  }

  std::vector<ImportDecl> resolved;
  resolved.reserve(imports.size());
  for (const auto& imported : imports) {
    ImportDecl entry;
    entry.bundle = imported->id();
    entry.digest = imported->digest();
    resolved.push_back(std::move(entry));
  }
  std::sort(resolved.begin(), resolved.end(),
            [](const ImportDecl& a, const ImportDecl& b) { return a.bundle < b.bundle; });

  if (resolved.size() != document.imports.size()) {
    return Status::failure(ErrorCode::ImportConflict,
                           "bundle '" + document.id.str() + "' declares " +
                               std::to_string(document.imports.size()) +
                               " import(s) but " + std::to_string(resolved.size()) +
                               " resolved bundle(s) were supplied");
  }
  for (std::size_t i = 0; i < resolved.size(); ++i) {
    if (!(resolved[i].bundle == document.imports[i].bundle)) {
      return Status::failure(ErrorCode::ImportConflict,
                             "bundle '" + document.id.str() + "' declares an import of '" +
                                 document.imports[i].bundle.str() + "' but the resolved bundle at that "
                                 "position is '" + resolved[i].bundle.str() + "'");
    }
    if (!(resolved[i].digest == document.imports[i].digest)) {
      return Status::failure(ErrorCode::IncompatibleBundle,
                             "bundle '" + document.id.str() + "' imports '" + resolved[i].bundle.str() +
                                 "' at digest " + document.imports[i].digest.to_hex() +
                                 ", but the supplied document has digest " + resolved[i].digest.to_hex());
    }
  }

  CanonicalBundle canonical;
  canonical.bundle_ = std::move(document);
  canonical.resolved_imports_ = std::move(resolved);
  canonical.imports_ = std::move(imports);
  canonical.closure_ = std::move(closure);
  canonical.document_ = bundle_to_json(canonical.bundle_);
  canonical.canonical_bytes_ = to_canonical_json(canonical.document_);
  if (canonical.canonical_bytes_.size() > limits.max_bundle_bytes) {
    return limit_error("canonical bundle size", canonical.canonical_bytes_.size(), limits.max_bundle_bytes);
  }
  canonical.digest_ = Digest256::of(canonical.canonical_bytes_);
  return canonical;
}

Result<CanonicalBundle> compile_standalone_bundle(Bundle document, const Limits& limits) {
  if (!document.imports.empty()) {
    return Status::failure(ErrorCode::ImportConflict,
                           "bundle '" + document.id.str() +
                               "' declares imports; compile it through BundleCompiler so that every "
                               "dependency is resolved explicitly");
  }
  return canonicalize_bundle(std::move(document), std::vector<std::shared_ptr<const CanonicalBundle>>{},
                             limits);
}

/// The bundle and every transitive import, in deterministic topological order
/// with dependencies before dependents.
std::vector<const CanonicalBundle*> policy_set_closure(const CanonicalBundle& root) {
  std::map<const CanonicalBundle*, std::vector<const CanonicalBundle*>> edges;
  const auto edges_for = [&edges](const CanonicalBundle* node) -> const std::vector<const CanonicalBundle*>& {
    const auto found = edges.find(node);
    if (found != edges.end()) {
      return found->second;
    }
    std::vector<const CanonicalBundle*> list;
    list.reserve(node->imports().size());
    for (const auto& dependency : node->imports()) {
      list.push_back(dependency.get());
    }
    std::sort(list.begin(), list.end(),
              [](const CanonicalBundle* a, const CanonicalBundle* b) { return a->id() < b->id(); });
    return edges.emplace(node, std::move(list)).first->second;
  };

  struct Frame {
    const CanonicalBundle* node;
    std::size_t next;
  };
  std::vector<const CanonicalBundle*> ordered;
  std::set<const CanonicalBundle*> emitted;
  std::set<const CanonicalBundle*> active;
  std::vector<Frame> stack;
  active.insert(&root);
  stack.push_back(Frame{&root, 0});
  while (!stack.empty()) {
    const CanonicalBundle* node = stack.back().node;
    const std::vector<const CanonicalBundle*>& children = edges_for(node);
    if (stack.back().next >= children.size()) {
      stack.pop_back();
      active.erase(node);
      if (emitted.insert(node).second) {
        ordered.push_back(node);
      }
      continue;
    }
    const CanonicalBundle* child = children[stack.back().next];
    stack.back().next += 1;
    if (emitted.find(child) != emitted.end()) {
      continue;
    }
    if (active.find(child) != active.end()) {
      continue;
    }
    active.insert(child);
    stack.push_back(Frame{child, 0});
  }
  return ordered;
}

BundleCompiler::BundleCompiler(Limits limits) : limits_(std::move(limits)) {}

Status BundleCompiler::provide(Bundle document) {
  if (!document.id.is_set()) {
    return Status::failure(ErrorCode::PolicySchema, "supplied bundle document has no bundle identity");
  }
  if (documents_.find(document.id) != documents_.end()) {
    return Status::failure(ErrorCode::AlreadyExists,
                           "a document for bundle '" + document.id.str() + "' was already supplied");
  }
  documents_.emplace(document.id, std::move(document));
  return Status::success();
}

Result<std::shared_ptr<const CanonicalBundle>> BundleCompiler::compile(const BundleId& id) {
  if (auto limits_failure = validate_limits(limits_); !limits_failure.ok()) {
    return limits_failure;
  }
  std::vector<BundleId> stack;
  return compile_inner(id, stack);
}

Result<std::shared_ptr<const CanonicalBundle>> BundleCompiler::compile_inner(const BundleId& id,
                                                                             std::vector<BundleId>& stack) {
  const auto cached = compiled_.find(id);
  if (cached != compiled_.end()) {
    return cached->second;
  }
  for (const BundleId& active : stack) {
    if (active == id) {
      std::string path;
      for (const BundleId& entry : stack) {
        path.append(entry.str());
        path.append(" -> ");
      }
      path.append(id.str());
      return Status::failure(ErrorCode::CycleDetected, "policy bundle import cycle: " + path);
    }
  }
  const auto document = documents_.find(id);
  if (document == documents_.end()) {
    return Status::failure(ErrorCode::NotFound, "no policy document was supplied for bundle '" + id.str() + "'");
  }

  // A copy keeps the supplied document intact, so a failed compile can be
  // retried after the caller supplies the missing dependency.
  const Bundle source = document->second;
  stack.push_back(id);

  std::vector<std::shared_ptr<const CanonicalBundle>> imports;
  imports.reserve(source.imports.size());

  Status failure = Status::success();
  for (const auto& entry : source.imports) {
    auto imported = compile_inner(entry.bundle, stack);
    if (!imported) {
      failure = imported.status();
      break;
    }
    if (!(imported.value()->digest() == entry.digest)) {
      failure = Status::failure(ErrorCode::IncompatibleBundle,
                                "bundle '" + id.str() + "' imports '" + entry.bundle.str() + "' at digest " +
                                    entry.digest.to_hex() + ", but the supplied document for '" +
                                    entry.bundle.str() + "' compiles to digest " +
                                    imported.value()->digest().to_hex());
      break;
    }
    imports.push_back(imported.value());
  }
  stack.pop_back();
  if (!failure.ok()) {
    return failure;
  }

  auto canonical = canonicalize_bundle(source, imports, limits_);
  if (!canonical) {
    return canonical.status();
  }
  auto stored = std::make_shared<const CanonicalBundle>(std::move(canonical).value());
  compiled_.emplace(id, stored);
  return stored;
}

}  // namespace fpe
