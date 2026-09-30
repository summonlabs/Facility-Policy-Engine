#ifndef FPE_LIMITS_HPP
#define FPE_LIMITS_HPP

#include <cstdint>

#include "fpe/status.hpp"

namespace fpe {

/// Absolute ceilings that no caller, configuration file, or policy bundle can
/// raise. Every bound in this table exists to make adversarial policy bundles
/// and hostile inputs cost-bounded.
///
/// The distinction between \ref Limits and \ref HardCaps is the security
/// property: Limits may be lowered per evaluation, HardCaps may not be raised
/// by anyone.
struct HardCaps {
  static constexpr std::uint32_t kImports = 256;
  static constexpr std::uint32_t kImportDepth = 32;
  static constexpr std::uint32_t kRules = 65536;
  static constexpr std::uint32_t kFacts = 65536;
  static constexpr std::uint32_t kPredicates = 16384;
  static constexpr std::uint32_t kConditionDepth = 64;
  static constexpr std::uint32_t kConditionNodes = 65536;
  static constexpr std::uint32_t kCollectionItems = 4096;
  static constexpr std::uint32_t kObligationsPerRule = 64;
  static constexpr std::uint32_t kExplanationEntries = 65536;
  static constexpr std::uint64_t kEvaluationSteps = 100000000ull;
  static constexpr std::uint64_t kBundleBytes = 64ull * 1024ull * 1024ull;
  static constexpr std::uint32_t kInputFacts = 65536;
  static constexpr std::uint32_t kTextBytes = 4096;
  static constexpr std::uint32_t kIdentifierBytes = 256;
  static constexpr std::uint32_t kJsonDepth = 128;
  static constexpr std::uint32_t kJsonNodes = 1000000;
  static constexpr std::uint64_t kArtifactBytes = 256ull * 1024ull * 1024ull;
  static constexpr std::uint32_t kStoreListing = 1000000;
  static constexpr std::uint64_t kRecordPayloadBytes = 64ull * 1024ull * 1024ull;
};

/// Effective bounds for one operation.
///
/// Defaults are deliberately far below the hard caps so that the common path is
/// cheap, while still being large enough for real facility policy sets.
struct Limits {
  std::uint32_t max_imports = 64;
  std::uint32_t max_import_depth = 16;
  std::uint32_t max_rules = 4096;
  std::uint32_t max_facts = 4096;
  std::uint32_t max_predicates = 1024;
  std::uint32_t max_condition_depth = 24;
  std::uint32_t max_condition_nodes = 8192;
  std::uint32_t max_collection_items = 256;
  std::uint32_t max_obligations_per_rule = 16;
  std::uint32_t max_explanation_entries = 8192;
  std::uint64_t max_evaluation_steps = 2000000ull;
  std::uint64_t max_bundle_bytes = 8ull * 1024ull * 1024ull;
  std::uint32_t max_input_facts = 8192;
  std::uint32_t max_text_bytes = 512;
  std::uint32_t max_identifier_bytes = 128;
  std::uint32_t max_json_depth = 48;
  std::uint32_t max_json_nodes = 200000;
  std::uint64_t max_artifact_bytes = 16ull * 1024ull * 1024ull;
  std::uint32_t max_store_listing = 100000;
  std::uint64_t max_record_payload_bytes = 8ull * 1024ull * 1024ull;

  static Limits defaults() noexcept { return Limits{}; }
  static Limits hard_caps() noexcept;
};

/// Rejects limits that exceed \ref HardCaps or that are internally
/// inconsistent (for example a maximum depth above the maximum node count).
Status validate_limits(const Limits& limits);

}  // namespace fpe

#endif  // FPE_LIMITS_HPP
