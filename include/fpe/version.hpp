#ifndef FPE_VERSION_HPP
#define FPE_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace fpe {

/// Product version of the Facility Policy Engine runtime.
inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// Product name, used in CLI banners and diagnostics.
inline constexpr std::string_view kProductName = "Facility Policy Engine";

/// Semantic revision of the *evaluator*.
///
/// This value changes only when evaluation semantics change in a way that could
/// produce a different outcome for the same canonical policy and the same
/// inputs. Decision artifacts carry it so a consumer can detect that a decision
/// was produced by a different evaluator revision than the one it was written
/// against.
inline constexpr std::uint32_t kEvaluatorRevision = 1;

/// Revision of the durable store format family. Every persisted record carries
/// its own format version; this constant identifies the family this build
/// writes.
inline constexpr std::uint32_t kStoreFormatVersion = 1;

/// Revision of the canonical decision-artifact schema.
inline constexpr std::uint32_t kArtifactSchemaVersion = 1;

/// Revision of the canonical policy-bundle schema.
inline constexpr std::uint32_t kBundleSchemaVersion = 1;

/// Revision of the canonical policy input-set schema.
inline constexpr std::uint32_t kInputSchemaVersion = 1;

/// Revision of the canonical policy-set document a store publishes. A published
/// generation is self-contained: it carries the root bundle and every bundle it
/// imports, so a later reader needs no separate resolution step.
inline constexpr std::uint32_t kPolicySetSchemaVersion = 1;

/// Revision of the out-of-band anchor document.
inline constexpr std::uint32_t kAnchorSchemaVersion = 1;

/// "major.minor.patch" of this build.
std::string_view engine_version();

}  // namespace fpe

#endif  // FPE_VERSION_HPP
