#ifndef FPE_STORE_HPP
#define FPE_STORE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/digest.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe {

/// Every fixed size, tag, and name of the durable store format.
///
/// Nothing here is inferred at run time: a reader validates the magic, the
/// format version, the record kind, the declared length, the checksum, and the
/// digest before it interprets a single field, so bytes from another format can
/// never be read as if they were this one.
struct StoreFormat {
  static constexpr std::string_view kManifestName = "MANIFEST.bin";
  static constexpr std::string_view kLockName = "LOCK";
  static constexpr std::string_view kGenerationDirectory = "gen";
  static constexpr std::string_view kGenerationSuffix = ".fpg";

  static constexpr std::uint32_t kManifestVersion = 1;
  static constexpr std::uint32_t kRecordVersion = 1;
  static constexpr std::uint32_t kManifestKind = 2;
  static constexpr std::uint32_t kRecordKind = 1;

  /// Fixed manifest size: no payload, so its length is itself a format check.
  static constexpr std::size_t kManifestBytes = 184;
  /// Fixed generation-record header size; the payload follows immediately.
  static constexpr std::size_t kRecordHeaderBytes = 184;
  static constexpr std::size_t kStoreIdBytes = 16;
  static constexpr std::size_t kMaxPathBytes = 4096;
};

/// Durable identity of one store directory.
///
/// Created once when the store is created, never derived from the path, the
/// host, or the user, and never an input to a decision. It exists so that an
/// anchor or a copied directory can be told apart from the store it claims to
/// be.
class StoreId {
 public:
  constexpr StoreId() noexcept = default;

  static StoreId from_bytes(const std::array<std::byte, StoreFormat::kStoreIdBytes>& bytes) noexcept;

  const std::array<std::byte, StoreFormat::kStoreIdBytes>& bytes() const noexcept { return bytes_; }
  bool is_zero() const noexcept;
  std::string to_hex() const;

  friend bool operator==(const StoreId& a, const StoreId& b) noexcept { return a.bytes_ == b.bytes_; }
  friend std::strong_ordering operator<=>(const StoreId& a, const StoreId& b) noexcept {
    return a.bytes_ <=> b.bytes_;
  }

 private:
  std::array<std::byte, StoreFormat::kStoreIdBytes> bytes_{};
};

/// Verified head of a store.
///
/// Generation zero means nothing has been published yet. That is a real state,
/// not an error, and it is never confused with "policy is empty": readers report
/// has_policy() == false and refuse to evaluate.
struct StoreHead {
  StoreId store_id;
  Generation generation;
  /// The incarnation that currently owns this store. It advances every time a
  /// writer opens the store — including an open that publishes nothing — so a
  /// decision produced under an earlier incarnation is fenced even when the
  /// policy itself did not change.
  Epoch control_epoch;
  Sequence sequence;
  Generation floor_generation;
  Digest256 manifest_digest;
  Digest256 record_digest;
  Digest256 bundle_digest;
};

/// Verified metadata of one published generation.
struct GenerationInfo {
  StoreId store_id;
  Generation generation;
  Sequence sequence;
  Epoch control_epoch;
  TimestampNanos created_at;
  Digest256 record_digest;
  Digest256 prev_record_digest;
  Digest256 bundle_digest;
  std::uint64_t payload_bytes = 0;
};

/// An out-of-band record of how far a store had advanced.
///
/// A store directory that is rolled back in its entirety is internally
/// consistent, so nothing inside it can reveal the rollback. An anchor kept
/// outside the store is what makes that detectable, and check_anchor is what
/// enforces it. Without an anchor, the store can only prove internal
/// consistency, and the documentation says so rather than implying otherwise.
struct StoreAnchor {
  StoreId store_id;
  Generation generation;
  Sequence sequence;
  Digest256 manifest_digest;
};

struct StoreReaderState;
struct StoreWriterState;

/// A verified, immutable read view of a store.
///
/// Opening a reader takes no lock and advances nothing, so any number of
/// processes may read concurrently with a writer. A reader observes either the
/// generation that was current when it opened, or (after refresh) a later one:
/// the manifest is replaced atomically, so a partially written generation is
/// never visible.
class StoreReader {
 public:
  StoreReader() noexcept;
  ~StoreReader();
  StoreReader(StoreReader&& other) noexcept;
  StoreReader& operator=(StoreReader&& other) noexcept;
  StoreReader(const StoreReader&) = delete;
  StoreReader& operator=(const StoreReader&) = delete;

  /// A copy of the verified head. Returned by value on purpose: a reference
  /// would let a caller hold a view across refresh() and silently observe a
  /// different, or partially updated, generation.
  StoreHead head() const noexcept;
  bool has_policy() const noexcept;
  bool is_open() const noexcept;

  /// Re-reads and re-verifies the manifest, picking up a generation published
  /// since this reader was opened.
  Status refresh();

  /// Parses and verifies the published policy set. The result is cached; a
  /// failure is remembered and reported identically on every call.
  Result<const CanonicalBundle*> policy();

  /// The policy state a consumer should trust right now, for fencing. Fails
  /// with StoreEmpty when nothing has been published yet.
  Result<CurrentPolicy> current_policy();

  /// Verifies the manifest's generation record and, from there, every earlier
  /// generation record still present, as far as \\p max_records.
  Status verify_history(std::uint32_t max_records, std::vector<GenerationInfo>& history);

  const std::filesystem::path& root() const noexcept;

 private:
  friend Result<StoreReader> open_reader(const std::filesystem::path& root, const Limits& limits);
  friend Status check_anchor(const StoreReader& reader, const StoreAnchor& anchor);

  std::unique_ptr<StoreReaderState> state_;
};

/// The single writer of a store.
///
/// Holding a writer means holding the operating system's exclusive lock on the
/// store's lock file. A second writer in this or any other process fails with
/// LockHeld; a writer that dies releases the lock because the kernel releases it
/// with the process, so a crash never leaves the store permanently unwritable.
class StoreWriter {
 public:
  StoreWriter() noexcept;
  ~StoreWriter();
  StoreWriter(StoreWriter&& other) noexcept;
  StoreWriter& operator=(StoreWriter&& other) noexcept;
  StoreWriter(const StoreWriter&) = delete;
  StoreWriter& operator=(const StoreWriter&) = delete;

  /// A copy of the current head, for the same reason as StoreReader::head.
  StoreHead head() const noexcept;
  bool is_open() const noexcept;
  const std::filesystem::path& root() const noexcept;

  /// Publishes \\p bundle as the next policy generation.
  ///
  /// The bundle and every bundle it imports are written into the generation
  /// record, so the published generation is self-contained. The commit point is
  /// the atomic replacement of the manifest: before it the store still reports
  /// the previous generation, after it the new generation is authoritative.
  Result<Generation> publish(const CanonicalBundle& bundle);

  /// Raises the rollback floor. A later open refuses a manifest whose
  /// generation is below the floor, which turns a detected rollback into a
  /// refusal instead of a silent downgrade.
  Status raise_floor(Generation floor);

  /// Rebuilds the manifest from one generation record that verifies completely.
  ///
  /// This is the only recovery path, and it never guesses: the operator names
  /// the generation, and the record and its predecessor link must verify before
  /// the manifest is replaced.
  Status recover_to(Generation generation);

  /// Releases the writer lock. Idempotent.
  void close() noexcept;

 private:
  friend Result<StoreWriter> open_writer(const std::filesystem::path& root, const Limits& limits);

  std::unique_ptr<StoreWriterState> state_;
};

/// Creates a store directory. Refuses to touch an existing store.
Result<StoreHead> create_store(const std::filesystem::path& root, const Limits& limits);

/// Opens a reader. Never creates, never locks, never advances anything.
Result<StoreReader> open_reader(const std::filesystem::path& root, const Limits& limits);

/// Opens the writer: takes the exclusive lock and advances the control epoch so
/// that every decision produced under the previous incarnation is fenced.
Result<StoreWriter> open_writer(const std::filesystem::path& root, const Limits& limits);

/// Reads an anchor document.
Result<StoreAnchor> read_anchor(const std::filesystem::path& path, const Limits& limits);

/// Writes an anchor document, staged, flushed, read back, and atomically
/// replaced.
Status write_anchor(const std::filesystem::path& path, const StoreAnchor& anchor, const Limits& limits);

/// Refuses when the store has gone backwards relative to \\p anchor.
Status check_anchor(const StoreReader& reader, const StoreAnchor& anchor);

/// Canonical JSON form of an anchor document.
JsonValue anchor_to_json(const StoreAnchor& anchor);

}  // namespace fpe

#endif  // FPE_STORE_HPP
