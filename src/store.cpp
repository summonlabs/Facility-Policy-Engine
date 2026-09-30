#include "fpe/store.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "platform.hpp"
#include "fpe/version.hpp"

namespace fpe {
namespace {

constexpr char kManifestMagic[8] = {'F', 'P', 'E', 'M', 'A', 'N', 'I', '1'};
constexpr char kRecordMagic[8] = {'F', 'P', 'E', 'G', 'E', 'N', '0', '1'};

// Manifest field offsets. The layout is fixed and exact; every offset below is
// used with a length that has already been validated against kManifestBytes.
constexpr std::size_t kManifestMagicOffset = 0;
constexpr std::size_t kManifestVersionOffset = 8;
constexpr std::size_t kManifestKindOffset = 12;
constexpr std::size_t kManifestStoreIdOffset = 16;
constexpr std::size_t kManifestGenerationOffset = 32;
constexpr std::size_t kManifestEpochOffset = 40;
constexpr std::size_t kManifestSequenceOffset = 48;
constexpr std::size_t kManifestFloorOffset = 56;
constexpr std::size_t kManifestRecordDigestOffset = 64;
constexpr std::size_t kManifestBundleDigestOffset = 96;
constexpr std::size_t kManifestPayloadLengthOffset = 128;
constexpr std::size_t kManifestReservedOffset = 136;
constexpr std::size_t kManifestPayloadCrcOffset = 144;
constexpr std::size_t kManifestHeaderCrcOffset = 148;
constexpr std::size_t kManifestDigestOffset = 152;

// Generation record field offsets.
constexpr std::size_t kRecordMagicOffset = 0;
constexpr std::size_t kRecordVersionOffset = 8;
constexpr std::size_t kRecordKindOffset = 12;
constexpr std::size_t kRecordStoreIdOffset = 16;
constexpr std::size_t kRecordGenerationOffset = 32;
constexpr std::size_t kRecordSequenceOffset = 40;
constexpr std::size_t kRecordEpochOffset = 48;
constexpr std::size_t kRecordCreatedOffset = 56;
constexpr std::size_t kRecordPrevDigestOffset = 64;
constexpr std::size_t kRecordBundleDigestOffset = 96;
constexpr std::size_t kRecordPayloadLengthOffset = 128;
constexpr std::size_t kRecordReservedOffset = 136;
constexpr std::size_t kRecordPayloadCrcOffset = 144;
constexpr std::size_t kRecordHeaderCrcOffset = 148;
constexpr std::size_t kRecordDigestOffset = 152;

void put_u32(std::byte* out, std::uint32_t value) noexcept {
  for (std::size_t i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (8u * i)) & 0xFFu);
  }
}

void put_u64(std::byte* out, std::uint64_t value) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::byte>((value >> (8u * i)) & 0xFFu);
  }
}

std::uint32_t get_u32(const std::byte* in) noexcept {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<unsigned>(in[i])) << (8u * i);
  }
  return value;
}

std::uint64_t get_u64(const std::byte* in) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<unsigned>(in[i])) << (8u * i);
  }
  return value;
}

Digest256 get_digest(const std::byte* in) noexcept {
  std::array<std::byte, Digest256::kBytes> bytes{};
  std::memcpy(bytes.data(), in, Digest256::kBytes);
  return Digest256::from_bytes(bytes);
}

void put_digest(std::byte* out, const Digest256& digest) noexcept {
  std::memcpy(out, digest.data(), Digest256::kBytes);
}

std::vector<std::byte> digest_input(const std::byte* prefix, std::size_t prefix_bytes,
                                    const std::vector<std::byte>& payload) {
  std::vector<std::byte> buffer;
  buffer.reserve(prefix_bytes + payload.size());
  buffer.insert(buffer.end(), prefix, prefix + prefix_bytes);
  buffer.insert(buffer.end(), payload.begin(), payload.end());
  return buffer;
}

Status verify_header_checksum(const std::vector<std::byte>& bytes, std::size_t checksum_offset,
                              std::size_t covered_bytes, std::string_view what) {
  const std::uint32_t stored = get_u32(bytes.data() + checksum_offset);
  const std::uint32_t computed = crc32(bytes.data(), covered_bytes);
  if (stored != computed) {
    return Status::failure(ErrorCode::ChecksumMismatch,
                           std::string(what) + " checksum " + std::to_string(stored) +
                               " does not match its contents (" + std::to_string(computed) + ")");
  }
  return Status::success();
}

Status verify_digest(const std::vector<std::byte>& bytes, std::size_t digest_offset, std::size_t covered_bytes,
                     const std::vector<std::byte>& payload, std::string_view what) {
  const Digest256 stored = get_digest(bytes.data() + digest_offset);
  const std::vector<std::byte> hashed = digest_input(bytes.data(), covered_bytes, payload);
  const Digest256 computed = Digest256::of(std::string_view(reinterpret_cast<const char*>(hashed.data()),
                                                           hashed.size()));
  if (!(stored == computed)) {
    return Status::failure(ErrorCode::DigestMismatch,
                           std::string(what) + " digest " + stored.to_hex() +
                               " does not match its contents (" + computed.to_hex() + ")");
  }
  return Status::success();
}

std::string generation_file_name(Generation generation) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string name(16, '0');
  std::uint64_t value = generation.raw();
  for (std::size_t i = 0; i < 16; ++i) {
    name[15 - i] = kDigits[value & 0xFu];
    value >>= 4;
  }
  name.append(StoreFormat::kGenerationSuffix);
  return name;
}

std::filesystem::path manifest_path(const std::filesystem::path& root) {
  return root / std::filesystem::path(StoreFormat::kManifestName);
}

std::filesystem::path lock_path(const std::filesystem::path& root) {
  return root / std::filesystem::path(StoreFormat::kLockName);
}

std::filesystem::path generation_directory(const std::filesystem::path& root) {
  return root / std::filesystem::path(StoreFormat::kGenerationDirectory);
}

std::filesystem::path generation_path(const std::filesystem::path& root, Generation generation) {
  return generation_directory(root) / std::filesystem::path(generation_file_name(generation));
}

/// Encodes a manifest. The digest is over the bytes, so it is not a field that
/// the caller supplies: it is derived here and returned.
std::vector<std::byte> encode_manifest(const StoreHead& head, Digest256& digest_out) {
  std::vector<std::byte> bytes(StoreFormat::kManifestBytes, std::byte{0});
  std::memcpy(bytes.data() + kManifestMagicOffset, kManifestMagic, sizeof(kManifestMagic));
  put_u32(bytes.data() + kManifestVersionOffset, StoreFormat::kManifestVersion);
  put_u32(bytes.data() + kManifestKindOffset, StoreFormat::kManifestKind);
  std::memcpy(bytes.data() + kManifestStoreIdOffset, head.store_id.bytes().data(), StoreFormat::kStoreIdBytes);
  put_u64(bytes.data() + kManifestGenerationOffset, head.generation.raw());
  put_u64(bytes.data() + kManifestEpochOffset, head.control_epoch.raw());
  put_u64(bytes.data() + kManifestSequenceOffset, head.sequence.raw());
  put_u64(bytes.data() + kManifestFloorOffset, head.floor_generation.raw());
  put_digest(bytes.data() + kManifestRecordDigestOffset, head.record_digest);
  put_digest(bytes.data() + kManifestBundleDigestOffset, head.bundle_digest);
  put_u64(bytes.data() + kManifestPayloadLengthOffset, 0);
  put_u64(bytes.data() + kManifestReservedOffset, 0);
  put_u32(bytes.data() + kManifestPayloadCrcOffset, crc32(nullptr, 0));
  put_u32(bytes.data() + kManifestHeaderCrcOffset,
          crc32(bytes.data(), kManifestHeaderCrcOffset));
  // The digest covers every byte that precedes it and nothing else, which is
  // exactly the range the reader re-hashes.
  digest_out = Digest256::of(
      std::string_view(reinterpret_cast<const char*>(bytes.data()), kManifestDigestOffset));
  put_digest(bytes.data() + kManifestDigestOffset, digest_out);
  return bytes;
}

Status decode_manifest(const std::vector<std::byte>& bytes, StoreHead& head) {
  if (bytes.size() < StoreFormat::kManifestBytes) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "manifest is " + std::to_string(bytes.size()) + " bytes, shorter than the fixed " +
                               std::to_string(StoreFormat::kManifestBytes) + "-byte layout");
  }
  if (bytes.size() > StoreFormat::kManifestBytes) {
    return Status::failure(ErrorCode::TrailingBytes,
                           "manifest is " + std::to_string(bytes.size()) + " bytes, longer than the fixed " +
                               std::to_string(StoreFormat::kManifestBytes) + "-byte layout");
  }
  if (std::memcmp(bytes.data() + kManifestMagicOffset, kManifestMagic, sizeof(kManifestMagic)) != 0) {
    return Status::failure(ErrorCode::BadMagic, "manifest does not begin with the store magic");
  }
  const std::uint32_t version = get_u32(bytes.data() + kManifestVersionOffset);
  if (version != StoreFormat::kManifestVersion) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "manifest format version " + std::to_string(version) +
                               " is not supported by this build (expected " +
                               std::to_string(StoreFormat::kManifestVersion) + ")");
  }
  const std::uint32_t kind = get_u32(bytes.data() + kManifestKindOffset);
  if (kind != StoreFormat::kManifestKind) {
    return Status::failure(ErrorCode::WrongRecordKind,
                           "manifest record kind " + std::to_string(kind) + " is not a manifest kind");
  }
  if (auto checksum = verify_header_checksum(bytes, kManifestHeaderCrcOffset, kManifestHeaderCrcOffset,
                                             "manifest header");
      !checksum.ok()) {
    return checksum;
  }
  if (get_u64(bytes.data() + kManifestPayloadLengthOffset) != 0) {
    return Status::failure(ErrorCode::BadDeclaredLength, "manifest must not declare a payload");
  }
  if (get_u64(bytes.data() + kManifestReservedOffset) != 0) {
    return Status::failure(ErrorCode::ReservedNotZero, "manifest reserved field is not zero");
  }
  if (get_u32(bytes.data() + kManifestPayloadCrcOffset) != crc32(nullptr, 0)) {
    return Status::failure(ErrorCode::ChecksumMismatch, "manifest payload checksum is not the empty-payload value");
  }
  if (auto digest = verify_digest(bytes, kManifestDigestOffset, kManifestDigestOffset, {}, "manifest");
      !digest.ok()) {
    return digest;
  }

  StoreHead decoded;
  std::array<std::byte, StoreFormat::kStoreIdBytes> store_id{};
  std::memcpy(store_id.data(), bytes.data() + kManifestStoreIdOffset, StoreFormat::kStoreIdBytes);
  decoded.store_id = StoreId::from_bytes(store_id);
  decoded.generation = Generation::from_raw(get_u64(bytes.data() + kManifestGenerationOffset));
  decoded.control_epoch = Epoch::from_raw(get_u64(bytes.data() + kManifestEpochOffset));
  decoded.sequence = Sequence::from_raw(get_u64(bytes.data() + kManifestSequenceOffset));
  decoded.floor_generation = Generation::from_raw(get_u64(bytes.data() + kManifestFloorOffset));
  decoded.record_digest = get_digest(bytes.data() + kManifestRecordDigestOffset);
  decoded.bundle_digest = get_digest(bytes.data() + kManifestBundleDigestOffset);
  decoded.manifest_digest = get_digest(bytes.data() + kManifestDigestOffset);

  if (decoded.store_id.is_zero()) {
    return Status::failure(ErrorCode::CorruptManifest, "manifest carries the reserved all-zero store identity");
  }
  if (decoded.floor_generation > decoded.generation) {
    return Status::failure(ErrorCode::RollbackDetected,
                           "manifest generation " + std::to_string(decoded.generation.raw()) +
                               " is below its own rollback floor of " +
                               std::to_string(decoded.floor_generation.raw()));
  }
  if (decoded.generation.is_zero()) {
    if (!decoded.record_digest.is_zero() || !decoded.bundle_digest.is_zero()) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "manifest reports no published generation but carries a generation digest");
    }
  } else if (decoded.record_digest.is_zero() || decoded.bundle_digest.is_zero()) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "manifest reports generation " + std::to_string(decoded.generation.raw()) +
                               " without a record or bundle digest");
  }
  head = decoded;
  return Status::success();
}

/// Encodes one generation record. The record digest covers the fixed header and
/// the payload, so a truncated or edited payload cannot verify.
std::vector<std::byte> encode_record(const StoreId& store_id, Generation generation, Sequence sequence,
                                     Epoch epoch, TimestampNanos created_at,
                                     const Digest256& prev_record_digest, const Digest256& bundle_digest,
                                     const std::string& payload, Digest256& record_digest_out) {
  std::vector<std::byte> bytes(StoreFormat::kRecordHeaderBytes, std::byte{0});
  std::memcpy(bytes.data() + kRecordMagicOffset, kRecordMagic, sizeof(kRecordMagic));
  put_u32(bytes.data() + kRecordVersionOffset, StoreFormat::kRecordVersion);
  put_u32(bytes.data() + kRecordKindOffset, StoreFormat::kRecordKind);
  std::memcpy(bytes.data() + kRecordStoreIdOffset, store_id.bytes().data(), StoreFormat::kStoreIdBytes);
  put_u64(bytes.data() + kRecordGenerationOffset, generation.raw());
  put_u64(bytes.data() + kRecordSequenceOffset, sequence.raw());
  put_u64(bytes.data() + kRecordEpochOffset, epoch.raw());
  put_u64(bytes.data() + kRecordCreatedOffset, static_cast<std::uint64_t>(created_at.unix_nanos()));
  put_digest(bytes.data() + kRecordPrevDigestOffset, prev_record_digest);
  put_digest(bytes.data() + kRecordBundleDigestOffset, bundle_digest);
  put_u64(bytes.data() + kRecordPayloadLengthOffset, static_cast<std::uint64_t>(payload.size()));
  put_u64(bytes.data() + kRecordReservedOffset, 0);
  put_u32(bytes.data() + kRecordPayloadCrcOffset, crc32(payload.data(), payload.size()));
  put_u32(bytes.data() + kRecordHeaderCrcOffset, crc32(bytes.data(), kRecordHeaderCrcOffset));
  bytes.insert(bytes.end(), reinterpret_cast<const std::byte*>(payload.data()),
               reinterpret_cast<const std::byte*>(payload.data()) + payload.size());

  // The record digest covers the fixed header up to (not including) the digest
  // field, followed by the payload. The digest field is not covered, so it can
  // be filled in afterwards, and the reader re-hashes exactly these two ranges.
  std::vector<std::byte> hashed;
  hashed.reserve(kRecordDigestOffset + payload.size());
  hashed.insert(hashed.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(kRecordDigestOffset));
  hashed.insert(hashed.end(), bytes.begin() + static_cast<std::ptrdiff_t>(StoreFormat::kRecordHeaderBytes),
                bytes.end());
  record_digest_out =
      Digest256::of(std::string_view(reinterpret_cast<const char*>(hashed.data()), hashed.size()));
  put_digest(bytes.data() + kRecordDigestOffset, record_digest_out);
  return bytes;
}

struct DecodedRecord {
  GenerationInfo info;
  std::string payload;
};

Status decode_record(const std::vector<std::byte>& bytes, DecodedRecord& out) {
  if (bytes.size() < StoreFormat::kRecordHeaderBytes) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "generation record is " + std::to_string(bytes.size()) +
                               " bytes, shorter than the fixed " +
                               std::to_string(StoreFormat::kRecordHeaderBytes) + "-byte header");
  }
  if (std::memcmp(bytes.data() + kRecordMagicOffset, kRecordMagic, sizeof(kRecordMagic)) != 0) {
    return Status::failure(ErrorCode::BadMagic, "generation record does not begin with the record magic");
  }
  const std::uint32_t version = get_u32(bytes.data() + kRecordVersionOffset);
  if (version != StoreFormat::kRecordVersion) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "generation record format version " + std::to_string(version) +
                               " is not supported by this build (expected " +
                               std::to_string(StoreFormat::kRecordVersion) + ")");
  }
  const std::uint32_t kind = get_u32(bytes.data() + kRecordKindOffset);
  if (kind != StoreFormat::kRecordKind) {
    return Status::failure(ErrorCode::WrongRecordKind,
                           "generation record kind " + std::to_string(kind) +
                               " is not a generation-record kind");
  }
  const std::uint64_t declared_payload = get_u64(bytes.data() + kRecordPayloadLengthOffset);
  const std::uint64_t expected =
      static_cast<std::uint64_t>(StoreFormat::kRecordHeaderBytes) + declared_payload;
  if (static_cast<std::uint64_t>(bytes.size()) < expected) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "generation record declares " + std::to_string(declared_payload) +
                               " payload bytes but only " + std::to_string(bytes.size()) +
                               " bytes are present");
  }
  if (static_cast<std::uint64_t>(bytes.size()) > expected) {
    return Status::failure(ErrorCode::TrailingBytes,
                           "generation record carries " + std::to_string(bytes.size() - expected) +
                               " bytes beyond its declared payload length");
  }
  if (auto checksum = verify_header_checksum(bytes, kRecordHeaderCrcOffset, kRecordHeaderCrcOffset,
                                             "generation record header");
      !checksum.ok()) {
    return checksum;
  }
  const std::vector<std::byte> payload(bytes.begin() + static_cast<std::ptrdiff_t>(StoreFormat::kRecordHeaderBytes),
                                       bytes.end());
  const std::uint32_t stored_payload_crc = get_u32(bytes.data() + kRecordPayloadCrcOffset);
  const std::uint32_t computed_payload_crc = crc32(payload.data(), payload.size());
  if (stored_payload_crc != computed_payload_crc) {
    return Status::failure(ErrorCode::ChecksumMismatch,
                           "generation record payload checksum " + std::to_string(stored_payload_crc) +
                               " does not match its contents (" + std::to_string(computed_payload_crc) + ")");
  }
  if (auto digest = verify_digest(bytes, kRecordDigestOffset, kRecordDigestOffset, payload,
                                  "generation record");
      !digest.ok()) {
    return digest;
  }
  if (get_u64(bytes.data() + kRecordReservedOffset) != 0) {
    return Status::failure(ErrorCode::ReservedNotZero, "generation record reserved field is not zero");
  }

  DecodedRecord decoded;
  std::array<std::byte, StoreFormat::kStoreIdBytes> store_id{};
  std::memcpy(store_id.data(), bytes.data() + kRecordStoreIdOffset, StoreFormat::kStoreIdBytes);
  decoded.info.store_id = StoreId::from_bytes(store_id);
  if (decoded.info.store_id.is_zero()) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "generation record carries the reserved all-zero store identity");
  }
  decoded.info.generation = Generation::from_raw(get_u64(bytes.data() + kRecordGenerationOffset));
  decoded.info.sequence = Sequence::from_raw(get_u64(bytes.data() + kRecordSequenceOffset));
  decoded.info.control_epoch = Epoch::from_raw(get_u64(bytes.data() + kRecordEpochOffset));
  decoded.info.created_at =
      TimestampNanos::from_unix_nanos(static_cast<std::int64_t>(get_u64(bytes.data() + kRecordCreatedOffset)));
  decoded.info.prev_record_digest = get_digest(bytes.data() + kRecordPrevDigestOffset);
  decoded.info.bundle_digest = get_digest(bytes.data() + kRecordBundleDigestOffset);
  decoded.info.payload_bytes = declared_payload;
  decoded.info.record_digest = get_digest(bytes.data() + kRecordDigestOffset);
  decoded.payload.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
  out = std::move(decoded);
  return Status::success();
}

Status read_and_decode_record(const std::filesystem::path& path, const Limits& limits, DecodedRecord& out) {
  const std::uint64_t bound =
      static_cast<std::uint64_t>(StoreFormat::kRecordHeaderBytes) + limits.max_record_payload_bytes + 1;
  auto bytes = platform::read_file(path, bound);
  if (!bytes) {
    return bytes.status();
  }
  return decode_record(bytes.value(), out);
}

}  // namespace

// ---- Store identity --------------------------------------------------------

StoreId StoreId::from_bytes(const std::array<std::byte, StoreFormat::kStoreIdBytes>& bytes) noexcept {
  StoreId id;
  id.bytes_ = bytes;
  return id;
}

bool StoreId::is_zero() const noexcept {
  for (const std::byte byte : bytes_) {
    if (byte != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::string StoreId::to_hex() const { return fpe::to_hex(bytes_.data(), bytes_.size()); }

namespace {

/// Stage, flush, read back, and atomically publish one file.
///
/// This is the only way any durable file in a store is written, so the commit
/// point is the same everywhere: the atomic replacement at the end. A crash
/// before it leaves the previous file exactly as it was, plus at most one
/// abandoned staging file.
Status write_file_atomically(const std::filesystem::path& target, const std::vector<std::byte>& bytes,
                             std::string_view tag) {
  const std::filesystem::path staging = platform::temporary_sibling(target, tag);
  if (auto cleared = platform::remove_file(staging); !cleared.ok()) {
    return cleared;
  }
  auto handle = platform::create_exclusive(staging);
  if (!handle) {
    return handle.status();
  }
  if (auto written = platform::write_all(handle.value(), bytes.data(), bytes.size()); !written.ok()) {
    handle.value().close();
    platform::remove_file(staging);
    return written;
  }
  if (auto flushed = platform::flush_file(handle.value()); !flushed.ok()) {
    handle.value().close();
    platform::remove_file(staging);
    return flushed;
  }
  handle.value().close();

  const std::uint64_t bound = static_cast<std::uint64_t>(bytes.size()) + 1;
  auto read_back = platform::read_file(staging, bound);
  if (!read_back) {
    platform::remove_file(staging);
    return read_back.status();
  }
  if (!(read_back.value() == bytes)) {
    platform::remove_file(staging);
    return Status::failure(ErrorCode::ReadBackMismatch,
                           "the staged file '" + platform::path_text(staging) +
                               "' did not read back exactly as it was written");
  }
  if (auto replaced = platform::atomic_replace(staging, target); !replaced.ok()) {
    platform::remove_file(staging);
    return replaced;
  }
  return Status::success();
}

Status write_manifest_file(const std::filesystem::path& root, StoreHead& head) {
  Digest256 digest;
  const std::vector<std::byte> bytes = encode_manifest(head, digest);
  if (auto written = write_file_atomically(manifest_path(root), bytes, "manifest"); !written.ok()) {
    return written;
  }
  head.manifest_digest = digest;
  return Status::success();
}

Status load_manifest(const std::filesystem::path& root, StoreHead& head) {
  const std::uint64_t bound = static_cast<std::uint64_t>(StoreFormat::kManifestBytes) + 4096;
  auto bytes = platform::read_file(manifest_path(root), bound);
  if (!bytes) {
    return bytes.status();
  }
  return decode_manifest(bytes.value(), head);
}

/// Reads the generation record the manifest names and checks that the record
/// agrees with every field the manifest claims about it.
Status load_current_record(const std::filesystem::path& root, const StoreHead& head, const Limits& limits,
                           DecodedRecord& out) {
  if (head.generation.is_zero()) {
    return Status::failure(ErrorCode::StoreEmpty, "this store has no published policy generation");
  }
  if (auto status = read_and_decode_record(generation_path(root, head.generation), limits, out); !status.ok()) {
    return status;
  }
  if (!(out.info.generation == head.generation)) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "generation record names generation " + std::to_string(out.info.generation.raw()) +
                               " but the manifest names " + std::to_string(head.generation.raw()));
  }
  if (!(out.info.sequence == head.sequence)) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "generation record names publication sequence " +
                               std::to_string(out.info.sequence.raw()) + " but the manifest names " +
                               std::to_string(head.sequence.raw()));
  }
  // The record's control epoch is the incarnation it was published under; the
  // manifest's is the current incarnation. They differ legitimately once a new
  // writer opens the store, so the record's epoch is provenance, not an
  // equality check.
  if (!(out.info.store_id == head.store_id)) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "generation record belongs to store " + out.info.store_id.to_hex() +
                               " but the manifest names store " + head.store_id.to_hex());
  }
  if (!(out.info.record_digest == head.record_digest)) {
    return Status::failure(ErrorCode::DigestMismatch,
                           "generation record digest " + out.info.record_digest.to_hex() +
                               " does not match the manifest digest " + head.record_digest.to_hex());
  }
  if (!(out.info.bundle_digest == head.bundle_digest)) {
    return Status::failure(ErrorCode::DigestMismatch,
                           "generation record policy digest " + out.info.bundle_digest.to_hex() +
                               " does not match the manifest digest " + head.bundle_digest.to_hex());
  }
  return Status::success();
}

/// Highest control epoch any generation record in this store names.
///
/// Used only by recovery: the rebuilt manifest must publish a control epoch
/// strictly newer than every epoch that has ever been durable, so that no
/// decision produced before the recovery can be mistaken for a current one.
Status highest_published_epoch(const std::filesystem::path& root, const Limits& limits, std::uint64_t& out) {
  out = 0;
  const std::filesystem::path directory = generation_directory(root);
  if (!platform::file_exists(directory)) {
    return Status::success();
  }
  std::vector<std::string> names;
  if (auto listed = platform::list_directory(directory, names); !listed.ok()) {
    return listed;
  }
  std::size_t considered = 0;
  for (const std::string& name : names) {
    if (name.size() <= StoreFormat::kGenerationSuffix.size() ||
        name.compare(name.size() - StoreFormat::kGenerationSuffix.size(), StoreFormat::kGenerationSuffix.size(),
                     StoreFormat::kGenerationSuffix) != 0) {
      continue;
    }
    considered += 1;
    if (considered > limits.max_store_listing) {
      return Status::failure(ErrorCode::LimitExceeded,
                             "the store holds more generation records than the configured listing bound of " +
                                 std::to_string(limits.max_store_listing));
    }
    DecodedRecord record;
    if (auto status = read_and_decode_record(directory / std::filesystem::path(name), limits, record);
        !status.ok()) {
      return status;
    }
    out = std::max(out, record.info.control_epoch.raw());
  }
  return Status::success();
}

JsonValue policy_set_to_json(const CanonicalBundle& root) {
  JsonValue::Object document;
  document.emplace("schema", JsonValue::integer(static_cast<std::int64_t>(kPolicySetSchemaVersion)));
  document.emplace("kind", JsonValue::string("policy-set"));
  document.emplace("root", JsonValue::string(root.id().str()));
  JsonValue::Array bundles;
  const std::vector<const CanonicalBundle*> closure = policy_set_closure(root);
  bundles.reserve(closure.size());
  for (const CanonicalBundle* node : closure) {
    bundles.push_back(node->document());
  }
  document.emplace("bundles", JsonValue::array(std::move(bundles)));
  return JsonValue::object(std::move(document));
}

Result<std::shared_ptr<const CanonicalBundle>> policy_set_from_json(const JsonValue& document,
                                                                   const Limits& limits,
                                                                   const Digest256& expected_digest) {
  auto unknown = json_reject_unknown_members(document, {"schema", "kind", "root", "bundles"}, "policy-set");
  if (!unknown.ok()) {
    return unknown;
  }
  auto schema_member = json_require_member(document, "schema", "policy-set");
  if (!schema_member) {
    return schema_member.status();
  }
  auto schema = json_as_integer(*schema_member.value(), "policy-set.schema");
  if (!schema) {
    return schema.status();
  }
  if (schema.value() != static_cast<std::int64_t>(kPolicySetSchemaVersion)) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "published policy-set schema revision " + std::to_string(schema.value()) +
                               " is not supported by this build (expected " +
                               std::to_string(kPolicySetSchemaVersion) + ")");
  }
  auto kind_member = json_require_member(document, "kind", "policy-set");
  if (!kind_member) {
    return kind_member.status();
  }
  auto kind = json_as_string(*kind_member.value(), "policy-set.kind");
  if (!kind) {
    return kind.status();
  }
  if (kind.value() != "policy-set") {
    return Status::failure(ErrorCode::PolicySchema,
                           "published document kind '" + std::string(kind.value()) + "' is not a policy set");
  }
  auto root_member = json_require_member(document, "root", "policy-set");
  if (!root_member) {
    return root_member.status();
  }
  auto root_text = json_as_string(*root_member.value(), "policy-set.root");
  if (!root_text) {
    return root_text.status();
  }
  auto root_id = BundleId::parse(root_text.value(), limits.max_identifier_bytes);
  if (!root_id) {
    return root_id.status();
  }
  auto bundles_member = json_require_member(document, "bundles", "policy-set");
  if (!bundles_member) {
    return bundles_member.status();
  }
  auto bundles = json_as_array(*bundles_member.value(), "policy-set.bundles");
  if (!bundles) {
    return bundles.status();
  }
  const JsonValue::Array& array = *bundles.value();
  const std::size_t maximum =
      (static_cast<std::size_t>(limits.max_imports) * static_cast<std::size_t>(limits.max_import_depth)) + 1;
  if (array.size() > maximum) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "published policy set carries " + std::to_string(array.size()) +
                               " bundles, above the maximum of " + std::to_string(maximum));
  }
  if (array.empty()) {
    return Status::failure(ErrorCode::PolicySchema, "published policy set carries no bundles");
  }

  std::map<BundleId, std::shared_ptr<const CanonicalBundle>> compiled;
  for (std::size_t i = 0; i < array.size(); ++i) {
    const std::string item_path = json_index_path("policy-set.bundles", i);
    auto bundle = bundle_from_json(array[i], limits);
    if (!bundle) {
      return bundle.status();
    }
    std::vector<std::shared_ptr<const CanonicalBundle>> imports;
    imports.reserve(bundle.value().imports.size());
    for (const auto& declaration : bundle.value().imports) {
      const auto found = compiled.find(declaration.bundle);
      if (found == compiled.end()) {
        return Status::failure(ErrorCode::ImportConflict,
                               std::string(item_path) + ": bundle '" + bundle.value().id.str() +
                                   "' imports '" + declaration.bundle.str() +
                                   "', which does not appear earlier in the published policy set; the set "
                                   "is not in dependency order");
      }
      if (!(found->second->digest() == declaration.digest)) {
        return Status::failure(ErrorCode::IncompatibleBundle,
                               std::string(item_path) + ": bundle '" + bundle.value().id.str() +
                                   "' imports '" + declaration.bundle.str() + "' at digest " +
                                   declaration.digest.to_hex() + " but the published set carries digest " +
                                   found->second->digest().to_hex());
      }
      imports.push_back(found->second);
    }
    const BundleId id = bundle.value().id;
    auto canonical = canonicalize_bundle(std::move(bundle).value(), std::move(imports), limits);
    if (!canonical) {
      return canonical.status();
    }
    auto shared = std::make_shared<const CanonicalBundle>(std::move(canonical).value());
    if (!compiled.emplace(id, shared).second) {
      return Status::failure(ErrorCode::DuplicateIdentity,
                             "published policy set carries bundle '" + id.str() + "' more than once");
    }
  }

  const auto found = compiled.find(root_id.value());
  if (found == compiled.end()) {
    return Status::failure(ErrorCode::NotFound, "published policy set does not contain its declared root '" +
                                                    root_id.value().str() + "'");
  }
  if (!(found->second->digest() == expected_digest)) {
    return Status::failure(ErrorCode::DigestMismatch,
                           "published policy set resolves to digest " + found->second->digest().to_hex() +
                               " but the store manifest names " + expected_digest.to_hex());
  }
  return found->second;
}

}  // namespace

// ---- Reader ----------------------------------------------------------------

struct StoreReaderState {
  std::filesystem::path root;
  Limits limits;
  StoreHead head;
  std::string payload;
  std::shared_ptr<const CanonicalBundle> policy;
  bool policy_attempted = false;
  Status policy_failure;
};

namespace {

Status load_reader_state(StoreReaderState& state) {
  StoreHead head;
  if (auto status = load_manifest(state.root, head); !status.ok()) {
    return status;
  }
  DecodedRecord record;
  if (!head.generation.is_zero()) {
    if (auto status = load_current_record(state.root, head, state.limits, record); !status.ok()) {
      return status;
    }
  }
  state.head = head;
  state.payload = std::move(record.payload);
  state.policy.reset();
  state.policy_attempted = false;
  state.policy_failure = Status::success();
  return Status::success();
}

}  // namespace

StoreReader::StoreReader() noexcept = default;
StoreReader::~StoreReader() = default;
StoreReader::StoreReader(StoreReader&& other) noexcept = default;
StoreReader& StoreReader::operator=(StoreReader&& other) noexcept = default;

StoreHead StoreReader::head() const noexcept {
  return state_ == nullptr ? StoreHead{} : state_->head;
}

bool StoreReader::is_open() const noexcept { return state_ != nullptr; }

bool StoreReader::has_policy() const noexcept {
  return state_ != nullptr && !state_->head.generation.is_zero();
}

const std::filesystem::path& StoreReader::root() const noexcept {
  static const std::filesystem::path kAbsent;
  return state_ == nullptr ? kAbsent : state_->root;
}

Status StoreReader::refresh() {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store reader is not open");
  }
  return load_reader_state(*state_);
}

Result<const CanonicalBundle*> StoreReader::policy() {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store reader is not open");
  }
  if (state_->policy_attempted) {
    if (!state_->policy_failure.ok()) {
      return state_->policy_failure;
    }
    return state_->policy.get();
  }
  state_->policy_attempted = true;
  if (state_->head.generation.is_zero()) {
    state_->policy_failure =
        Status::failure(ErrorCode::StoreEmpty, "this store has no published policy generation");
    return state_->policy_failure;
  }
  auto document = parse_json(state_->payload, state_->limits);
  if (!document) {
    state_->policy_failure = document.status();
    return state_->policy_failure;
  }
  auto canonical = policy_set_from_json(document.value(), state_->limits, state_->head.bundle_digest);
  if (!canonical) {
    state_->policy_failure = canonical.status();
    return state_->policy_failure;
  }
  state_->policy = std::move(canonical).value();
  return state_->policy.get();
}

Result<CurrentPolicy> StoreReader::current_policy() {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store reader is not open");
  }
  if (state_->head.generation.is_zero()) {
    return Status::failure(ErrorCode::StoreEmpty, "this store has no published policy generation");
  }
  auto canonical = policy();
  if (!canonical) {
    return canonical.status();
  }
  CurrentPolicy current;
  current.bundle = canonical.value()->id();
  current.digest = state_->head.bundle_digest;
  current.generation = state_->head.generation;
  current.control_epoch = state_->head.control_epoch;
  return current;
}

Status StoreReader::verify_history(std::uint32_t max_records, std::vector<GenerationInfo>& history) {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store reader is not open");
  }
  history.clear();
  if (state_->head.generation.is_zero()) {
    return Status::success();
  }
  DecodedRecord record;
  if (auto status = load_current_record(state_->root, state_->head, state_->limits, record); !status.ok()) {
    return status;
  }
  history.push_back(record.info);

  Generation cursor = state_->head.generation;
  Digest256 expected_predecessor = record.info.prev_record_digest;
  while (cursor.raw() > 1 && history.size() < max_records) {
    const Generation previous = Generation::from_raw(cursor.raw() - 1);
    DecodedRecord earlier;
    if (auto status = read_and_decode_record(generation_path(state_->root, previous), state_->limits, earlier);
        !status.ok()) {
      return status;
    }
    if (!(earlier.info.generation == previous)) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "generation record file for generation " + std::to_string(previous.raw()) +
                                 " names generation " + std::to_string(earlier.info.generation.raw()));
    }
    if (!(earlier.info.store_id == record.info.store_id)) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "generation " + std::to_string(previous.raw()) + " belongs to store " +
                                 earlier.info.store_id.to_hex() + " but generation " +
                                 std::to_string(cursor.raw()) + " belongs to store " +
                                 record.info.store_id.to_hex());
    }
    if (!(earlier.info.record_digest == expected_predecessor)) {
      return Status::failure(ErrorCode::DigestMismatch,
                             "generation " + std::to_string(cursor.raw()) + " links to record digest " +
                                 expected_predecessor.to_hex() + " but generation " +
                                 std::to_string(previous.raw()) + " has digest " +
                                 earlier.info.record_digest.to_hex());
    }
    if (!(earlier.info.sequence < record.info.sequence)) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "generation " + std::to_string(previous.raw()) +
                                 " has publication sequence " + std::to_string(earlier.info.sequence.raw()) +
                                 ", which is not older than generation " + std::to_string(cursor.raw()) +
                                 " at sequence " + std::to_string(record.info.sequence.raw()));
    }
    history.push_back(earlier.info);
    expected_predecessor = earlier.info.prev_record_digest;
    record = earlier;
    cursor = previous;
  }
  if (cursor.raw() == 1 && !expected_predecessor.is_zero()) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "the first generation record links to a predecessor that cannot exist");
  }
  return Status::success();
}

struct StoreWriterState {
  std::filesystem::path root;
  Limits limits;
  platform::FileHandle lock;
  StoreHead head;
  bool recovery_required = false;
  Status manifest_failure;
};

namespace {

Status recovery_required_status(const StoreWriterState& state) {
  Status status = Status::failure(ErrorCode::CorruptManifest,
                                  "the store manifest is unusable, so no new generation may be published "
                                  "until an explicit generation is recovered");
  if (!state.manifest_failure.ok()) {
    status.add_secondary(std::string("cause: ") + std::string(state.manifest_failure.to_string()));
  }
  return status;
}

}  // namespace

StoreWriter::StoreWriter() noexcept = default;
StoreWriter::~StoreWriter() = default;
StoreWriter::StoreWriter(StoreWriter&& other) noexcept = default;
StoreWriter& StoreWriter::operator=(StoreWriter&& other) noexcept = default;

StoreHead StoreWriter::head() const noexcept {
  return state_ == nullptr ? StoreHead{} : state_->head;
}

bool StoreWriter::is_open() const noexcept { return state_ != nullptr && state_->lock.is_open(); }

const std::filesystem::path& StoreWriter::root() const noexcept {
  static const std::filesystem::path kAbsent;
  return state_ == nullptr ? kAbsent : state_->root;
}

void StoreWriter::close() noexcept {
  if (state_ != nullptr) {
    state_->lock.close();
  }
}

Result<Generation> StoreWriter::publish(const CanonicalBundle& bundle) {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store writer is not open");
  }
  if (state_->recovery_required) {
    return recovery_required_status(*state_);
  }
  auto next_generation = state_->head.generation.next();
  if (!next_generation) {
    return next_generation.status();
  }
  auto next_sequence = state_->head.sequence.next();
  if (!next_sequence) {
    return next_sequence.status();
  }
  if (static_cast<std::uint64_t>(bundle.canonical_bytes().size()) > state_->limits.max_record_payload_bytes) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the canonical policy set is " + std::to_string(bundle.canonical_bytes().size()) +
                               " bytes, above the configured record payload bound of " +
                               std::to_string(state_->limits.max_record_payload_bytes));
  }

  const std::string payload = to_canonical_json(policy_set_to_json(bundle));
  if (static_cast<std::uint64_t>(payload.size()) > state_->limits.max_record_payload_bytes) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the published policy set is " + std::to_string(payload.size()) +
                               " bytes, above the configured record payload bound of " +
                               std::to_string(state_->limits.max_record_payload_bytes));
  }

  Digest256 record_digest;
  const std::vector<std::byte> bytes =
      encode_record(state_->head.store_id, next_generation.value(), next_sequence.value(),
                    state_->head.control_epoch, TimestampNanos::now(), state_->head.record_digest,
                    bundle.digest(), payload, record_digest);

  if (auto written = write_file_atomically(generation_path(state_->root, next_generation.value()), bytes,
                                           "generation");
      !written.ok()) {
    return written;
  }

  StoreHead next_head = state_->head;
  next_head.generation = next_generation.value();
  next_head.sequence = next_sequence.value();
  next_head.record_digest = record_digest;
  next_head.bundle_digest = bundle.digest();
  if (auto published = write_manifest_file(state_->root, next_head); !published.ok()) {
    return published;
  }
  state_->head = next_head;
  return next_generation.value();
}

Status StoreWriter::raise_floor(Generation floor) {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store writer is not open");
  }
  if (state_->recovery_required) {
    return recovery_required_status(*state_);
  }
  if (floor < state_->head.floor_generation) {
    return Status::failure(ErrorCode::OutOfRange,
                           "the rollback floor cannot be lowered from " +
                               std::to_string(state_->head.floor_generation.raw()) + " to " +
                               std::to_string(floor.raw()));
  }
  if (state_->head.generation < floor) {
    return Status::failure(ErrorCode::OutOfRange,
                           "the rollback floor " + std::to_string(floor.raw()) +
                               " is above the current generation " +
                               std::to_string(state_->head.generation.raw()));
  }
  StoreHead next_head = state_->head;
  next_head.floor_generation = floor;
  if (auto published = write_manifest_file(state_->root, next_head); !published.ok()) {
    return published;
  }
  state_->head = next_head;
  return Status::success();
}

Status StoreWriter::recover_to(Generation generation) {
  if (state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store writer is not open");
  }
  if (generation.is_zero()) {
    return Status::failure(ErrorCode::OutOfRange,
                           "recovery must name a published generation; generation zero means the store "
                           "never published one");
  }
  DecodedRecord record;
  if (auto status = read_and_decode_record(generation_path(state_->root, generation), state_->limits, record);
      !status.ok()) {
    return status;
  }
  if (!(record.info.generation == generation)) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "the record for generation " + std::to_string(generation.raw()) +
                               " names generation " + std::to_string(record.info.generation.raw()));
  }
  if (record.payload.empty()) {
    return Status::failure(ErrorCode::CorruptManifest,
                           "the record for generation " + std::to_string(generation.raw()) +
                               " carries no policy payload");
  }
  if (generation.raw() == 1) {
    if (!record.info.prev_record_digest.is_zero()) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "the first generation record links to a predecessor that cannot exist");
    }
  } else {
    DecodedRecord earlier;
    const Generation previous = Generation::from_raw(generation.raw() - 1);
    if (auto status = read_and_decode_record(generation_path(state_->root, previous), state_->limits, earlier);
        !status.ok()) {
      return status;
    }
    if (!(earlier.info.record_digest == record.info.prev_record_digest)) {
      return Status::failure(ErrorCode::DigestMismatch,
                             "generation " + std::to_string(generation.raw()) + " links to record digest " +
                                 record.info.prev_record_digest.to_hex() + " but generation " +
                                 std::to_string(previous.raw()) + " has digest " +
                                 earlier.info.record_digest.to_hex());
    }
    if (!(earlier.info.sequence < record.info.sequence)) {
      return Status::failure(ErrorCode::CorruptManifest,
                             "generation " + std::to_string(previous.raw()) +
                                 " is not older in publication order than generation " +
                                 std::to_string(generation.raw()));
    }
  }

  std::uint64_t highest_epoch = 0;
  if (auto status = highest_published_epoch(state_->root, state_->limits, highest_epoch); !status.ok()) {
    return status;
  }
  if (state_->head.store_id.is_zero() && highest_epoch == 0) {
    highest_epoch = record.info.control_epoch.raw();
  }
  if (highest_epoch == UINT64_MAX) {
    return Status::failure(ErrorCode::CounterOverflow,
                           "the store control epoch cannot be advanced past its maximum value");
  }

  StoreHead recovered;
  recovered.store_id = record.info.store_id;
  recovered.generation = generation;
  recovered.control_epoch = Epoch::from_raw(highest_epoch + 1);
  recovered.sequence = record.info.sequence;
  recovered.floor_generation = state_->head.floor_generation;
  if (recovered.floor_generation > generation) {
    return Status::failure(ErrorCode::RollbackDetected,
                           "generation " + std::to_string(generation.raw()) +
                               " is below the store rollback floor of " +
                               std::to_string(recovered.floor_generation.raw()));
  }
  recovered.record_digest = record.info.record_digest;
  recovered.bundle_digest = record.info.bundle_digest;
  if (auto published = write_manifest_file(state_->root, recovered); !published.ok()) {
    return published;
  }
  state_->head = recovered;
  state_->recovery_required = false;
  state_->manifest_failure = Status::success();
  return Status::success();
}

// ---- Opening a store -------------------------------------------------------

Result<StoreHead> create_store(const std::filesystem::path& root, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (auto path_status = platform::validate_path(root, StoreFormat::kMaxPathBytes); !path_status.ok()) {
    return path_status;
  }
  if (platform::file_exists(manifest_path(root))) {
    return Status::failure(ErrorCode::StoreNotEmpty,
                           "a policy store already exists at '" + platform::path_text(root) + "'");
  }
  if (auto created = platform::ensure_directory(root); !created.ok()) {
    return created;
  }
  if (auto created = platform::ensure_directory(generation_directory(root)); !created.ok()) {
    return created;
  }
  auto lock = platform::acquire_writer_lock(lock_path(root));
  if (!lock) {
    return lock.status();
  }
  // Re-check under the lock: two concurrent creators must not both succeed.
  if (platform::file_exists(manifest_path(root))) {
    return Status::failure(ErrorCode::StoreNotEmpty,
                           "a policy store already exists at '" + platform::path_text(root) + "'");
  }

  auto random = platform::random_bytes(StoreFormat::kStoreIdBytes);
  if (!random) {
    return random.status();
  }
  std::array<std::byte, StoreFormat::kStoreIdBytes> id_bytes{};
  std::copy(random.value().begin(), random.value().end(), id_bytes.begin());
  StoreId store_id = StoreId::from_bytes(id_bytes);
  if (store_id.is_zero()) {
    // Astronomically unlikely, but a zero identity is reserved, so it must
    // never be minted.
    id_bytes[StoreFormat::kStoreIdBytes - 1] = std::byte{1};
    store_id = StoreId::from_bytes(id_bytes);
  }

  StoreHead head;
  head.store_id = store_id;
  head.generation = Generation::from_raw(0);
  head.control_epoch = Epoch::from_raw(1);
  head.sequence = Sequence::from_raw(0);
  head.floor_generation = Generation::from_raw(0);
  if (auto written = write_manifest_file(root, head); !written.ok()) {
    return written;
  }
  return head;
}

Result<StoreReader> open_reader(const std::filesystem::path& root, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (auto path_status = platform::validate_path(root, StoreFormat::kMaxPathBytes); !path_status.ok()) {
    return path_status;
  }
  if (!platform::file_exists(manifest_path(root))) {
    // A store whose manifest is gone is not an empty store: refusing here is
    // what stops a reader from silently starting over.
    std::vector<std::string> names;
    if (platform::file_exists(generation_directory(root))) {
      if (auto listed = platform::list_directory(generation_directory(root), names);
          listed.ok() && !names.empty()) {
        return Status::failure(ErrorCode::CorruptManifest,
                               "the directory '" + platform::path_text(root) +
                                   "' holds generation records but no manifest; open a writer and recover "
                                   "an explicit generation instead");
      }
    }
    return Status::failure(ErrorCode::NotFound, "no policy store manifest at '" +
                                                    platform::path_text(manifest_path(root)) + "'");
  }
  StoreReader reader;
  reader.state_ = std::make_unique<StoreReaderState>();
  reader.state_->root = root;
  reader.state_->limits = limits;
  if (auto loaded = load_reader_state(*reader.state_); !loaded.ok()) {
    return loaded;
  }
  return reader;
}

Result<StoreWriter> open_writer(const std::filesystem::path& root, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (auto path_status = platform::validate_path(root, StoreFormat::kMaxPathBytes); !path_status.ok()) {
    return path_status;
  }
  if (!platform::file_exists(root)) {
    return Status::failure(ErrorCode::NotFound,
                           "there is no policy store directory at '" + platform::path_text(root) + "'");
  }
  auto lock = platform::acquire_writer_lock(lock_path(root));
  if (!lock) {
    return lock.status();
  }
  StoreWriter writer;
  writer.state_ = std::make_unique<StoreWriterState>();
  writer.state_->root = root;
  writer.state_->limits = limits;
  writer.state_->lock = std::move(lock).value();

  StoreHead head;
  auto loaded = load_manifest(root, head);
  if (!loaded.ok()) {
    writer.state_->recovery_required = true;
    writer.state_->manifest_failure = loaded;
    return writer;
  }
  if (!head.generation.is_zero()) {
    DecodedRecord record;
    if (auto verified = load_current_record(root, head, limits, record); !verified.ok()) {
      writer.state_->recovery_required = true;
      writer.state_->manifest_failure = verified;
      writer.state_->head = head;
      return writer;
    }
  }

  auto next_epoch = head.control_epoch.next();
  if (!next_epoch) {
    return next_epoch.status();
  }
  head.control_epoch = next_epoch.value();
  if (auto published = write_manifest_file(root, head); !published.ok()) {
    return published;
  }
  writer.state_->head = head;
  return writer;
}

// ---- Anchors ---------------------------------------------------------------

namespace {

Result<StoreId> store_id_from_hex(std::string_view hex) {
  if (hex.size() != StoreFormat::kStoreIdBytes * 2) {
    return Status::failure(ErrorCode::OutOfRange,
                           "a store identity must be exactly " +
                               std::to_string(StoreFormat::kStoreIdBytes * 2) +
                               " hexadecimal characters, got " + std::to_string(hex.size()));
  }
  std::array<std::byte, StoreFormat::kStoreIdBytes> bytes{};
  for (std::size_t i = 0; i < StoreFormat::kStoreIdBytes; ++i) {
    for (std::size_t half = 0; half < 2; ++half) {
      const char c = hex[i * 2 + half];
      unsigned value = 0;
      if (c >= '0' && c <= '9') {
        value = static_cast<unsigned>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        value = static_cast<unsigned>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        value = static_cast<unsigned>(c - 'A' + 10);
      } else {
        return Status::failure(ErrorCode::OutOfRange,
                               "a store identity contains a non-hexadecimal character at byte offset " +
                                   std::to_string(i * 2 + half));
      }
      bytes[i] = static_cast<std::byte>((std::to_integer<unsigned>(bytes[i]) << 4) | value);
    }
  }
  return StoreId::from_bytes(bytes);
}

Result<std::uint64_t> counter_from_json(const JsonValue& document, std::string_view key, std::string_view path) {
  auto member = json_require_member(document, key, path);
  if (!member) {
    return member.status();
  }
  auto value = json_as_integer(*member.value(), json_child_path(path, key));
  if (!value) {
    return value.status();
  }
  if (value.value() < 0) {
    return Status::failure(ErrorCode::PolicySchema,
                           std::string(json_child_path(path, key)) + " must not be negative");
  }
  return static_cast<std::uint64_t>(value.value());
}

}  // namespace

JsonValue anchor_to_json(const StoreAnchor& anchor) {
  JsonValue::Object document;
  document.emplace("schema", JsonValue::integer(static_cast<std::int64_t>(kAnchorSchemaVersion)));
  document.emplace("kind", JsonValue::string("store-anchor"));
  document.emplace("store_id", JsonValue::string(anchor.store_id.to_hex()));
  document.emplace("generation", JsonValue::integer(static_cast<std::int64_t>(anchor.generation.raw())));
  document.emplace("sequence", JsonValue::integer(static_cast<std::int64_t>(anchor.sequence.raw())));
  document.emplace("manifest_digest", JsonValue::string(anchor.manifest_digest.to_hex()));
  return JsonValue::object(std::move(document));
}

Result<StoreAnchor> read_anchor(const std::filesystem::path& path, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (auto path_status = platform::validate_path(path, StoreFormat::kMaxPathBytes); !path_status.ok()) {
    return path_status;
  }
  auto bytes = platform::read_file(path, static_cast<std::uint64_t>(limits.max_text_bytes) * 64);
  if (!bytes) {
    return bytes.status();
  }
  const std::string_view text(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
  auto document = parse_json(text, limits);
  if (!document) {
    return document.status();
  }
  auto unknown = json_reject_unknown_members(
      document.value(), {"schema", "kind", "store_id", "generation", "sequence", "manifest_digest"}, "anchor");
  if (!unknown.ok()) {
    return unknown;
  }
  auto schema_member = json_require_member(document.value(), "schema", "anchor");
  if (!schema_member) {
    return schema_member.status();
  }
  auto schema = json_as_integer(*schema_member.value(), "anchor.schema");
  if (!schema) {
    return schema.status();
  }
  if (schema.value() != static_cast<std::int64_t>(kAnchorSchemaVersion)) {
    return Status::failure(ErrorCode::UnsupportedVersion,
                           "anchor schema revision " + std::to_string(schema.value()) +
                               " is not supported by this build (expected " +
                               std::to_string(kAnchorSchemaVersion) + ")");
  }
  auto kind_member = json_require_member(document.value(), "kind", "anchor");
  if (!kind_member) {
    return kind_member.status();
  }
  auto kind = json_as_string(*kind_member.value(), "anchor.kind");
  if (!kind) {
    return kind.status();
  }
  if (kind.value() != "store-anchor") {
    return Status::failure(ErrorCode::PolicySchema,
                           "anchor document kind '" + std::string(kind.value()) + "' is not an anchor");
  }
  auto id_member = json_require_member(document.value(), "store_id", "anchor");
  if (!id_member) {
    return id_member.status();
  }
  auto id_text = json_as_string(*id_member.value(), "anchor.store_id");
  if (!id_text) {
    return id_text.status();
  }
  auto store_id = store_id_from_hex(id_text.value());
  if (!store_id) {
    return store_id.status();
  }
  auto generation = counter_from_json(document.value(), "generation", "anchor");
  if (!generation) {
    return generation.status();
  }
  auto sequence = counter_from_json(document.value(), "sequence", "anchor");
  if (!sequence) {
    return sequence.status();
  }
  auto digest_member = json_require_member(document.value(), "manifest_digest", "anchor");
  if (!digest_member) {
    return digest_member.status();
  }
  auto digest_text = json_as_string(*digest_member.value(), "anchor.manifest_digest");
  if (!digest_text) {
    return digest_text.status();
  }
  auto digest = Digest256::from_hex(digest_text.value());
  if (!digest) {
    return digest.status();
  }

  StoreAnchor anchor;
  anchor.store_id = store_id.value();
  anchor.generation = Generation::from_raw(generation.value());
  anchor.sequence = Sequence::from_raw(sequence.value());
  anchor.manifest_digest = digest.value();
  return anchor;
}

Status write_anchor(const std::filesystem::path& path, const StoreAnchor& anchor, const Limits& limits) {
  if (auto limits_failure = validate_limits(limits); !limits_failure.ok()) {
    return limits_failure;
  }
  if (auto path_status = platform::validate_path(path, StoreFormat::kMaxPathBytes); !path_status.ok()) {
    return path_status;
  }
  if (anchor.store_id.is_zero()) {
    return Status::failure(ErrorCode::InvalidState, "an anchor must name a store identity");
  }
  if (anchor.generation.is_zero()) {
    return Status::failure(ErrorCode::InvalidState, "an anchor must name a published generation");
  }
  if (anchor.manifest_digest.is_zero()) {
    return Status::failure(ErrorCode::InvalidState, "an anchor must name a manifest digest");
  }
  if (anchor.generation.raw() > static_cast<std::uint64_t>(INT64_MAX) ||
      anchor.sequence.raw() > static_cast<std::uint64_t>(INT64_MAX)) {
    return Status::failure(ErrorCode::OutOfRange,
                           "the anchor names a generation or sequence beyond the JSON integer range");
  }
  const std::string text = to_canonical_json(anchor_to_json(anchor));
  const std::vector<std::byte> bytes(reinterpret_cast<const std::byte*>(text.data()),
                                     reinterpret_cast<const std::byte*>(text.data()) + text.size());
  return write_file_atomically(path, bytes, "anchor");
}

Status check_anchor(const StoreReader& reader, const StoreAnchor& anchor) {
  if (reader.state_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "the store reader is not open");
  }
  const StoreHead& head = reader.state_->head;
  if (!(anchor.store_id == head.store_id)) {
    return Status::failure(ErrorCode::DigestBindingMismatch,
                           "anchor names store " + anchor.store_id.to_hex() + " but this store is " +
                               head.store_id.to_hex());
  }
  if (head.generation < anchor.generation) {
    return Status::failure(ErrorCode::RollbackDetected,
                           "the anchor recorded generation " + std::to_string(anchor.generation.raw()) +
                               " but this store reports generation " +
                               std::to_string(head.generation.raw()));
  }
  if (head.sequence < anchor.sequence) {
    return Status::failure(ErrorCode::RollbackDetected,
                           "the anchor recorded publication sequence " +
                               std::to_string(anchor.sequence.raw()) + " but this store reports sequence " +
                               std::to_string(head.sequence.raw()));
  }
  if (head.generation == anchor.generation && !(head.manifest_digest == anchor.manifest_digest)) {
    return Status::failure(ErrorCode::DigestBindingMismatch,
                           "generation " + std::to_string(head.generation.raw()) +
                               " has manifest digest " + head.manifest_digest.to_hex() +
                               " but the anchor recorded " + anchor.manifest_digest.to_hex());
  }
  return Status::success();
}

}  // namespace fpe

