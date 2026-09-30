#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "fpe/decision.hpp"
#include "fpe/runtime.hpp"
#include "fpe/store.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::ErrorCode;
using fpe::FenceStatus;
using fpe::Generation;
using fpe::Limits;
using fpe::Status;

namespace {

constexpr std::string_view kPolicy =
    R"json({"schema":1,"bundle":"facility.thermal","revision":1,"facts":[{"key":"zone.temperature","type":"integer"}],"rules":[{"id":"r.refuse","priority":10,"effect":"refuse","when":{"test":{"fact":"zone.temperature","op":"greater-than","operands":[35]}},"reason":"thermal.too-hot"}]})json";

constexpr std::string_view kOtherPolicy =
    R"json({"schema":1,"bundle":"facility.thermal","revision":2,"facts":[{"key":"zone.temperature","type":"integer"}],"rules":[{"id":"r.refuse","priority":10,"effect":"refuse","when":{"test":{"fact":"zone.temperature","op":"greater-than","operands":[45]}},"reason":"thermal.too-hot"}]})json";

std::string read_binary(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

void write_binary(const std::filesystem::path& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  stream.flush();
}

std::filesystem::path manifest_of(const std::filesystem::path& root) {
  return root / std::filesystem::path(fpe::StoreFormat::kManifestName);
}

std::filesystem::path record_of(const std::filesystem::path& root, std::uint64_t generation) {
  std::string name(16, '0');
  std::uint64_t value = generation;
  static constexpr char kDigits[] = "0123456789abcdef";
  for (std::size_t i = 0; i < 16; ++i) {
    name[15 - i] = kDigits[value & 0xFu];
    value >>= 4;
  }
  name.append(fpe::StoreFormat::kGenerationSuffix);
  return root / std::filesystem::path(fpe::StoreFormat::kGenerationDirectory) / std::filesystem::path(name);
}

/// Creates a store with one published generation.
struct Fixture {
  fpe::test::TempDirectory directory;
  fpe::CanonicalBundle bundle;
};

fpe::Result<fpe::CanonicalBundle> compile(std::string_view text) { return fpe::test::compile_json(text); }

}  // namespace

FPE_TEST(store_create_publish_and_read_back) {
  auto directory = fpe::test::TempDirectory::create("store-basic");
  FPE_REQUIRE(directory.has_value());

  auto head = fpe::create_store(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(head.has_value());
  FPE_CHECK(head.value().generation.is_zero());
  FPE_CHECK(!head.value().store_id.is_zero());
  FPE_CHECK(!head.value().manifest_digest.is_zero());

  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  FPE_CHECK(!reader.value().has_policy());
  FPE_CHECK(!reader.value().policy().has_value());
  FPE_CHECK_EQ(reader.value().policy().status().code(), ErrorCode::StoreEmpty);

  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  auto published = writer.value().publish(compiled.value());
  FPE_REQUIRE(published.has_value());
  FPE_CHECK_EQ(published.value().raw(), std::uint64_t{1});
  writer.value().close();

  auto reopened = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reopened.has_value());
  FPE_CHECK(reopened.value().has_policy());
  FPE_CHECK_EQ(reopened.value().head().generation.raw(), std::uint64_t{1});
  FPE_CHECK(reopened.value().head().bundle_digest == compiled.value().digest());
  auto policy = reopened.value().policy();
  FPE_REQUIRE(policy.has_value());
  FPE_CHECK_EQ(policy.value()->id().str(), std::string("facility.thermal"));
  FPE_CHECK(policy.value()->digest() == compiled.value().digest());
}

FPE_TEST(store_is_single_writer_and_a_second_writer_is_refused) {
  auto directory = fpe::test::TempDirectory::create("store-lock");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto first = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(first.has_value());
  auto second = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_CHECK(!second.has_value());
  FPE_CHECK_EQ(second.status().code(), ErrorCode::LockHeld);

  first.value().close();
  auto third = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_CHECK(third.has_value());
  third.value().close();
}

FPE_TEST(store_writer_open_advances_the_control_epoch) {
  auto directory = fpe::test::TempDirectory::create("store-epoch");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto first = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(first.has_value());
  const std::uint64_t first_epoch = first.value().head().control_epoch.raw();
  first.value().close();

  auto second = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(second.has_value());
  FPE_CHECK(second.value().head().control_epoch.raw() > first_epoch);
  second.value().close();

  // A reader never advances the epoch.
  const std::uint64_t before = second.value().head().control_epoch.raw();
  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  FPE_CHECK_EQ(reader.value().head().control_epoch.raw(), before);
}

FPE_TEST(store_reader_observes_a_newly_published_generation_after_refresh) {
  auto directory = fpe::test::TempDirectory::create("store-refresh");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto first = compile(kPolicy);
  auto second = compile(kOtherPolicy);
  FPE_REQUIRE(first.has_value());
  FPE_REQUIRE(second.has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(first.value()).has_value());
  writer.value().close();

  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  FPE_CHECK(reader.value().head().bundle_digest == first.value().digest());

  auto second_writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(second_writer.has_value());
  FPE_REQUIRE(second_writer.value().publish(second.value()).has_value());
  second_writer.value().close();

  // Until refresh, the reader keeps the view it verified.
  FPE_CHECK(reader.value().head().bundle_digest == first.value().digest());
  FPE_REQUIRE(reader.value().refresh().ok());
  FPE_CHECK(reader.value().head().bundle_digest == second.value().digest());
  FPE_CHECK_EQ(reader.value().head().generation.raw(), std::uint64_t{2});
}

FPE_TEST(store_history_verifies_the_record_chain) {
  auto directory = fpe::test::TempDirectory::create("store-history");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());

  for (int i = 0; i < 5; ++i) {
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(writer.has_value());
    FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
    writer.value().close();
  }

  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  std::vector<fpe::GenerationInfo> history;
  FPE_REQUIRE(reader.value().verify_history(1000, history).ok());
  FPE_REQUIRE(history.size() == 5);
  for (std::size_t i = 0; i < history.size(); ++i) {
    FPE_CHECK_EQ(history[i].generation.raw(), static_cast<std::uint64_t>(5 - i));
  }
  for (std::size_t i = 1; i < history.size(); ++i) {
    FPE_CHECK(history[i].sequence.raw() < history[i - 1].sequence.raw());
  }
  FPE_CHECK(history.front().prev_record_digest.is_zero() == false);
}

FPE_TEST(store_publication_is_self_contained_across_imports) {
  auto directory = fpe::test::TempDirectory::create("store-import");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto leaf = fpe::test::parse_bundle(
      R"json({"schema":1,"bundle":"leaf","revision":1,"facts":[{"key":"f.shared","type":"integer"}]})json");
  FPE_REQUIRE(leaf.has_value());
  fpe::BundleCompiler compiler(Limits::defaults());
  FPE_REQUIRE(compiler.provide(std::move(leaf).value()).ok());
  auto leaf_id = fpe::BundleId::parse("leaf", 128);
  FPE_REQUIRE(leaf_id.has_value());
  auto compiled_leaf = compiler.compile(leaf_id.value());
  FPE_REQUIRE(compiled_leaf.has_value());

  const std::string root_text =
      "{\"schema\":1,\"bundle\":\"root\",\"revision\":1,\"imports\":[{\"bundle\":\"leaf\",\"digest\":\"" +
      compiled_leaf.value()->digest().to_hex() +
      "\"}],\"rules\":[{\"id\":\"r.a\",\"priority\":1,\"effect\":\"allow\",\"when\":{\"test\":{\"fact\":\"f.shared\",\"op\":\"exists\"}},\"reason\":\"x\"}]}";
  auto root = fpe::test::parse_bundle(root_text);
  FPE_REQUIRE(root.has_value());
  FPE_REQUIRE(compiler.provide(std::move(root).value()).ok());
  auto root_id = fpe::BundleId::parse("root", 128);
  FPE_REQUIRE(root_id.has_value());
  auto compiled_root = compiler.compile(root_id.value());
  FPE_REQUIRE(compiled_root.has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(*compiled_root.value()).has_value());
  writer.value().close();

  // A fresh reader resolves the whole policy set from the published payload
  // alone: no compiler, no external documents.
  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  auto policy = reader.value().policy();
  FPE_REQUIRE(policy.has_value());
  FPE_CHECK_EQ(policy.value()->imports().size(), std::size_t{1});
  FPE_CHECK(policy.value()->imports().front()->digest() == compiled_leaf.value()->digest());
}

FPE_TEST(store_single_bit_corruption_is_always_detected) {
  auto directory = fpe::test::TempDirectory::create("store-corrupt");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
  writer.value().close();

  const std::filesystem::path manifest = manifest_of(directory.value().path());
  const std::filesystem::path record = record_of(directory.value().path(), 1);

  for (const std::filesystem::path& target : {manifest, record}) {
    const std::string original = read_binary(target);
    FPE_REQUIRE(!original.empty());
    for (std::size_t offset = 0; offset < original.size(); ++offset) {
      std::string corrupted = original;
      corrupted[offset] = static_cast<char>(static_cast<unsigned char>(corrupted[offset]) ^ 0x01u);
      write_binary(target, corrupted);
      auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
      FPE_CHECK(!reader.has_value());
      if (reader.has_value()) {
        std::cout << "        undetected corruption of " << fpe::test::path_text(target) << " at offset "
                  << offset << "\n";
      }
    }
    write_binary(target, original);
    // The untouched store must still open.
    auto restored = fpe::open_reader(directory.value().path(), Limits::defaults());
    FPE_CHECK(restored.has_value());
  }
}

FPE_TEST(store_truncation_and_extension_sweeps_are_detected) {
  auto directory = fpe::test::TempDirectory::create("store-truncate");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
  writer.value().close();

  const std::filesystem::path manifest = manifest_of(directory.value().path());
  const std::filesystem::path record = record_of(directory.value().path(), 1);

  for (const std::filesystem::path& target : {manifest, record}) {
    const std::string original = read_binary(target);
    // Every prefix shorter than the declared length must be refused.
    for (std::size_t length = 0; length < original.size(); ++length) {
      write_binary(target, original.substr(0, length));
      auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
      FPE_CHECK(!reader.has_value());
    }
    // One extra byte must be refused as trailing content.
    write_binary(target, original + std::string(1, '\0'));
    auto extended = fpe::open_reader(directory.value().path(), Limits::defaults());
    FPE_CHECK(!extended.has_value());
    write_binary(target, original);
  }
}

FPE_TEST(store_missing_manifest_with_records_present_fails_closed) {
  auto directory = fpe::test::TempDirectory::create("store-nomanifest");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
  writer.value().close();

  std::error_code error;
  std::filesystem::remove(manifest_of(directory.value().path()), error);
  FPE_REQUIRE(!error);

  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_CHECK(!reader.has_value());
  FPE_CHECK_EQ(reader.status().code(), ErrorCode::CorruptManifest);

  // A writer opens in "recovery required" state and refuses to publish.
  auto recovering = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(recovering.has_value());
  auto publish = recovering.value().publish(compiled.value());
  FPE_CHECK(!publish.has_value());
  FPE_CHECK_EQ(publish.status().code(), ErrorCode::CorruptManifest);

  // Recovery from an explicitly named generation restores the store.
  FPE_REQUIRE(recovering.value().recover_to(Generation::from_raw(1)).ok());
  auto recovered_head = recovering.value().head();
  FPE_CHECK_EQ(recovered_head.generation.raw(), std::uint64_t{1});
  FPE_CHECK(recovered_head.bundle_digest == compiled.value().digest());
  recovering.value().close();

  auto reopened = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reopened.has_value());
  FPE_CHECK(reopened.value().has_policy());
  auto policy = reopened.value().policy();
  FPE_REQUIRE(policy.has_value());
  FPE_CHECK(policy.value()->digest() == compiled.value().digest());
}

FPE_TEST(store_recovery_from_a_missing_generation_fails_closed) {
  auto directory = fpe::test::TempDirectory::create("store-recover-missing");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  const Status missing = writer.value().recover_to(Generation::from_raw(9));
  FPE_CHECK(!missing.ok());
  FPE_CHECK_EQ(missing.code(), ErrorCode::NotFound);

  const Status zero = writer.value().recover_to(Generation::from_raw(0));
  FPE_CHECK(!zero.ok());
  FPE_CHECK_EQ(zero.code(), ErrorCode::OutOfRange);
}

FPE_TEST(store_rollback_floor_refuses_a_regressed_manifest) {
  auto directory = fpe::test::TempDirectory::create("store-floor");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());

  for (int i = 0; i < 3; ++i) {
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(writer.has_value());
    FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
    writer.value().close();
  }

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().raise_floor(Generation::from_raw(3)).ok());
  const Status below = writer.value().raise_floor(Generation::from_raw(1));
  FPE_CHECK(!below.ok());
  FPE_CHECK_EQ(below.code(), ErrorCode::OutOfRange);
  const Status above = writer.value().raise_floor(Generation::from_raw(4));
  FPE_CHECK(!above.ok());
  FPE_CHECK_EQ(above.code(), ErrorCode::OutOfRange);

  // A manifest written below the floor is refused on open.
  const Status recovered = writer.value().recover_to(Generation::from_raw(2));
  FPE_CHECK(!recovered.ok());
  FPE_CHECK_EQ(recovered.code(), ErrorCode::RollbackDetected);
  writer.value().close();
}

FPE_TEST(store_anchor_detects_a_whole_directory_rollback) {
  auto directory = fpe::test::TempDirectory::create("store-anchor");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
  writer.value().close();

  const std::filesystem::path anchor_path = directory.value().child("anchor.json");
  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  fpe::StoreAnchor anchor;
  anchor.store_id = reader.value().head().store_id;
  anchor.generation = reader.value().head().generation;
  anchor.sequence = reader.value().head().sequence;
  anchor.manifest_digest = reader.value().head().manifest_digest;
  FPE_REQUIRE(fpe::write_anchor(anchor_path, anchor, Limits::defaults()).ok());
  FPE_REQUIRE(fpe::check_anchor(reader.value(), anchor).ok());

  auto parsed = fpe::read_anchor(anchor_path, Limits::defaults());
  FPE_REQUIRE(parsed.has_value());
  FPE_CHECK_EQ(parsed.value().generation.raw(), anchor.generation.raw());
  FPE_CHECK_EQ(parsed.value().store_id.to_hex(), anchor.store_id.to_hex());

  // Roll the whole directory back to generation zero.
  const std::string manifest_bytes = read_binary(manifest_of(directory.value().path()));
  std::error_code error;
  std::filesystem::remove(manifest_of(directory.value().path()), error);
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  (void)manifest_bytes;

  auto rolled_back = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(rolled_back.has_value());
  const Status checked = fpe::check_anchor(rolled_back.value(), parsed.value());
  FPE_CHECK(!checked.ok());
  FPE_CHECK_EQ(checked.code(), ErrorCode::DigestBindingMismatch);
}

FPE_TEST(store_anchor_rejects_a_foreign_store) {
  auto first = fpe::test::TempDirectory::create("store-anchor-a");
  auto second = fpe::test::TempDirectory::create("store-anchor-b");
  FPE_REQUIRE(first.has_value());
  FPE_REQUIRE(second.has_value());
  FPE_REQUIRE(fpe::create_store(first.value().path(), Limits::defaults()).has_value());
  FPE_REQUIRE(fpe::create_store(second.value().path(), Limits::defaults()).has_value());

  auto reader = fpe::open_reader(first.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  fpe::StoreAnchor foreign;
  foreign.store_id = fpe::StoreId::from_bytes({});
  foreign.generation = Generation::from_raw(1);
  foreign.sequence = fpe::Sequence::from_raw(1);
  foreign.manifest_digest = fpe::Digest256::of("x");
  const Status checked = fpe::check_anchor(reader.value(), foreign);
  FPE_CHECK(!checked.ok());
  FPE_CHECK_EQ(checked.code(), ErrorCode::DigestBindingMismatch);

  // A zero store identity cannot be written into an anchor at all.
  FPE_CHECK(!fpe::write_anchor(first.value().child("bad.json"), foreign, Limits::defaults()).ok());
}

FPE_TEST(store_path_validation_refuses_hostile_directories) {
  const Limits limits = Limits::defaults();
  FPE_CHECK_EQ(fpe::create_store(std::filesystem::path(), limits).status().code(), ErrorCode::PathEmpty);
  FPE_CHECK_EQ(fpe::open_reader(std::filesystem::path(), limits).status().code(), ErrorCode::PathEmpty);

  auto reserved = fpe::test::TempDirectory::create("store-reserved");
  FPE_REQUIRE(reserved.has_value());
  const std::filesystem::path device = reserved.value().child("NUL");
  auto created = fpe::create_store(device, limits);
  FPE_CHECK(!created.has_value());
  FPE_CHECK_EQ(created.status().code(), ErrorCode::ReservedIdentifier);

  const std::filesystem::path with_control =
      reserved.value().path() / std::filesystem::path(std::string("bad\nname"));
  auto controlled = fpe::create_store(with_control, limits);
  FPE_CHECK(!controlled.has_value());
  FPE_CHECK_EQ(controlled.status().code(), ErrorCode::PathInvalid);

  const std::string long_component(6000, 'x');
  auto too_long = fpe::create_store(reserved.value().path() / std::filesystem::path(long_component), limits);
  FPE_CHECK(!too_long.has_value());
  FPE_CHECK(too_long.status().code() == ErrorCode::PathTooLong ||
            too_long.status().code() == ErrorCode::IoFailure);
}

FPE_TEST(store_repeated_open_close_is_stable) {
  auto directory = fpe::test::TempDirectory::create("store-repeat");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());

  for (int i = 0; i < 40; ++i) {
    auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(reader.has_value());
    FPE_REQUIRE(reader.value().refresh().ok());
  }
  for (int i = 0; i < 10; ++i) {
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(writer.has_value());
    FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
    writer.value().close();
  }
  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  FPE_CHECK_EQ(reader.value().head().generation.raw(), std::uint64_t{10});
  std::vector<fpe::GenerationInfo> history;
  FPE_REQUIRE(reader.value().verify_history(1000, history).ok());
  FPE_CHECK_EQ(history.size(), std::size_t{10});
}

// ---- Decision artifacts and fencing ---------------------------------------

namespace {

fpe::Result<fpe::DecisionArtifact> evaluate_with_binding(const fpe::CanonicalBundle& bundle,
                                                         const fpe::InputSet& inputs,
                                                         std::optional<Generation> generation,
                                                         std::optional<fpe::Epoch> epoch) {
  fpe::EvaluationOptions options;
  options.binding.generation = generation;
  options.binding.control_epoch = epoch;
  return fpe::evaluate(bundle, inputs, options);
}

}  // namespace

FPE_TEST(decision_artifact_digest_detects_any_change) {
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("zone.temperature", 40)));
  FPE_REQUIRE(inputs.has_value());
  auto artifact = fpe::evaluate(compiled.value(), inputs.value(), fpe::EvaluationOptions{});
  FPE_REQUIRE(artifact.has_value());
  FPE_CHECK(fpe::verify_artifact(artifact.value()).ok());

  fpe::DecisionArtifact tampered = artifact.value();
  tampered.outcome = fpe::Outcome::Allow;
  FPE_CHECK(!fpe::verify_artifact(tampered).ok());
  FPE_CHECK_EQ(fpe::verify_artifact(tampered).code(), ErrorCode::DigestBindingMismatch);

  fpe::DecisionArtifact unfinalized = artifact.value();
  unfinalized.artifact_digest = fpe::Digest256();
  FPE_CHECK(!fpe::verify_artifact(unfinalized).ok());
}

FPE_TEST(decision_artifact_json_round_trip_is_exact) {
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("zone.temperature", 40)));
  FPE_REQUIRE(inputs.has_value());
  auto artifact = evaluate_with_binding(compiled.value(), inputs.value(), Generation::from_raw(4),
                                        fpe::Epoch::from_raw(2));
  FPE_REQUIRE(artifact.has_value());

  const std::string document = fpe::to_canonical_json(fpe::artifact_document(artifact.value()));
  const fpe::Limits limits = Limits::defaults();
  auto parsed = fpe::parse_json(document, limits);
  FPE_REQUIRE(parsed.has_value());
  auto restored = fpe::artifact_from_json(parsed.value(), limits);
  FPE_REQUIRE(restored.has_value());
  FPE_CHECK(restored.value().artifact_digest == artifact.value().artifact_digest);
  FPE_CHECK_EQ(fpe::to_canonical_json(fpe::artifact_document(restored.value())), document);

  // A single changed byte must be refused.
  std::string corrupted = document;
  const std::size_t position = corrupted.find("\"outcome\":\"refuse\"");
  FPE_REQUIRE(position != std::string::npos);
  corrupted.replace(position, std::strlen("\"outcome\":\"refuse\""), "\"outcome\":\"allow\"");
  auto tampered = fpe::parse_json(corrupted, limits);
  FPE_REQUIRE(tampered.has_value());
  auto rejected = fpe::artifact_from_json(tampered.value(), limits);
  FPE_CHECK(!rejected.has_value());
  FPE_CHECK_EQ(rejected.status().code(), ErrorCode::DigestBindingMismatch);
}

FPE_TEST(decision_fencing_reports_each_staleness_cause_distinctly) {
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("zone.temperature", 40)));
  FPE_REQUIRE(inputs.has_value());

  auto bound = evaluate_with_binding(compiled.value(), inputs.value(), Generation::from_raw(4),
                                     fpe::Epoch::from_raw(2));
  FPE_REQUIRE(bound.has_value());

  fpe::CurrentPolicy current;
  current.bundle = compiled.value().id();
  current.digest = compiled.value().digest();
  current.generation = Generation::from_raw(4);
  current.control_epoch = fpe::Epoch::from_raw(2);
  FPE_CHECK(fpe::fence_decision(bound.value(), current).is_current());

  fpe::CurrentPolicy newer = current;
  newer.generation = Generation::from_raw(5);
  FPE_CHECK_EQ(fpe::fence_decision(bound.value(), newer).status, FenceStatus::StaleGeneration);

  fpe::CurrentPolicy older = current;
  older.generation = Generation::from_raw(3);
  FPE_CHECK_EQ(fpe::fence_decision(bound.value(), older).status, FenceStatus::GenerationRegressed);

  fpe::CurrentPolicy new_epoch = current;
  new_epoch.control_epoch = fpe::Epoch::from_raw(3);
  FPE_CHECK_EQ(fpe::fence_decision(bound.value(), new_epoch).status, FenceStatus::StaleEpoch);

  auto other = compile(kOtherPolicy);
  FPE_REQUIRE(other.has_value());
  fpe::CurrentPolicy different = current;
  different.digest = other.value().digest();
  FPE_CHECK_EQ(fpe::fence_decision(bound.value(), different).status, FenceStatus::BundleChanged);

  fpe::CurrentPolicy unpublished = current;
  unpublished.generation.reset();
  unpublished.control_epoch.reset();
  FPE_CHECK_EQ(fpe::fence_decision(bound.value(), unpublished).status, FenceStatus::UnboundCurrentPolicy);

  auto unbound = fpe::evaluate(compiled.value(), inputs.value(), fpe::EvaluationOptions{});
  FPE_REQUIRE(unbound.has_value());
  FPE_CHECK_EQ(fpe::fence_decision(unbound.value(), current).status, FenceStatus::UnboundDecision);

  fpe::DecisionArtifact tampered = bound.value();
  tampered.control_epoch = fpe::Epoch::from_raw(99);
  FPE_CHECK_EQ(fpe::fence_decision(tampered, current).status, FenceStatus::ArtifactDigestMismatch);
}

FPE_TEST(decision_fencing_rejects_a_different_evaluator_revision) {
  auto compiled = compile(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("zone.temperature", 40)));
  FPE_REQUIRE(inputs.has_value());
  auto artifact = evaluate_with_binding(compiled.value(), inputs.value(), Generation::from_raw(1),
                                        fpe::Epoch::from_raw(1));
  FPE_REQUIRE(artifact.has_value());

  fpe::DecisionArtifact from_another_build = artifact.value();
  from_another_build.evaluator_revision = artifact.value().evaluator_revision + 1;
  FPE_REQUIRE(fpe::finalize_artifact(from_another_build).ok());

  fpe::CurrentPolicy current;
  current.bundle = compiled.value().id();
  current.digest = compiled.value().digest();
  current.generation = Generation::from_raw(1);
  current.control_epoch = fpe::Epoch::from_raw(1);
  FPE_CHECK_EQ(fpe::fence_decision(from_another_build, current).status,
               FenceStatus::EvaluatorRevisionChanged);
}

FPE_TEST(decision_hot_reload_fences_decisions_made_before_the_change) {
  auto directory = fpe::test::TempDirectory::create("store-hot-reload");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto first = compile(kPolicy);
  auto second = compile(kOtherPolicy);
  FPE_REQUIRE(first.has_value());
  FPE_REQUIRE(second.has_value());

  auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(writer.has_value());
  FPE_REQUIRE(writer.value().publish(first.value()).has_value());
  writer.value().close();

  auto runtime = fpe::PolicyRuntime::open(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(runtime.has_value());
  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("zone.temperature", 40)));
  FPE_REQUIRE(inputs.has_value());

  auto before = runtime.value().decide(inputs.value(), fpe::EvaluationOptions{});
  FPE_REQUIRE(before.has_value());
  FPE_CHECK_EQ(before.value().outcome, fpe::Outcome::Refuse);
  FPE_CHECK(fpe::verify_artifact(before.value()).ok());
  FPE_CHECK(runtime.value().fence(before.value()).value().is_current());

  auto second_writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(second_writer.has_value());
  FPE_REQUIRE(second_writer.value().publish(second.value()).has_value());
  second_writer.value().close();

  auto reloaded = runtime.value().reload();
  FPE_REQUIRE(reloaded.has_value());
  FPE_CHECK(reloaded.value());

  // The old decision is unchanged and still verifies, but it is no longer
  // current: it names the generation and policy it was made under.
  FPE_CHECK(fpe::verify_artifact(before.value()).ok());
  FPE_CHECK(before.value().bundle_digest == first.value().digest());
  auto fence = runtime.value().fence(before.value());
  FPE_REQUIRE(fence.has_value());
  FPE_CHECK(!fence.value().is_current());
  FPE_CHECK_EQ(fence.value().status, FenceStatus::BundleChanged);

  auto after = runtime.value().decide(inputs.value(), fpe::EvaluationOptions{});
  FPE_REQUIRE(after.has_value());
  FPE_CHECK_EQ(after.value().outcome, fpe::Outcome::Unknown);
  FPE_CHECK(after.value().bundle_digest == second.value().digest());
  FPE_CHECK_EQ(after.value().policy_generation->raw(), std::uint64_t{2});
  FPE_CHECK(runtime.value().fence(after.value()).value().is_current());
}
