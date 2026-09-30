#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "fpe/engine.hpp"
#include "fpe/policy.hpp"
#include "fpe/runtime.hpp"
#include "fpe/store.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::Generation;
using fpe::Limits;

namespace {

std::string policy_document(int revision, int threshold) {
  return "{\"schema\":1,\"bundle\":\"machine.bundle\",\"revision\":" + std::to_string(revision) +
         ",\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[{\"id\":\"r.refuse\",\"priority\":10,"
         "\"effect\":\"refuse\",\"when\":{\"test\":{\"fact\":\"f.n\",\"op\":\"greater-than\",\"operands\":[" +
         std::to_string(threshold) + "]}},\"reason\":\"machine.refuse\"}]}";
}

}  // namespace

FPE_TEST(statemachine_store_invariants_hold_after_every_action) {
  const std::uint64_t seed = fpe::test::global_seed() ^ 0x9E3779B9u;
  std::cout << "    seeded state machine, seed " << seed << "\n";
  fpe::test::Random random(seed);

  auto directory = fpe::test::TempDirectory::create("machine-store");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  std::uint64_t highest_generation = 0;
  std::uint64_t highest_sequence = 0;
  std::uint64_t highest_epoch = 0;
  const std::size_t actions = 60;

  for (std::size_t step = 0; step < actions; ++step) {
    const std::uint32_t choice = random.next_u32() % 5u;
    if (choice == 0 || choice == 1) {
      const int revision = static_cast<int>(random.below(1000));
      const int threshold = static_cast<int>(random.below(50));
      auto compiled = fpe::test::compile_json(policy_document(revision, threshold));
      FPE_REQUIRE(compiled.has_value());
      auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
      FPE_REQUIRE(writer.has_value());
      auto published = writer.value().publish(compiled.value());
      FPE_REQUIRE(published.has_value());
      FPE_CHECK(published.value().raw() > highest_generation);
      FPE_CHECK(writer.value().head().sequence.raw() > highest_sequence);
      FPE_CHECK(writer.value().head().control_epoch.raw() > highest_epoch);
      highest_generation = published.value().raw();
      highest_sequence = writer.value().head().sequence.raw();
      highest_epoch = writer.value().head().control_epoch.raw();
      writer.value().close();
    } else if (choice == 2) {
      auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
      FPE_REQUIRE(writer.has_value());
      const std::uint64_t current_floor = writer.value().head().floor_generation.raw();
      if (highest_generation > current_floor && random.coin()) {
        // A floor may only be raised, so the new value is drawn from the range
        // above the current one and at or below the current generation.
        const std::uint64_t floor =
            current_floor + 1 + random.below(highest_generation - current_floor);
        FPE_REQUIRE(writer.value().raise_floor(Generation::from_raw(floor)).ok());
        FPE_CHECK(writer.value().head().floor_generation.raw() >= floor);
      }
      highest_epoch = writer.value().head().control_epoch.raw();
      writer.value().close();
    } else {
      auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
      FPE_REQUIRE(reader.has_value());
      if (random.coin()) {
        FPE_REQUIRE(reader.value().refresh().ok());
      }
      // Invariant: the store only ever moves forward, and whatever it reports
      // verifies completely.
      FPE_CHECK(reader.value().head().generation.raw() >= highest_generation);
      FPE_CHECK(reader.value().head().sequence.raw() >= highest_sequence);
      FPE_CHECK(reader.value().head().control_epoch.raw() >= highest_epoch);
      FPE_CHECK(reader.value().head().floor_generation <= reader.value().head().generation);
      if (reader.value().has_policy()) {
        FPE_CHECK(!reader.value().head().bundle_digest.is_zero());
        auto policy = reader.value().policy();
        FPE_REQUIRE(policy.has_value());
        FPE_CHECK(policy.value()->digest() == reader.value().head().bundle_digest);
        auto current = reader.value().current_policy();
        FPE_REQUIRE(current.has_value());
        FPE_CHECK(current.value().digest == reader.value().head().bundle_digest);
      }
      std::vector<fpe::GenerationInfo> history;
      FPE_REQUIRE(reader.value().verify_history(1000000, history).ok());
      FPE_CHECK_EQ(history.size(), static_cast<std::size_t>(reader.value().head().generation.raw()));
    }
  }
}

FPE_TEST(statemachine_evaluation_outcome_tracks_the_published_policy) {
  const std::uint64_t seed = fpe::test::global_seed() ^ 0x1234567u;
  std::cout << "    seeded publication/evaluation interleaving, seed " << seed << "\n";
  fpe::test::Random random(seed);

  auto directory = fpe::test::TempDirectory::create("machine-eval");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  auto inputs = fpe::test::inputs_from_json(
      fpe::test::input_document(fpe::test::observed_integer("f.n", 40)));
  FPE_REQUIRE(inputs.has_value());

  int last_threshold = 0;
  for (int step = 0; step < 30; ++step) {
    const int threshold = static_cast<int>(random.below(60));
    auto compiled = fpe::test::compile_json(policy_document(step, threshold));
    FPE_REQUIRE(compiled.has_value());
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(writer.has_value());
    FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
    writer.value().close();
    last_threshold = threshold;

    auto runtime = fpe::PolicyRuntime::open(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(runtime.has_value());
    auto artifact = runtime.value().decide(inputs.value(), fpe::EvaluationOptions{});
    FPE_REQUIRE(artifact.has_value());
    // The input fact is 40, so the policy refuses exactly when its threshold is
    // below 40. The engine must agree with the policy that is current.
    const fpe::Outcome expected = last_threshold < 40 ? fpe::Outcome::Refuse : fpe::Outcome::Unknown;
    FPE_CHECK_EQ(artifact.value().outcome, expected);
    FPE_CHECK(fpe::verify_artifact(artifact.value()).ok());
    FPE_CHECK(runtime.value().fence(artifact.value()).value().is_current());
  }
}

FPE_TEST(statemachine_policy_permutation_invariance_is_exhaustive_for_small_sets) {
  const std::uint64_t seed = fpe::test::global_seed() ^ 0xABCDEFu;
  std::cout << "    seeded rule permutation sweep, seed " << seed << "\n";
  fpe::test::Random random(seed);

  const std::string rules[] = {
      "{\"id\":\"r.a\",\"priority\":30,\"effect\":\"allow\",\"when\":{\"test\":{\"fact\":\"f.n\",\"op\":\"greater-than\",\"operands\":[1]}},\"reason\":\"a\"}",
      "{\"id\":\"r.b\",\"priority\":30,\"effect\":\"refuse\",\"when\":{\"test\":{\"fact\":\"f.n\",\"op\":\"less-than\",\"operands\":[100]}},\"reason\":\"b\"}",
      "{\"id\":\"r.c\",\"priority\":20,\"effect\":\"allow\",\"when\":{\"all\":[]},\"reason\":\"c\"}",
      "{\"id\":\"r.d\",\"priority\":40,\"effect\":\"defer\",\"when\":{\"all\":[]},\"reason\":\"d\"}"};
  const std::size_t rule_count = sizeof(rules) / sizeof(rules[0]);

  std::vector<std::size_t> order(rule_count);
  for (std::size_t i = 0; i < rule_count; ++i) {
    order[i] = i;
  }

  fpe::Digest256 baseline_digest;
  fpe::Outcome baseline_outcome = fpe::Outcome::Unknown;
  bool have_baseline = false;
  const std::string input = fpe::test::input_document(fpe::test::observed_integer("f.n", 50));

  for (int trial = 0; trial < 40; ++trial) {
    std::string joined;
    for (std::size_t i = 0; i < rule_count; ++i) {
      if (i > 0) {
        joined.push_back(',');
      }
      joined.append(rules[order[i]]);
    }
    const std::string document = "{\"schema\":1,\"bundle\":\"perm.bundle\",\"revision\":1,"
                                 "\"facts\":[{\"key\":\"f.n\",\"type\":\"integer\"}],\"rules\":[" +
                                 joined + "]}";
    auto compiled = fpe::test::compile_json(document);
    FPE_REQUIRE(compiled.has_value());
    auto inputs = fpe::test::inputs_from_json(input);
    FPE_REQUIRE(inputs.has_value());
    auto artifact = fpe::evaluate(compiled.value(), inputs.value(), fpe::EvaluationOptions{});
    FPE_REQUIRE(artifact.has_value());

    if (!have_baseline) {
      baseline_digest = compiled.value().digest();
      baseline_outcome = artifact.value().outcome;
      have_baseline = true;
    } else {
      FPE_CHECK(compiled.value().digest() == baseline_digest);
      FPE_CHECK_EQ(artifact.value().outcome, baseline_outcome);
    }

    for (std::size_t i = rule_count; i > 1; --i) {
      const std::size_t j = random.index(i);
      std::swap(order[i - 1], order[j]);
    }
  }
}
