#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fpe/store.hpp"
#include "test_support.hpp"

#include "fixtures.hpp"

using fpe::ErrorCode;
using fpe::Limits;
using fpe::Status;

namespace {

constexpr std::string_view kPolicy =
    R"json({"schema":1,"bundle":"process.bundle","revision":1,"facts":[{"key":"f.n","type":"integer"}],"rules":[{"id":"r.a","priority":1,"effect":"refuse","when":{"test":{"fact":"f.n","op":"greater-than","operands":[10]}},"reason":"process.refuse"}]})json";

std::string read_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

void write_text(const std::filesystem::path& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(text.data(), static_cast<std::streamsize>(text.size()));
  stream.flush();
}

/// Waits until \p predicate holds, with a generous bound. This is a
/// synchronisation bound between two real processes, not a test timeout: if it
/// expires the case reports what it was waiting for.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds bound) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < bound) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return predicate();
}

}  // namespace

FPE_TEST(multiprocess_writer_lock_excludes_a_second_process) {
  auto directory = fpe::test::TempDirectory::create("mp-lock");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  const std::filesystem::path log = directory.value().child("holder.log");
  auto child = fpe::test::ChildProcess::start(
      fpe::test::test_executable_path(),
      {"--child", "hold-writer", fpe::test::path_text(directory.value().path()), "1500"}, log);
  FPE_REQUIRE(child.has_value());

  const bool announced = wait_until(
      [&log] { return read_text(log).find("writer-held") != std::string::npos; },
      std::chrono::milliseconds(30000));
  FPE_REQUIRE(announced);

  // While the other process holds the writer, this process must be refused.
  auto blocked = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_CHECK(!blocked.has_value());
  FPE_CHECK_EQ(blocked.status().code(), ErrorCode::LockHeld);

  auto exit_code = child.value().wait();
  FPE_REQUIRE(exit_code.has_value());
  FPE_CHECK_EQ(exit_code.value(), 0);

  auto acquired = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_CHECK(acquired.has_value());
  if (acquired.has_value()) {
    acquired.value().close();
  }
}

FPE_TEST(multiprocess_kernel_releases_the_lock_when_the_writer_dies) {
  auto directory = fpe::test::TempDirectory::create("mp-kill-lock");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  const std::filesystem::path log = directory.value().child("victim.log");
  auto child = fpe::test::ChildProcess::start(
      fpe::test::test_executable_path(),
      {"--child", "hold-writer", fpe::test::path_text(directory.value().path()), "60000"}, log);
  FPE_REQUIRE(child.has_value());

  const bool announced = wait_until(
      [&log] { return read_text(log).find("writer-held") != std::string::npos; },
      std::chrono::milliseconds(30000));
  FPE_REQUIRE(announced);

  auto blocked = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(!blocked.has_value());

  // Abrupt death: no cleanup runs in the child, so only the kernel releasing its
  // handles can free the lock.
  FPE_REQUIRE(child.value().terminate_now().ok());
  FPE_CHECK(!child.value().running());

  const auto start = std::chrono::steady_clock::now();
  bool acquired = false;
  while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(30000)) {
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    if (writer.has_value()) {
      acquired = true;
      writer.value().close();
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  FPE_CHECK(acquired);
}

FPE_TEST(multiprocess_readers_never_observe_a_partial_publication) {
  auto directory = fpe::test::TempDirectory::create("mp-readers");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  const std::filesystem::path policy_path = directory.value().child("policy.json");
  const std::filesystem::path input_path = directory.value().child("facts.json");
  write_text(policy_path, std::string(kPolicy));
  write_text(input_path, fpe::test::input_document(fpe::test::observed_integer("f.n", 20)));

  auto compiled = fpe::test::compile_json(kPolicy);
  FPE_REQUIRE(compiled.has_value());
  auto seed_writer = fpe::open_writer(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(seed_writer.has_value());
  FPE_REQUIRE(seed_writer.value().publish(compiled.value()).has_value());
  seed_writer.value().close();

  const int readers = 3;
  std::vector<fpe::test::ChildProcess> children;
  for (int i = 0; i < readers; ++i) {
    const std::filesystem::path log = directory.value().child("reader-" + std::to_string(i) + ".log");
    auto child = fpe::test::ChildProcess::start(
        fpe::test::test_executable_path(),
        {"--child", "eval-loop", fpe::test::path_text(directory.value().path()),
         fpe::test::path_text(input_path), "40"},
        log);
    FPE_REQUIRE(child.has_value());
    children.push_back(std::move(child).value());
  }

  // Publish continuously while the readers work.
  for (int i = 0; i < 25; ++i) {
    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    if (!writer) {
      fpe::test::record_failure("open_writer failed: " + std::string(writer.status().to_string()), __FILE__,
                                __LINE__);
      break;
    }
    auto published = writer.value().publish(compiled.value());
    if (!published) {
      fpe::test::record_failure("publish failed: " + std::string(published.status().to_string()), __FILE__,
                                __LINE__);
      writer.value().close();
      break;
    }
    writer.value().close();
  }

  for (std::size_t i = 0; i < children.size(); ++i) {
    auto exit_code = children[i].wait();
    FPE_REQUIRE(exit_code.has_value());
    const std::string output = children[i].log_contents();
    FPE_CHECK_EQ(exit_code.value(), 0);
    if (exit_code.value() != 0) {
      std::cout << "        reader " << i << " reported: " << output << "\n";
    }
    FPE_CHECK(output.find("eval-loop-ok") != std::string::npos);
  }

  auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
  FPE_REQUIRE(reader.has_value());
  std::vector<fpe::GenerationInfo> history;
  FPE_REQUIRE(reader.value().verify_history(1000000, history).ok());
  FPE_CHECK_EQ(history.size(), std::size_t{26});
}

FPE_TEST(multiprocess_abrupt_death_during_publication_leaves_a_recoverable_store) {
  auto directory = fpe::test::TempDirectory::create("mp-crash");
  FPE_REQUIRE(directory.has_value());
  FPE_REQUIRE(fpe::create_store(directory.value().path(), Limits::defaults()).has_value());

  const std::filesystem::path policy_path = directory.value().child("policy.json");
  write_text(policy_path, std::string(kPolicy));

  fpe::test::Random random(fpe::test::global_seed() ^ 0xC0FFEEu);
  std::cout << "    seeded crash injection, seed " << (fpe::test::global_seed() ^ 0xC0FFEEu) << "\n";

  for (int round = 0; round < 6; ++round) {
    const std::filesystem::path log = directory.value().child("crasher-" + std::to_string(round) + ".log");
    auto child = fpe::test::ChildProcess::start(
        fpe::test::test_executable_path(),
        {"--child", "publish-loop", fpe::test::path_text(directory.value().path()), "process.bundle",
         fpe::test::path_text(policy_path), "400"},
        log);
    FPE_REQUIRE(child.has_value());

    // Kill somewhere inside the publishing loop, at a different point each round.
    std::this_thread::sleep_for(std::chrono::milliseconds(20 + static_cast<int>(random.below(120))));
    FPE_REQUIRE(child.value().terminate_now().ok());

    // Whatever the crash interrupted, the store must still open, still verify,
    // and still be writable. A partially written generation is never visible.
    auto reader = fpe::open_reader(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(reader.has_value());
    std::vector<fpe::GenerationInfo> history;
    FPE_REQUIRE(reader.value().verify_history(1000000, history).ok());
    FPE_CHECK_EQ(history.size(), static_cast<std::size_t>(reader.value().head().generation.raw()));
    if (reader.value().has_policy()) {
      auto policy = reader.value().policy();
      FPE_REQUIRE(policy.has_value());
      FPE_CHECK(policy.value()->digest() == reader.value().head().bundle_digest);
    }

    auto writer = fpe::open_writer(directory.value().path(), Limits::defaults());
    FPE_REQUIRE(writer.has_value());
    auto compiled = fpe::test::compile_json(kPolicy);
    FPE_REQUIRE(compiled.has_value());
    FPE_REQUIRE(writer.value().publish(compiled.value()).has_value());
    writer.value().close();
  }
}
