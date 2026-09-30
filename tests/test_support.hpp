#ifndef FPE_TEST_SUPPORT_HPP
#define FPE_TEST_SUPPORT_HPP

// First-party test harness.
//
// The project has no third-party runtime dependency, including in its tests, so
// the harness is small and explicit: a registry of named cases, hard and soft
// assertions, a deterministic printed seed for randomised cases, real child
// processes, and real temporary directories.

#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "fpe/digest.hpp"
#include "fpe/status.hpp"
#include "fpe/types.hpp"

namespace fpe::test {

/// Thrown by a hard assertion. Ends the current case; the runner continues with
/// the next one.
class AssertionFailure : public std::exception {
 public:
  explicit AssertionFailure(std::string message) : message_(std::move(message)) {}
  const char* what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

struct TestCase {
  std::string name;
  std::function<void()> body;
};

std::vector<TestCase>& registry();

struct Registrar {
  Registrar(std::string name, std::function<void()> body);
};

/// Records a soft failure: the current case is marked failed but keeps running.
void record_failure(const std::string& message, const char* file, int line);

/// Zeroes the soft-failure count. The runner calls this before every case and
/// treats a non-zero count as a failed case, so a soft assertion can never be
/// silently ignored.
void reset_case_failures() noexcept;
int case_failures() noexcept;

void check_bool(bool condition, const char* expression, const char* file, int line);

template <class T>
std::string debug_string(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_same_v<T, bool>) {
    return value ? "true" : "false";
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else if constexpr (std::is_convertible_v<T, std::string_view>) {
    return std::string(std::string_view(value));
  } else {
    return "<value>";
  }
}

inline std::string debug_string(const Status& status) { return status.to_string(); }
inline std::string debug_string(const Digest256& digest) { return digest.to_hex(); }

template <class Tag>
std::string debug_string(const Name<Tag>& value) {
  return value.is_set() ? value.str() : std::string("<unset>");
}

template <class Tag>
std::string debug_string(const Counter<Tag>& value) {
  return std::to_string(value.raw());
}

inline std::string debug_string(const Priority& value) { return std::to_string(value.raw()); }

template <class A, class B>
void check_equal(const A& actual, const B& expected, const char* actual_text, const char* expected_text,
                 const char* file, int line) {
  if (actual == expected) {
    return;
  }
  record_failure(std::string(actual_text) + " == " + expected_text + "\n      actual:   " +
                     debug_string(actual) + "\n      expected: " + debug_string(expected),
                 file, line);
}

/// Deterministic pseudo-random generator (SplitMix64). Every randomised case
/// prints its seed, so a failing run can be replayed exactly.
class Random {
 public:
  explicit Random(std::uint64_t seed) noexcept : state_(seed) {}

  std::uint64_t next() noexcept;
  std::uint32_t next_u32() noexcept;
  std::uint64_t below(std::uint64_t bound) noexcept;
  std::size_t index(std::size_t bound) noexcept { return static_cast<std::size_t>(below(bound)); }
  bool coin() noexcept { return (next() & 1u) != 0u; }

 private:
  std::uint64_t state_;
};

/// The seed every randomised case starts from. Fixed by default so a run is
/// reproducible; overridable with --seed.
std::uint64_t global_seed();
void set_global_seed(std::uint64_t seed);

/// A temporary directory that removes itself, including on failure paths.
class TempDirectory {
 public:
  TempDirectory() = default;
  ~TempDirectory();
  TempDirectory(TempDirectory&& other) noexcept;
  TempDirectory& operator=(TempDirectory&& other) noexcept;
  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  static Result<TempDirectory> create(std::string_view tag);

  const std::filesystem::path& path() const noexcept { return path_; }
  std::filesystem::path child(std::string_view name) const;
  bool is_open() const noexcept { return !path_.empty(); }

 private:
  std::filesystem::path path_;
};

/// One child process.
///
/// Standard output and standard error are redirected to a file rather than a
/// pipe, so a child can be left running while the parent keeps working without
/// any risk of the child blocking on a full pipe.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts \p executable with \p arguments. \p log_path receives both streams.
  static Result<ChildProcess> start(const std::filesystem::path& executable,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& log_path);

  bool running();
  /// Waits for normal termination and reports the exit code.
  Result<int> wait();
  /// Terminates the child abruptly, as a crash would: no cleanup runs and the
  /// operating system releases every handle it held.
  Status terminate_now();
  std::string log_contents() const;
  bool is_started() const noexcept { return started_; }

 private:
  void close_handles() noexcept;

  std::intptr_t process_ = -1;
  std::filesystem::path log_path_;
  bool started_ = false;
  bool finished_ = false;
  int exit_code_ = 0;
};

/// Runs \p executable to completion and returns its exit code and output.
struct ProcessResult {
  int exit_code = -1;
  std::string output;
};

Result<ProcessResult> run_process(const std::filesystem::path& executable,
                                  const std::vector<std::string>& arguments,
                                  const std::filesystem::path& log_path);

/// Records the executable paths the runner discovered, so that cases which
/// need a real child process can start one without hard-coded paths.
void set_executable_paths(std::filesystem::path test_executable, std::filesystem::path cli_executable);

const std::filesystem::path& test_executable_path();
const std::filesystem::path& cli_executable_path();

/// UTF-8 rendering of a path.
std::string path_text(const std::filesystem::path& path);

}  // namespace fpe::test

#define FPE_TEST(name)                                                                    \
  static void name();                                                                     \
  static const ::fpe::test::Registrar name##_registrar(#name, &name);                      \
  static void name()

#define FPE_REQUIRE(condition)                                                            \
  do {                                                                                    \
    if (!(condition)) {                                                                   \
      throw ::fpe::test::AssertionFailure(std::string(__FILE__) + ":" +                   \
                                          std::to_string(__LINE__) + ": required " #condition); \
    }                                                                                     \
  } while (false)

#define FPE_CHECK(condition) ::fpe::test::check_bool((condition), #condition, __FILE__, __LINE__)

#define FPE_CHECK_EQ(actual, expected)                                                    \
  ::fpe::test::check_equal((actual), (expected), #actual, #expected, __FILE__, __LINE__)

#endif  // FPE_TEST_SUPPORT_HPP
