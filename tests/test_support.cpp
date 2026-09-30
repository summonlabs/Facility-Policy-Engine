#include "test_support.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace fpe::test {
namespace {

std::atomic<int> g_failures{0};
int g_case_failures = 0;
std::uint64_t g_seed = 20260101ull;
std::atomic<std::uint64_t> g_temp_counter{0};

std::filesystem::path temp_root() {
  std::error_code error;
  std::filesystem::path root = std::filesystem::temp_directory_path(error);
  if (error || root.empty()) {
    root = std::filesystem::path(".");
  }
  return root / "fpe-tests";
}

void force_remove(const std::filesystem::path& path) noexcept {
  std::error_code error;
  std::filesystem::remove_all(path, error);
  if (error) {
    // A read-only attribute is the usual reason a removal fails on Windows.
    std::filesystem::permissions(path, std::filesystem::perms::owner_all | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::add, error);
    std::error_code retry;
    std::filesystem::remove_all(path, retry);
  }
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(std::string name, std::function<void()> body) {
  registry().push_back(TestCase{std::move(name), std::move(body)});
}

void record_failure(const std::string& message, const char* file, int line) {
  g_failures.fetch_add(1);
  g_case_failures += 1;
  std::cout << "    FAIL " << file << ":" << line << ": " << message << "\n";
}

void reset_case_failures() noexcept { g_case_failures = 0; }

int case_failures() noexcept { return g_case_failures; }

void check_bool(bool condition, const char* expression, const char* file, int line) {
  if (!condition) {
    record_failure(std::string("expected ") + expression, file, line);
  }
}

std::uint64_t Random::next() noexcept {
  state_ += 0x9E3779B97F4A7C15ull;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

std::uint32_t Random::next_u32() noexcept { return static_cast<std::uint32_t>(next() >> 32); }

std::uint64_t Random::below(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return next() % bound;
}

std::uint64_t global_seed() { return g_seed; }

void set_global_seed(std::uint64_t seed) { g_seed = seed; }

TempDirectory::~TempDirectory() {
  if (!path_.empty()) {
    force_remove(path_);
  }
}

TempDirectory::TempDirectory(TempDirectory&& other) noexcept : path_(std::move(other.path_)) {
  other.path_.clear();
}

TempDirectory& TempDirectory::operator=(TempDirectory&& other) noexcept {
  if (this != &other) {
    if (!path_.empty()) {
      force_remove(path_);
    }
    path_ = std::move(other.path_);
    other.path_.clear();
  }
  return *this;
}

Result<TempDirectory> TempDirectory::create(std::string_view tag) {
  const std::uint64_t counter = g_temp_counter.fetch_add(1);
  std::filesystem::path directory = temp_root() / (std::string(tag) + "-" + std::to_string(counter));
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  std::filesystem::create_directories(directory, error);
  if (error) {
    return Status::failure(ErrorCode::IoFailure,
                           "cannot create the temporary directory '" + path_text(directory) +
                               "': " + error.message());
  }
  TempDirectory result;
  result.path_ = std::move(directory);
  return result;
}

std::filesystem::path TempDirectory::child(std::string_view name) const {
  return path_ / std::filesystem::path(std::string(name));
}

std::string path_text(const std::filesystem::path& path) {
  const std::u8string utf8 = path.u8string();
  return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

#ifdef _WIN32

namespace {

std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), needed);
  return wide;
}

std::string quote_argument(const std::string& argument) {
  std::string out = "\"";
  for (const char c : argument) {
    if (c == '"') {
      out.append("\\\"");
    } else {
      out.push_back(c);
    }
  }
  out.push_back('"');
  return out;
}

}  // namespace

ChildProcess::~ChildProcess() { close_handles(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_), log_path_(std::move(other.log_path_)), started_(other.started_),
      finished_(other.finished_), exit_code_(other.exit_code_) {
  other.process_ = -1;
  other.started_ = false;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    close_handles();
    process_ = other.process_;
    log_path_ = std::move(other.log_path_);
    started_ = other.started_;
    finished_ = other.finished_;
    exit_code_ = other.exit_code_;
    other.process_ = -1;
    other.started_ = false;
  }
  return *this;
}

void ChildProcess::close_handles() noexcept {
  if (process_ != -1) {
    ::CloseHandle(reinterpret_cast<HANDLE>(process_));
    process_ = -1;
  }
}

Result<ChildProcess> ChildProcess::start(const std::filesystem::path& executable,
                                         const std::vector<std::string>& arguments,
                                         const std::filesystem::path& log_path) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;

  const HANDLE log = ::CreateFileW(log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
  if (log == INVALID_HANDLE_VALUE) {
    return Status::failure(ErrorCode::IoFailure,
                           "cannot create the child log '" + path_text(log_path) + "'");
  }

  std::string command = quote_argument(path_text(executable));
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = log;
  startup.hStdError = log;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION information{};
  std::wstring mutable_command = widen(command);
  const BOOL created = ::CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
  ::CloseHandle(log);
  if (created == 0) {
    return Status::failure(ErrorCode::IoFailure,
                           "cannot start '" + path_text(executable) + "': Windows error " +
                               std::to_string(::GetLastError()));
  }
  ::CloseHandle(information.hThread);

  ChildProcess child;
  child.process_ = reinterpret_cast<std::intptr_t>(information.hProcess);
  child.log_path_ = log_path;
  child.started_ = true;
  return child;
}

bool ChildProcess::running() {
  if (!started_ || finished_) {
    return false;
  }
  const DWORD state = ::WaitForSingleObject(reinterpret_cast<HANDLE>(process_), 0);
  if (state == WAIT_TIMEOUT) {
    return true;
  }
  if (state == WAIT_OBJECT_0) {
    DWORD code = 0;
    ::GetExitCodeProcess(reinterpret_cast<HANDLE>(process_), &code);
    exit_code_ = static_cast<int>(code);
    finished_ = true;
    return false;
  }
  return false;
}

Result<int> ChildProcess::wait() {
  if (!started_) {
    return Status::failure(ErrorCode::InvalidState, "the child process was never started");
  }
  if (finished_) {
    return exit_code_;
  }
  const DWORD state = ::WaitForSingleObject(reinterpret_cast<HANDLE>(process_), INFINITE);
  if (state != WAIT_OBJECT_0) {
    return Status::failure(ErrorCode::IoFailure, "waiting for the child process failed");
  }
  DWORD code = 0;
  if (::GetExitCodeProcess(reinterpret_cast<HANDLE>(process_), &code) == 0) {
    return Status::failure(ErrorCode::IoFailure, "reading the child exit code failed");
  }
  exit_code_ = static_cast<int>(code);
  finished_ = true;
  return exit_code_;
}

Status ChildProcess::terminate_now() {
  if (!started_ || finished_) {
    return Status::success();
  }
  if (::TerminateProcess(reinterpret_cast<HANDLE>(process_), 0xDEAD) == 0) {
    return Status::failure(ErrorCode::IoFailure, "terminating the child process failed");
  }
  ::WaitForSingleObject(reinterpret_cast<HANDLE>(process_), INFINITE);
  finished_ = true;
  return Status::success();
}

#else

ChildProcess::~ChildProcess() { close_handles(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_), log_path_(std::move(other.log_path_)), started_(other.started_),
      finished_(other.finished_), exit_code_(other.exit_code_) {
  other.process_ = -1;
  other.started_ = false;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    close_handles();
    process_ = other.process_;
    log_path_ = std::move(other.log_path_);
    started_ = other.started_;
    finished_ = other.finished_;
    exit_code_ = other.exit_code_;
    other.process_ = -1;
    other.started_ = false;
  }
  return *this;
}

void ChildProcess::close_handles() noexcept { process_ = -1; }

Result<ChildProcess> ChildProcess::start(const std::filesystem::path& executable,
                                         const std::vector<std::string>& arguments,
                                         const std::filesystem::path& log_path) {
  const int log = ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (log < 0) {
    return Status::failure(ErrorCode::IoFailure, "cannot create the child log '" + path_text(log_path) + "'");
  }
  std::vector<std::string> storage;
  storage.push_back(executable.string());
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& entry : storage) {
    argv.push_back(entry.data());
  }
  argv.push_back(nullptr);

  pid_t pid = -1;
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, log, STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, log, STDERR_FILENO);
  const int spawned = posix_spawn(&pid, executable.c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(log);
  if (spawned != 0) {
    return Status::failure(ErrorCode::IoFailure,
                           "cannot start '" + path_text(executable) + "': " + std::strerror(spawned));
  }

  ChildProcess child;
  child.process_ = static_cast<std::intptr_t>(pid);
  child.log_path_ = log_path;
  child.started_ = true;
  return child;
}

bool ChildProcess::running() {
  if (!started_ || finished_) {
    return false;
  }
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(process_), &status, WNOHANG);
  if (result == 0) {
    return true;
  }
  if (result > 0) {
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    finished_ = true;
    return false;
  }
  return false;
}

Result<int> ChildProcess::wait() {
  if (!started_) {
    return Status::failure(ErrorCode::InvalidState, "the child process was never started");
  }
  if (finished_) {
    return exit_code_;
  }
  int status = 0;
  while (::waitpid(static_cast<pid_t>(process_), &status, 0) < 0) {
    if (errno != EINTR) {
      return Status::failure(ErrorCode::IoFailure, "waiting for the child process failed");
    }
  }
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  finished_ = true;
  return exit_code_;
}

Status ChildProcess::terminate_now() {
  if (!started_ || finished_) {
    return Status::success();
  }
  if (::kill(static_cast<pid_t>(process_), SIGKILL) != 0) {
    return Status::failure(ErrorCode::IoFailure, "terminating the child process failed");
  }
  int status = 0;
  ::waitpid(static_cast<pid_t>(process_), &status, 0);
  finished_ = true;
  return Status::success();
}

#endif

std::string ChildProcess::log_contents() const {
  if (log_path_.empty()) {
    return std::string();
  }
  std::ifstream stream(log_path_, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

Result<ProcessResult> run_process(const std::filesystem::path& executable,
                                  const std::vector<std::string>& arguments,
                                  const std::filesystem::path& log_path) {
  auto child = ChildProcess::start(executable, arguments, log_path);
  if (!child) {
    return child.status();
  }
  auto code = child.value().wait();
  if (!code) {
    return code.status();
  }
  ProcessResult result;
  result.exit_code = code.value();
  result.output = child.value().log_contents();
  return result;
}

namespace {
std::filesystem::path g_test_executable;
std::filesystem::path g_cli_executable;
}  // namespace

void set_executable_paths(std::filesystem::path test_executable, std::filesystem::path cli_executable) {
  g_test_executable = std::move(test_executable);
  g_cli_executable = std::move(cli_executable);
}

const std::filesystem::path& test_executable_path() { return g_test_executable; }

const std::filesystem::path& cli_executable_path() { return g_cli_executable; }

}  // namespace fpe::test
