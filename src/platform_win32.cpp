#include "platform.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#include "fpe/types.hpp"

namespace fpe::platform {
namespace {

Status last_error_status(ErrorCode code, std::string_view what) {
  const DWORD error = GetLastError();
  return Status::failure(code, std::string(what) + " failed with Windows error " + std::to_string(error));
}

/// A transient sharing conflict is expected on Windows: a concurrent reader, a
/// file-system filter, or an anti-malware scanner can hold a brief handle on a
/// file that is about to be replaced or removed. Those are not refusals, and
/// letting them fail a publication would make an atomic replacement
/// non-atomic from the caller's point of view.
bool is_transient_failure(DWORD error) noexcept {
  return error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION ||
         error == ERROR_LOCK_VIOLATION;
}

constexpr int kTransientAttempts = 40;
constexpr DWORD kTransientDelayMs = 5;

ErrorCode map_open_error(DWORD error) noexcept {
  switch (error) {
    case ERROR_SHARING_VIOLATION:
      return ErrorCode::LockHeld;
    case ERROR_ACCESS_DENIED:
      return ErrorCode::AccessDenied;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
      return ErrorCode::NotFound;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
      return ErrorCode::AlreadyExists;
    default:
      return ErrorCode::IoFailure;
  }
}

bool has_nul(const std::wstring& text) noexcept {
  return text.find(L'\0') != std::wstring::npos;
}

}  // namespace

FileHandle::~FileHandle() { close(); }

FileHandle::FileHandle(FileHandle&& other) noexcept : native_(other.native_) { other.native_ = -1; }

FileHandle& FileHandle::operator=(FileHandle&& other) noexcept {
  if (this != &other) {
    close();
    native_ = other.native_;
    other.native_ = -1;
  }
  return *this;
}

bool FileHandle::is_open() const noexcept { return native_ != -1; }

void FileHandle::close() noexcept {
  if (native_ != -1) {
    ::CloseHandle(reinterpret_cast<HANDLE>(native_));
    native_ = -1;
  }
}

Result<FileHandle> acquire_writer_lock(const std::filesystem::path& path) {
  // FILE_SHARE_READ (and only FILE_SHARE_READ) is what makes this a writer
  // lock: a second writer must request GENERIC_WRITE, which the sharing mode
  // denies, while readers that only open the manifest are unaffected.
  const HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return Status::failure(map_open_error(error), "acquiring the store writer lock failed with Windows error " +
                                                      std::to_string(error));
  }
  return FileHandle(reinterpret_cast<std::intptr_t>(handle));
}

Result<FileHandle> create_exclusive(const std::filesystem::path& path) {
  const HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return Status::failure(map_open_error(error), "creating '" + path_text(path) +
                                                      "' failed with Windows error " +
                                                      std::to_string(error));
  }
  return FileHandle(reinterpret_cast<std::intptr_t>(handle));
}

Result<FileHandle> open_for_read(const std::filesystem::path& path) {
  DWORD last_error = ERROR_SUCCESS;
  for (int attempt = 1; attempt <= kTransientAttempts; ++attempt) {
    const HANDLE handle =
        ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      return FileHandle(reinterpret_cast<std::intptr_t>(handle));
    }
    last_error = GetLastError();
    if (!is_transient_failure(last_error) || attempt == kTransientAttempts) {
      break;
    }
    ::Sleep(kTransientDelayMs);
  }
  return Status::failure(map_open_error(last_error),
                         "opening '" + path_text(path) + "' for reading failed with Windows error " +
                             std::to_string(last_error));
}

Status write_all(FileHandle& handle, const void* data, std::size_t size) {
  if (!handle.is_open()) {
    return Status::failure(ErrorCode::IoFailure, "write attempted on a closed file handle");
  }
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::size_t written = 0;
  while (written < size) {
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size - written, 1u << 20));
    DWORD produced = 0;
    if (::WriteFile(reinterpret_cast<HANDLE>(handle.native()), bytes + written, chunk, &produced, nullptr) == 0) {
      return last_error_status(ErrorCode::IoFailure, "writing a record");
    }
    if (produced == 0) {
      return Status::failure(ErrorCode::IoFailure, "writing a record made no progress");
    }
    written += produced;
  }
  return Status::success();
}

Status flush_file(FileHandle& handle) {
  if (!handle.is_open()) {
    return Status::failure(ErrorCode::FlushFailure, "flush attempted on a closed file handle");
  }
  if (::FlushFileBuffers(reinterpret_cast<HANDLE>(handle.native())) == 0) {
    return last_error_status(ErrorCode::FlushFailure, "flushing a record");
  }
  return Status::success();
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  auto handle = open_for_read(path);
  if (!handle) {
    return handle.status();
  }
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(reinterpret_cast<HANDLE>(handle.value().native()), &size) == 0) {
    return last_error_status(ErrorCode::IoFailure, "reading the size of a record");
  }
  if (size.QuadPart < 0) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "'" + path_text(path) + "' reports a negative size");
  }
  const auto declared = static_cast<std::uint64_t>(size.QuadPart);
  if (declared > max_bytes) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "'" + path_text(path) + "' is " + std::to_string(declared) +
                               " bytes, above the permitted maximum of " + std::to_string(max_bytes));
  }
  std::vector<std::byte> out(static_cast<std::size_t>(declared));
  std::size_t read = 0;
  while (read < out.size()) {
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - read, 1u << 20));
    DWORD produced = 0;
    if (::ReadFile(reinterpret_cast<HANDLE>(handle.value().native()), out.data() + read, chunk, &produced,
                   nullptr) == 0) {
      return last_error_status(ErrorCode::IoFailure, "reading a record");
    }
    if (produced == 0) {
      return Status::failure(ErrorCode::IoFailure,
                             "'" + path_text(path) + "' ended before its declared length");
    }
    read += produced;
  }
  return out;
}

Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& destination) {
  DWORD last_error = ERROR_SUCCESS;
  for (int attempt = 1; attempt <= kTransientAttempts; ++attempt) {
    if (::MoveFileExW(source.c_str(), destination.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0) {
      return Status::success();
    }
    last_error = GetLastError();
    if (!is_transient_failure(last_error) || attempt == kTransientAttempts) {
      break;
    }
    ::Sleep(kTransientDelayMs);
  }
  return Status::failure(ErrorCode::RenameFailure,
                         "replacing '" + path_text(destination) + "' with '" + path_text(source) +
                             "' failed with Windows error " + std::to_string(last_error) +
                             " after " + std::to_string(kTransientAttempts) + " attempts");
}

Status remove_file(const std::filesystem::path& path) noexcept {
  for (int attempt = 1; attempt <= kTransientAttempts; ++attempt) {
    if (::DeleteFileW(path.c_str()) != 0) {
      return Status::success();
    }
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Status::success();
    }
    if (!is_transient_failure(error) || attempt == kTransientAttempts) {
      return Status::failure(ErrorCode::IoFailure, "removing '" + path_text(path) +
                                                       "' failed with Windows error " +
                                                       std::to_string(error));
    }
    ::Sleep(kTransientDelayMs);
  }
  return Status::failure(ErrorCode::IoFailure, "removing '" + path_text(path) + "' failed");
}

bool file_exists(const std::filesystem::path& path) noexcept {
  std::error_code error;
  const bool exists = std::filesystem::exists(path, error);
  return exists && !error;
}

Status ensure_directory(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) {
    return Status::failure(ErrorCode::IoFailure,
                           "creating directory '" + path_text(path) + "' failed: " + error.message());
  }
  std::error_code probe;
  if (!std::filesystem::is_directory(path, probe) || probe) {
    return Status::failure(ErrorCode::NotADirectory, "'" + path_text(path) + "' is not a directory");
  }
  return Status::success();
}

Status list_directory(const std::filesystem::path& path, std::vector<std::string>& names) {
  std::error_code error;
  std::filesystem::directory_iterator iterator(path, error);
  if (error) {
    return Status::failure(ErrorCode::IoFailure,
                           "listing '" + path_text(path) + "' failed: " + error.message());
  }
  for (const auto& entry : iterator) {
    const std::string name = entry.path().filename().string();
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());
  return Status::success();
}

Result<std::vector<std::byte>> random_bytes(std::size_t count) {
  std::random_device device;
  std::vector<std::byte> out(count);
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = static_cast<std::byte>(static_cast<unsigned>(device()) & 0xFFu);
  }
  return out;
}

Status validate_path(const std::filesystem::path& path, std::size_t max_utf8_bytes) {
  const std::wstring native = path.native();
  if (native.empty()) {
    return Status::failure(ErrorCode::PathEmpty, "the store path is empty");
  }
  if (has_nul(native)) {
    return Status::failure(ErrorCode::PathInvalid, "the store path contains an embedded null character");
  }
  const std::string utf8 = path_text(path);
  if (utf8.size() > max_utf8_bytes) {
    return Status::failure(ErrorCode::PathTooLong,
                           "the store path is " + std::to_string(utf8.size()) +
                               " bytes, above the maximum of " + std::to_string(max_utf8_bytes));
  }
  for (std::size_t i = 0; i < utf8.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(utf8[i]);
    if (byte < 0x20u || byte == 0x7Fu) {
      return Status::failure(ErrorCode::PathInvalid,
                             "the store path contains a control character at byte offset " +
                                 std::to_string(i));
    }
  }
  for (const auto& component : path) {
    const std::string text = component.string();
    if (text.empty()) {
      continue;
    }
    if (is_reserved_windows_device_name(text)) {
      return Status::failure(ErrorCode::ReservedIdentifier,
                             "the store path contains the reserved device name '" + text + "'");
    }
  }
  return Status::success();
}

std::string path_text(const std::filesystem::path& path) {
  const std::u8string utf8 = path.u8string();
  return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

std::filesystem::path temporary_sibling(const std::filesystem::path& target, std::string_view tag) {
  static std::uint64_t counter = 0;
  counter += 1;
  std::filesystem::path candidate = target;
  candidate += ".tmp-";
  candidate += std::string(tag);
  candidate += "-";
  candidate += std::to_string(::GetCurrentProcessId());
  candidate += "-";
  candidate += std::to_string(counter);
  return candidate;
}

}  // namespace fpe::platform

#endif  // _WIN32
