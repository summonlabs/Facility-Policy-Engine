#include "platform.hpp"

#ifndef _WIN32

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#include "fpe/types.hpp"

namespace fpe::platform {
namespace {

Status errno_status(ErrorCode code, std::string_view what) {
  return Status::failure(code, std::string(what) + " failed: " + std::strerror(errno));
}

ErrorCode map_errno(int error) noexcept {
  switch (error) {
    case EWOULDBLOCK:
    case EAGAIN:
      return ErrorCode::LockHeld;
    case EACCES:
    case EPERM:
      return ErrorCode::AccessDenied;
    case ENOENT:
      return ErrorCode::NotFound;
    case EEXIST:
      return ErrorCode::AlreadyExists;
    case ENOTDIR:
      return ErrorCode::NotADirectory;
    default:
      return ErrorCode::IoFailure;
  }
}

/// Flushes a directory entry so that a rename survives a crash.
Status flush_directory(const std::filesystem::path& directory) {
  const int fd = ::open(directory.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return errno_status(ErrorCode::FlushFailure, "opening a directory for flushing");
  }
  const int result = ::fsync(fd);
  const int saved = errno;
  ::close(fd);
  if (result != 0) {
    errno = saved;
    return errno_status(ErrorCode::FlushFailure, "flushing a directory");
  }
  return Status::success();
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

bool FileHandle::is_open() const noexcept { return native_ >= 0; }

void FileHandle::close() noexcept {
  if (native_ >= 0) {
    ::close(static_cast<int>(native_));
    native_ = -1;
  }
}

Result<FileHandle> acquire_writer_lock(const std::filesystem::path& path) {
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0) {
    return errno_status(map_errno(errno), "opening the store writer lock file");
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    const int saved = errno;
    ::close(fd);
    errno = saved;
    return errno_status(map_errno(saved), "acquiring the store writer lock");
  }
  return FileHandle(static_cast<std::intptr_t>(fd));
}

Result<FileHandle> create_exclusive(const std::filesystem::path& path) {
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0) {
    return errno_status(map_errno(errno), "creating '" + path_text(path) + "'");
  }
  return FileHandle(static_cast<std::intptr_t>(fd));
}

Result<FileHandle> open_for_read(const std::filesystem::path& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return errno_status(map_errno(errno), "opening '" + path_text(path) + "' for reading");
  }
  return FileHandle(static_cast<std::intptr_t>(fd));
}

Status write_all(FileHandle& handle, const void* data, std::size_t size) {
  if (!handle.is_open()) {
    return Status::failure(ErrorCode::IoFailure, "write attempted on a closed file handle");
  }
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::size_t written = 0;
  while (written < size) {
    const ssize_t produced = ::write(static_cast<int>(handle.native()), bytes + written, size - written);
    if (produced < 0) {
      if (errno == EINTR) {
        continue;
      }
      return errno_status(ErrorCode::IoFailure, "writing a record");
    }
    if (produced == 0) {
      return Status::failure(ErrorCode::IoFailure, "writing a record made no progress");
    }
    written += static_cast<std::size_t>(produced);
  }
  return Status::success();
}

Status flush_file(FileHandle& handle) {
  if (!handle.is_open()) {
    return Status::failure(ErrorCode::FlushFailure, "flush attempted on a closed file handle");
  }
  if (::fsync(static_cast<int>(handle.native())) != 0) {
    return errno_status(ErrorCode::FlushFailure, "flushing a record");
  }
  return Status::success();
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  auto handle = open_for_read(path);
  if (!handle) {
    return handle.status();
  }
  struct stat info {};
  if (::fstat(static_cast<int>(handle.value().native()), &info) != 0) {
    return errno_status(ErrorCode::IoFailure, "reading the size of a record");
  }
  if (info.st_size < 0) {
    return Status::failure(ErrorCode::BadDeclaredLength, "'" + path_text(path) + "' reports a negative size");
  }
  const auto declared = static_cast<std::uint64_t>(info.st_size);
  if (declared > max_bytes) {
    return Status::failure(ErrorCode::BadDeclaredLength,
                           "'" + path_text(path) + "' is " + std::to_string(declared) +
                               " bytes, above the permitted maximum of " + std::to_string(max_bytes));
  }
  std::vector<std::byte> out(static_cast<std::size_t>(declared));
  std::size_t read = 0;
  while (read < out.size()) {
    const ssize_t produced =
        ::read(static_cast<int>(handle.value().native()), out.data() + read, out.size() - read);
    if (produced < 0) {
      if (errno == EINTR) {
        continue;
      }
      return errno_status(ErrorCode::IoFailure, "reading a record");
    }
    if (produced == 0) {
      return Status::failure(ErrorCode::IoFailure, "'" + path_text(path) + "' ended before its declared length");
    }
    read += static_cast<std::size_t>(produced);
  }
  return out;
}

Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& destination) {
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    return errno_status(ErrorCode::RenameFailure,
                        "replacing '" + path_text(destination) + "' with '" + path_text(source) + "'");
  }
  return flush_directory(destination.parent_path().empty() ? std::filesystem::path(".")
                                                           : destination.parent_path());
}

Status remove_file(const std::filesystem::path& path) noexcept {
  if (::unlink(path.c_str()) == 0) {
    return Status::success();
  }
  if (errno == ENOENT) {
    return Status::success();
  }
  return errno_status(ErrorCode::IoFailure, "removing '" + path_text(path) + "'");
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
    names.push_back(entry.path().filename().string());
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
  const std::string native = path.native();
  if (native.empty()) {
    return Status::failure(ErrorCode::PathEmpty, "the store path is empty");
  }
  if (native.find('\0') != std::string::npos) {
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

std::string path_text(const std::filesystem::path& path) { return path.string(); }

std::filesystem::path temporary_sibling(const std::filesystem::path& target, std::string_view tag) {
  static std::uint64_t counter = 0;
  counter += 1;
  std::filesystem::path candidate = target;
  candidate += ".tmp-";
  candidate += std::string(tag);
  candidate += "-";
  candidate += std::to_string(static_cast<long long>(::getpid()));
  candidate += "-";
  candidate += std::to_string(counter);
  return candidate;
}

}  // namespace fpe::platform

#endif  // !_WIN32
