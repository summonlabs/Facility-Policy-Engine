#ifndef FPE_PLATFORM_HPP
#define FPE_PLATFORM_HPP

// Internal operating-system boundary for the durable policy store.
//
// Everything that depends on the host file system is declared here and
// implemented once per platform. No other translation unit in this project
// calls the operating system directly, so the durability, sharing, flushing,
// and locking guarantees have exactly one place to be reviewed and one place to
// be tested.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "fpe/status.hpp"

namespace fpe::platform {

/// An owning native file handle.
///
/// The handle is closed on destruction, which matters for the writer lock: the
/// kernel releases an exclusive share or an flock when the last handle closes,
/// including when the process dies, so a crashed writer never leaves the store
/// permanently locked.
class FileHandle {
 public:
  FileHandle() noexcept = default;
  ~FileHandle();

  FileHandle(FileHandle&& other) noexcept;
  FileHandle& operator=(FileHandle&& other) noexcept;
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;

  bool is_open() const noexcept;
  void close() noexcept;

  std::intptr_t native() const noexcept { return native_; }

 private:
  friend Result<FileHandle> acquire_writer_lock(const std::filesystem::path& path);
  friend Result<FileHandle> create_exclusive(const std::filesystem::path& path);
  friend Result<FileHandle> open_for_read(const std::filesystem::path& path);

  explicit FileHandle(std::intptr_t native) noexcept : native_(native) {}

  std::intptr_t native_ = -1;
};

/// Takes the single-writer lock for a store directory.
///
/// Fails with LockHeld when another live process holds it. The lock is released
/// by the kernel when the holding process exits for any reason.
Result<FileHandle> acquire_writer_lock(const std::filesystem::path& path);

/// Creates a file that must not already exist, with no sharing permitted.
Result<FileHandle> create_exclusive(const std::filesystem::path& path);

/// Opens an existing file for reading, sharing it with concurrent readers and
/// with a writer that is about to replace it.
Result<FileHandle> open_for_read(const std::filesystem::path& path);

Status write_all(FileHandle& handle, const void* data, std::size_t size);
Status flush_file(FileHandle& handle);

/// Reads a whole file. Refuses anything larger than \\p max_bytes before
/// allocating.
Result<std::vector<std::byte>> read_file(const std::filesystem::path& path, std::uint64_t max_bytes);

/// Atomically replaces \\p destination with \\p source, flushing the metadata
/// change so that the replacement is durable before it is observed.
Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& destination);

Status remove_file(const std::filesystem::path& path) noexcept;
bool file_exists(const std::filesystem::path& path) noexcept;
Status ensure_directory(const std::filesystem::path& path);
Status list_directory(const std::filesystem::path& path, std::vector<std::string>& names);

/// Cryptographically strong bytes, used only to mint a durable store identity.
Result<std::vector<std::byte>> random_bytes(std::size_t count);

/// Refuses a path that cannot be handled safely: empty, too long, containing a
/// control character, or containing a reserved device-name component. Such a
/// component is refused rather than sanitized, because silently rewriting an
/// operator-supplied path is worse than refusing it.
Status validate_path(const std::filesystem::path& path, std::size_t max_utf8_bytes);

/// UTF-8 rendering of a path, for diagnostics only.
std::string path_text(const std::filesystem::path& path);

/// A unique temporary name in the same directory as \\p target, so that the
/// later rename stays within one volume and is therefore atomic.
std::filesystem::path temporary_sibling(const std::filesystem::path& target, std::string_view tag);

}  // namespace fpe::platform

#endif  // FPE_PLATFORM_HPP
