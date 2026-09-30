#ifndef FPE_STATUS_HPP
#define FPE_STATUS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace fpe {

/// Failure classification.
///
/// The numeric value *is* the deterministic precedence. When several failures
/// coexist for a single operation, the lowest numeric code is the one reported
/// and every other failure is retained as secondary evidence. Groups, in
/// reporting order:
///
///   1xx  address, path, existence
///   2xx  operating system, locking, I/O durability
///   3xx  durable container format (magic, version, length, checksum, digest)
///   4xx  semantic range, counters, store state
///   5xx  identity, text, encoding
///   6xx  JSON document
///   7xx  policy schema, references, cycles, compatibility
///   8xx  resource limits
///   9xx  evaluation, decision, fencing
///
/// A caller that must merge failures from independent stages uses
/// ef Status::prefer, which implements exactly this ordering.
enum class ErrorCode : std::uint32_t {
  Ok = 0,

  // 1xx address / path / existence
  PathEmpty = 100,
  PathInvalid = 101,
  PathTooLong = 102,
  NotFound = 103,
  AlreadyExists = 104,
  NotADirectory = 105,

  // 2xx operating system / locking / I/O
  IoFailure = 200,
  AccessDenied = 201,
  LockHeld = 202,
  LockUnavailable = 203,
  LockFailure = 204,
  FlushFailure = 205,
  RenameFailure = 206,
  ReadBackMismatch = 207,

  // 3xx durable container format
  BadMagic = 300,
  UnsupportedVersion = 301,
  WrongRecordKind = 302,
  BadDeclaredLength = 303,
  TrailingBytes = 304,
  ChecksumMismatch = 305,
  DigestMismatch = 306,
  MissingRecord = 307,
  CorruptManifest = 308,
  RollbackDetected = 309,

  // 4xx semantic range / counters / state
  OutOfRange = 400,
  CounterOverflow = 401,
  InvalidState = 402,
  ReservedNotZero = 403,
  StoreNotEmpty = 404,
  StoreEmpty = 405,
  UnsupportedOperation = 406,

  // 5xx identity / text / encoding
  InvalidIdentifier = 500,
  InvalidUtf8 = 501,
  TextTooLong = 502,
  EmptyText = 503,
  ReservedIdentifier = 504,

  // 6xx JSON document
  JsonSyntax = 600,
  JsonDepthExceeded = 601,
  JsonNodeLimit = 602,
  JsonDuplicateKey = 603,
  JsonNumberOutOfRange = 604,
  JsonTypeMismatch = 605,
  JsonMissingField = 606,
  JsonUnknownField = 607,
  JsonNotCanonical = 608,
  JsonTrailingContent = 609,

  // 7xx policy schema
  PolicySchema = 700,
  DuplicateIdentity = 701,
  UnknownReference = 702,
  CycleDetected = 703,
  ImportConflict = 704,
  IncompatibleBundle = 705,
  UnsupportedConstruct = 706,

  // 8xx resource limits
  LimitExceeded = 800,

  // 9xx evaluation / decision / fencing
  EvaluationLimitReached = 900,
  UnknownInput = 901,
  StalePolicyGeneration = 902,
  StaleControlEpoch = 903,
  DigestBindingMismatch = 904,
  DecisionNotCurrent = 905,
  InternalError = 999,
};

/// Stable, human-readable name of a failure code. Never localized.
std::string_view error_code_name(ErrorCode code) noexcept;

/// Numeric precedence of a failure code; lower is reported first.
constexpr std::uint32_t error_precedence(ErrorCode code) noexcept {
  return static_cast<std::uint32_t>(code);
}

/// True when \p a must be reported in preference to \p b.
constexpr bool error_precedes(ErrorCode a, ErrorCode b) noexcept {
  return static_cast<std::uint32_t>(a) < static_cast<std::uint32_t>(b);
}

/// Operation outcome: either success, or the single highest-precedence failure
/// plus any secondary failures retained for diagnosis.
///
/// A Status is never silently discarded. Merging two failures through
/// ef prefer keeps the loser as secondary evidence, so a refusal always
/// remains attributable to every condition that contributed to it.
class Status {
 public:
  Status() noexcept = default;

  static Status success() noexcept { return Status(); }

  static Status failure(ErrorCode code, std::string message);

  ErrorCode code() const noexcept { return code_; }
  bool ok() const noexcept { return code_ == ErrorCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }

  std::string_view message() const noexcept { return message_; }
  const std::vector<std::string>& secondary() const noexcept { return secondary_; }

  /// Attach a suppressed/secondary observation. Ignored for successful status.
  Status& add_secondary(std::string note);

  /// Deterministic merge. The lower-precedence-ranked code wins; the other
  /// failure is appended to the winner's secondary evidence, along with its own
  /// secondary evidence, in stable order.
  static Status prefer(Status a, Status b);

  /// "code-name: message" plus secondary evidence lines.
  std::string to_string() const;

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string message_;
  std::vector<std::string> secondary_;
};

/// Value-or-failure result.
///
/// The failure path is the only way an operation reports a problem: the API
/// neither throws nor returns sentinel values, so a missing value can never be
/// mistaken for a valid one.
template <class T>
class Result {
  static_assert(!std::is_same_v<T, Status>, "Result<Status> is not a valid type; return Status directly");

 public:
  Result(T value) : value_(std::move(value)), status_(Status::success()) {}
  Result(Status status) : status_(std::move(status)) {
    if (status_.ok()) {
      status_ = Status::failure(ErrorCode::InternalError, "result constructed from a success status");
    }
  }

  bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  const T& value() const& noexcept { return *value_; }
  T& value() & noexcept { return *value_; }
  T&& value() && noexcept { return std::move(*value_); }

  /// Precondition: has_value().
  const T* operator->() const noexcept { return &*value_; }
  T* operator->() noexcept { return &*value_; }
  const T& operator*() const& noexcept { return *value_; }
  T& operator*() & noexcept { return *value_; }

  const Status& status() const noexcept { return status_; }

 private:
  std::optional<T> value_;
  Status status_;
};

}  // namespace fpe

#endif  // FPE_STATUS_HPP
