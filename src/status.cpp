#include "fpe/status.hpp"

#include <utility>

namespace fpe {

std::string_view error_code_name(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok: return "ok";
    case ErrorCode::PathEmpty: return "path-empty";
    case ErrorCode::PathInvalid: return "path-invalid";
    case ErrorCode::PathTooLong: return "path-too-long";
    case ErrorCode::NotFound: return "not-found";
    case ErrorCode::AlreadyExists: return "already-exists";
    case ErrorCode::NotADirectory: return "not-a-directory";
    case ErrorCode::IoFailure: return "io-failure";
    case ErrorCode::AccessDenied: return "access-denied";
    case ErrorCode::LockHeld: return "lock-held";
    case ErrorCode::LockUnavailable: return "lock-unavailable";
    case ErrorCode::LockFailure: return "lock-failure";
    case ErrorCode::FlushFailure: return "flush-failure";
    case ErrorCode::RenameFailure: return "rename-failure";
    case ErrorCode::ReadBackMismatch: return "read-back-mismatch";
    case ErrorCode::BadMagic: return "bad-magic";
    case ErrorCode::UnsupportedVersion: return "unsupported-version";
    case ErrorCode::WrongRecordKind: return "wrong-record-kind";
    case ErrorCode::BadDeclaredLength: return "bad-declared-length";
    case ErrorCode::TrailingBytes: return "trailing-bytes";
    case ErrorCode::ChecksumMismatch: return "checksum-mismatch";
    case ErrorCode::DigestMismatch: return "digest-mismatch";
    case ErrorCode::MissingRecord: return "missing-record";
    case ErrorCode::CorruptManifest: return "corrupt-manifest";
    case ErrorCode::RollbackDetected: return "rollback-detected";
    case ErrorCode::OutOfRange: return "out-of-range";
    case ErrorCode::CounterOverflow: return "counter-overflow";
    case ErrorCode::InvalidState: return "invalid-state";
    case ErrorCode::ReservedNotZero: return "reserved-not-zero";
    case ErrorCode::StoreNotEmpty: return "store-not-empty";
    case ErrorCode::StoreEmpty: return "store-empty";
    case ErrorCode::UnsupportedOperation: return "unsupported-operation";
    case ErrorCode::InvalidIdentifier: return "invalid-identifier";
    case ErrorCode::InvalidUtf8: return "invalid-utf8";
    case ErrorCode::TextTooLong: return "text-too-long";
    case ErrorCode::EmptyText: return "empty-text";
    case ErrorCode::ReservedIdentifier: return "reserved-identifier";
    case ErrorCode::JsonSyntax: return "json-syntax";
    case ErrorCode::JsonDepthExceeded: return "json-depth-exceeded";
    case ErrorCode::JsonNodeLimit: return "json-node-limit";
    case ErrorCode::JsonDuplicateKey: return "json-duplicate-key";
    case ErrorCode::JsonNumberOutOfRange: return "json-number-out-of-range";
    case ErrorCode::JsonTypeMismatch: return "json-type-mismatch";
    case ErrorCode::JsonMissingField: return "json-missing-field";
    case ErrorCode::JsonUnknownField: return "json-unknown-field";
    case ErrorCode::JsonNotCanonical: return "json-not-canonical";
    case ErrorCode::JsonTrailingContent: return "json-trailing-content";
    case ErrorCode::PolicySchema: return "policy-schema";
    case ErrorCode::DuplicateIdentity: return "duplicate-identity";
    case ErrorCode::UnknownReference: return "unknown-reference";
    case ErrorCode::CycleDetected: return "cycle-detected";
    case ErrorCode::ImportConflict: return "import-conflict";
    case ErrorCode::IncompatibleBundle: return "incompatible-bundle";
    case ErrorCode::UnsupportedConstruct: return "unsupported-construct";
    case ErrorCode::LimitExceeded: return "limit-exceeded";
    case ErrorCode::EvaluationLimitReached: return "evaluation-limit-reached";
    case ErrorCode::UnknownInput: return "unknown-input";
    case ErrorCode::StalePolicyGeneration: return "stale-policy-generation";
    case ErrorCode::StaleControlEpoch: return "stale-control-epoch";
    case ErrorCode::DigestBindingMismatch: return "digest-binding-mismatch";
    case ErrorCode::DecisionNotCurrent: return "decision-not-current";
    case ErrorCode::InternalError: return "internal-error";
  }
  return "unrecognized-error-code";
}

Status Status::failure(ErrorCode code, std::string message) {
  Status status;
  // Reporting "ok" as a failure is a programming error; it must never produce a
  // status that claims success.
  status.code_ = code == ErrorCode::Ok ? ErrorCode::InternalError : code;
  status.message_ = std::move(message);
  return status;
}

Status& Status::add_secondary(std::string note) {
  if (!ok()) {
    secondary_.push_back(std::move(note));
  }
  return *this;
}

Status Status::prefer(Status a, Status b) {
  if (a.ok()) {
    return b;
  }
  if (b.ok()) {
    return a;
  }
  if (error_precedes(b.code_, a.code_)) {
    b.secondary_.push_back("suppressed " + a.to_string());
    return b;
  }
  a.secondary_.push_back("suppressed " + b.to_string());
  return a;
}

std::string Status::to_string() const {
  if (ok()) {
    return "ok";
  }
  std::string out;
  out.reserve(message_.size() + 32);
  out.append(error_code_name(code_));
  out.append(": ");
  out.append(message_);
  for (const auto& note : secondary_) {
    out.append("\n  ");
    out.append(note);
  }
  return out;
}

}  // namespace fpe
