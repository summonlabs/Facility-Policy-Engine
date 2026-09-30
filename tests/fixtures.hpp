#ifndef FPE_TEST_FIXTURES_HPP
#define FPE_TEST_FIXTURES_HPP

// Shared document builders for the test suite. Raw string literals keep every
// fixture readable next to the behaviour it exercises.

#include <string>
#include <string_view>
#include <utility>

#include "fpe/input.hpp"
#include "fpe/json.hpp"
#include "fpe/limits.hpp"
#include "fpe/policy.hpp"
#include "fpe/status.hpp"

namespace fpe::test {

inline Result<Bundle> parse_bundle(std::string_view text, const Limits& limits = Limits::defaults()) {
  auto document = parse_json(text, limits);
  if (!document) {
    return document.status();
  }
  return bundle_from_json(document.value(), limits);
}

inline Result<CanonicalBundle> compile_json(std::string_view text, const Limits& limits = Limits::defaults()) {
  auto bundle = parse_bundle(text, limits);
  if (!bundle) {
    return bundle.status();
  }
  return compile_standalone_bundle(std::move(bundle).value(), limits);
}

inline Result<InputSet> inputs_from_json(std::string_view text, const Limits& limits = Limits::defaults()) {
  auto document = parse_json(text, limits);
  if (!document) {
    return document.status();
  }
  return input_set_from_json(document.value(), limits);
}

/// An observed integer fact document.
inline std::string observed_integer(std::string_view key, long long value) {
  return "{\"key\":\"" + std::string(key) + "\",\"type\":\"integer\",\"state\":\"observed\",\"value\":" +
         std::to_string(value) + "}";
}

/// A fact document in a state that carries no value.
inline std::string stateless_fact(std::string_view key, std::string_view type, std::string_view state) {
  return "{\"key\":\"" + std::string(key) + "\",\"type\":\"" + std::string(type) + "\",\"state\":\"" +
         std::string(state) + "\"}";
}

inline std::string input_document(const std::string& facts) {
  return "{\"schema\":1,\"facts\":[" + facts + "]}";
}

}  // namespace fpe::test

#endif  // FPE_TEST_FIXTURES_HPP
