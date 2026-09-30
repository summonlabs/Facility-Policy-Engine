#include <cstdint>
#include <string>
#include <string_view>

#include "fpe/json.hpp"
#include "fpe/types.hpp"
#include "test_support.hpp"

using fpe::ErrorCode;
using fpe::FactKey;
using fpe::Limits;
using fpe::Status;

namespace {

Status parse_status(std::string_view text) {
  const Limits limits = Limits::defaults();
  auto parsed = fpe::parse_json(text, limits);
  return parsed ? Status::success() : parsed.status();
}

bool parses(std::string_view text) {
  const Limits limits = Limits::defaults();
  return static_cast<bool>(fpe::parse_json(text, limits));
}

std::string canonical(std::string_view text) {
  const Limits limits = Limits::defaults();
  auto parsed = fpe::parse_json(text, limits);
  if (!parsed) {
    return std::string("<parse failed: ") + std::string(parsed.status().to_string()) + ">";
  }
  return fpe::to_canonical_json(parsed.value());
}

}  // namespace

FPE_TEST(types_identifier_accepts_only_the_documented_alphabet) {
  const Limits limits = Limits::defaults();
  const auto check_valid = [&limits](std::string_view text) {
    FPE_CHECK(FactKey::parse(text, limits.max_identifier_bytes).has_value());
  };
  const auto check_invalid = [&limits](std::string_view text) {
    FPE_CHECK(!FactKey::parse(text, limits.max_identifier_bytes).has_value());
  };

  check_valid("a");
  check_valid("zone.temperature");
  check_valid("tenant:alpha");
  check_valid("rack-07");
  check_valid("_internal");
  check_valid("A1.b2:C3_d4-e5");

  check_invalid("");
  check_invalid(".leading");
  check_invalid("trailing.");
  check_invalid("trailing-");
  check_invalid("-leading");
  check_invalid("a..b");
  check_invalid("a b");
  check_invalid("a/b");
  check_invalid("a*b");
  check_invalid("na\xC3\xAFve");
  check_invalid(std::string("a\0b", 3));
}

FPE_TEST(types_identifier_rejects_reserved_device_names) {
  const Limits limits = Limits::defaults();
  for (const std::string_view name : {"CON", "con", "Con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1",
                                      "lpt9", "CON.txt", "nul.json"}) {
    FPE_CHECK(!FactKey::parse(name, limits.max_identifier_bytes).has_value());
  }
  for (const std::string_view name : {"CONS", "COM0", "COM10", "LPT0", "NULL", "AUXILIARY"}) {
    FPE_CHECK(FactKey::parse(name, limits.max_identifier_bytes).has_value());
  }
  // A device name is recognised before the first dot, so a suffixed form is
  // still the device.
  FPE_CHECK(!FactKey::parse("con.x.y", limits.max_identifier_bytes).has_value());
}

FPE_TEST(types_identifier_length_bound_is_inclusive_and_enforced) {
  const Limits limits = Limits::defaults();
  const std::string at_limit(limits.max_identifier_bytes, 'a');
  const std::string over_limit(limits.max_identifier_bytes + 1, 'a');
  FPE_CHECK(FactKey::parse(at_limit, limits.max_identifier_bytes).has_value());
  FPE_CHECK(!FactKey::parse(over_limit, limits.max_identifier_bytes).has_value());
}

FPE_TEST(types_utf8_validation_rejects_every_malformed_class) {
  FPE_CHECK(fpe::is_valid_utf8(""));
  FPE_CHECK(fpe::is_valid_utf8("plain ascii"));
  FPE_CHECK(fpe::is_valid_utf8("\xC3\xA9"));
  FPE_CHECK(fpe::is_valid_utf8("\xE2\x82\xAC"));
  FPE_CHECK(fpe::is_valid_utf8("\xF0\x9F\x98\x80"));

  FPE_CHECK(!fpe::is_valid_utf8("\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xC0\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xC1\xBF"));
  FPE_CHECK(!fpe::is_valid_utf8("\xE0\x80\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xF0\x80\x80\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xED\xA0\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xED\xBF\xBF"));
  FPE_CHECK(!fpe::is_valid_utf8("\xF4\x90\x80\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xF5\x80\x80\x80"));
  FPE_CHECK(!fpe::is_valid_utf8("\xFF"));
  FPE_CHECK(!fpe::is_valid_utf8("\xE2\x82"));
}

FPE_TEST(types_text_rejects_control_and_bidirectional_characters) {
  const Limits limits = Limits::defaults();
  const auto acceptable = [&limits](std::string_view text) {
    return !fpe::text_violation(text, limits.max_text_bytes, true).has_value();
  };
  FPE_CHECK(acceptable("ordinary policy text"));
  FPE_CHECK(acceptable(""));
  FPE_CHECK(acceptable("\xE2\x80\xA8"));
  FPE_CHECK(!acceptable(std::string("a\0b", 3)));
  FPE_CHECK(!acceptable("line\nbreak"));
  FPE_CHECK(!acceptable("tab\there"));
  FPE_CHECK(!acceptable("\xE2\x80\xAE"));
  FPE_CHECK(!acceptable("\xEF\xBB\xBF"));
  FPE_CHECK(!acceptable("del\x7F"));

  const std::string too_long(limits.max_text_bytes + 1, 'x');
  FPE_CHECK(fpe::text_violation(too_long, limits.max_text_bytes, true).has_value());
  FPE_CHECK(fpe::text_violation("", limits.max_text_bytes, false).has_value());
}

FPE_TEST(types_counters_never_wrap) {
  auto top = fpe::Generation::from_raw(fpe::Generation::kMax);
  FPE_CHECK(!top.try_increment());
  FPE_CHECK_EQ(top.raw(), fpe::Generation::kMax);
  FPE_CHECK(!top.try_add(1));
  FPE_CHECK(top.try_add(0));
  FPE_CHECK(!top.next().has_value());
  FPE_CHECK_EQ(top.next().status().code(), ErrorCode::CounterOverflow);

  auto near = fpe::Generation::from_raw(fpe::Generation::kMax - 1);
  auto incremented = near.next();
  FPE_REQUIRE(incremented.has_value());
  FPE_CHECK_EQ(incremented.value().raw(), fpe::Generation::kMax);
  FPE_CHECK(!near.try_add(2));
}

FPE_TEST(types_status_precedence_is_deterministic_and_keeps_evidence) {
  const Status format = Status::failure(ErrorCode::BadMagic, "bad magic");
  const Status io = Status::failure(ErrorCode::IoFailure, "io failed");
  const Status semantic = Status::failure(ErrorCode::OutOfRange, "out of range");
  const Status limit = Status::failure(ErrorCode::LimitExceeded, "too many");

  const Status io_over_format = Status::prefer(format, io);
  FPE_CHECK_EQ(io_over_format.code(), ErrorCode::IoFailure);
  FPE_CHECK(!io_over_format.secondary().empty());

  const Status format_over_semantic = Status::prefer(semantic, format);
  FPE_CHECK_EQ(format_over_semantic.code(), ErrorCode::BadMagic);

  const Status semantic_over_limit = Status::prefer(limit, semantic);
  FPE_CHECK_EQ(semantic_over_limit.code(), ErrorCode::OutOfRange);

  const Status with_ok = Status::prefer(Status::success(), io);
  FPE_CHECK_EQ(with_ok.code(), ErrorCode::IoFailure);
  const Status ok_loses = Status::prefer(io, Status::success());
  FPE_CHECK_EQ(ok_loses.code(), ErrorCode::IoFailure);

  FPE_CHECK(Status::success().ok());
  FPE_CHECK(!Status::failure(ErrorCode::Ok, "should become internal").ok());
  FPE_CHECK_EQ(Status::failure(ErrorCode::Ok, "x").code(), ErrorCode::InternalError);
}

FPE_TEST(json_canonical_order_is_byte_order) {
  FPE_CHECK_EQ(canonical("{\"b\":2,\"a\":1}"), std::string("{\"a\":1,\"b\":2}"));
  FPE_CHECK_EQ(canonical("{ \"z\" : [ 3 , 2 , 1 ] , \"a\" : { } }"), std::string("{\"a\":{},\"z\":[3,2,1]}"));
  FPE_CHECK_EQ(canonical("[]"), std::string("[]"));
  FPE_CHECK_EQ(canonical("{}"), std::string("{}"));
  FPE_CHECK_EQ(canonical("null"), std::string("null"));
  FPE_CHECK_EQ(canonical("true"), std::string("true"));
  FPE_CHECK_EQ(canonical("  \"x\"  "), std::string("\"x\""));
}

FPE_TEST(json_canonical_round_trip_is_exact) {
  const std::string source =
      "{\"nested\":{\"b\":[1,2,{\"c\":null}],\"a\":\"text\"},\"top\":true,\"n\":-9223372036854775808}";
  const std::string once = canonical(source);
  const std::string twice = canonical(once);
  FPE_CHECK_EQ(once, twice);

  const Limits limits = Limits::defaults();
  FPE_CHECK(fpe::require_canonical_json(once, limits).ok());
  FPE_CHECK(fpe::require_canonical_json(once + "\n", limits).ok());
  FPE_CHECK(!fpe::require_canonical_json(source, limits).ok());
  FPE_CHECK(!fpe::require_canonical_json("  " + once, limits).ok());
}

FPE_TEST(json_rejects_every_hostile_document_class) {
  FPE_CHECK(!parses(""));
  FPE_CHECK(!parses("   "));
  FPE_CHECK(!parses("\xEF\xBB\xBF{}"));
  FPE_CHECK(!parses("{}{}"));
  FPE_CHECK(!parses("{} x"));
  FPE_CHECK(!parses("{\"a\":1,}"));
  FPE_CHECK(!parses("[1,2,]"));
  FPE_CHECK(!parses("{'a':1}"));
  FPE_CHECK(!parses("{a:1}"));
  FPE_CHECK(!parses("{\"a\":01}"));
  FPE_CHECK(!parses("{\"a\":+1}"));
  FPE_CHECK(!parses("{\"a\":.5}"));
  FPE_CHECK(!parses("{\"a\":1.0}"));
  FPE_CHECK(!parses("{\"a\":1e3}"));
  FPE_CHECK(!parses("{\"a\":NaN}"));
  FPE_CHECK(!parses("{\"a\":Infinity}"));
  FPE_CHECK(!parses("{\"a\":-}"));
  FPE_CHECK(!parses("{\"a\":tru}"));
  FPE_CHECK(!parses("{\"a\":\"unterminated}"));
  FPE_CHECK(!parses("{\"a\":\"raw\ncontrol\"}"));
  FPE_CHECK(!parses("{\"a\":\"bad \\x escape\"}"));
  FPE_CHECK(!parses("{\"a\":\"\\uD800\"}"));
  FPE_CHECK(!parses("{\"a\":\"\\uDC00\"}"));
  FPE_CHECK(!parses("{\"a\":\"\\uD800\\u0041\"}"));
  FPE_CHECK(!parses("{\"a\":\"\\u12\"}"));
  FPE_CHECK(!parses("{\"a\":\"\xC3\x28\"}"));
  FPE_CHECK(!parses("{\"a\":\"\xFF\xFE\"}"));
}

FPE_TEST(json_rejects_duplicate_keys) {
  const Status status = parse_status("{\"a\":1,\"a\":2}");
  FPE_CHECK_EQ(status.code(), ErrorCode::JsonDuplicateKey);
  FPE_CHECK(!parses("{\"a\":{\"b\":1,\"b\":2}}"));
  FPE_CHECK(parses("{\"a\":1,\"A\":2}"));
}

FPE_TEST(json_integer_range_is_exact) {
  FPE_CHECK(parses("{\"a\":9223372036854775807}"));
  FPE_CHECK(parses("{\"a\":-9223372036854775808}"));
  FPE_CHECK(!parses("{\"a\":9223372036854775808}"));
  FPE_CHECK(!parses("{\"a\":-9223372036854775809}"));
  FPE_CHECK(!parses("{\"a\":99999999999999999999999999}"));

  const Limits limits = Limits::defaults();
  auto minimum = fpe::parse_json("{\"a\":-9223372036854775808}", limits);
  FPE_REQUIRE(minimum.has_value());
  const fpe::JsonValue* member = minimum.value().member("a");
  FPE_REQUIRE(member != nullptr);
  FPE_REQUIRE(member->as_integer() != nullptr);
  FPE_CHECK(*member->as_integer() == (std::numeric_limits<std::int64_t>::min)());
}

FPE_TEST(json_bounds_are_enforced_before_allocation) {
  Limits limits = Limits::defaults();
  limits.max_json_depth = 4;
  limits.max_json_nodes = 8;

  auto nested = fpe::parse_json("[[[[[[[[[1]]]]]]]]]", limits);
  FPE_CHECK(!nested.has_value());
  FPE_CHECK_EQ(nested.status().code(), ErrorCode::JsonDepthExceeded);

  auto nodes = fpe::parse_json("[1,2,3,4,5,6,7,8,9,10]", limits);
  FPE_CHECK(!nodes.has_value());
  FPE_CHECK_EQ(nodes.status().code(), ErrorCode::JsonNodeLimit);

  auto allowed = fpe::parse_json("[[[1]]]", limits);
  FPE_CHECK(allowed.has_value());
}

FPE_TEST(json_string_escapes_decode_exactly) {
  const Limits limits = Limits::defaults();
  auto parsed = fpe::parse_json("{\"a\":\"\\u0041\\u00e9\\u20ac\\ud83d\\ude00\\n\\t\\\"\\\\\\/\"}", limits);
  FPE_REQUIRE(parsed.has_value());
  const fpe::JsonValue* member = parsed.value().member("a");
  FPE_REQUIRE(member != nullptr);
  FPE_REQUIRE(member->as_string() != nullptr);
  const std::string expected = "A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80\n\t\"\\/";
  FPE_CHECK_EQ(*member->as_string(), expected);

  const std::string once = fpe::to_canonical_json(parsed.value());
  auto reparsed = fpe::parse_json(once, limits);
  FPE_REQUIRE(reparsed.has_value());
  FPE_CHECK_EQ(fpe::to_canonical_json(reparsed.value()), once);
}
