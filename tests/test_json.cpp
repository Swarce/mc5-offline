#include "../server/core/json.hpp"
#include "check.hpp"

using mc5::Json;

int main() {
    // round-trip primitives
    CHECK_EQ(Json::parse("true").as_bool(), true);
    CHECK_EQ(Json::parse("42").as_int(), 42);
    CHECK_EQ(Json::parse("-7").as_int(), -7);
    CHECK(Json::parse("3.5").as_double() == 3.5);
    CHECK_EQ(Json::parse("\"hi\"").as_string(), std::string("hi"));
    CHECK(Json::parse("null").is_null());

    // object order preserved on dump
    Json o = Json::object();
    o["name"] = "mc5";
    o["status"] = "active";
    o["preferred"] = true;
    CHECK_EQ(o.dump(), std::string("{\"name\":\"mc5\",\"status\":\"active\",\"preferred\":true}"));

    // array
    Json a = Json::array();
    a.push_back(1);
    a.push_back("x");
    CHECK_EQ(a.dump(), std::string("[1,\"x\"]"));
    CHECK_EQ(a.size(), std::size_t(2));

    // nested parse + access
    Json n = Json::parse("{\"a\":{\"b\":[1,2,3]},\"c\":\"d\"}");
    CHECK(n.is_object());
    CHECK_EQ(n["a"]["b"].size(), std::size_t(3));
    CHECK_EQ(n["a"]["b"].at(2).as_int(), 3);
    CHECK_EQ(n["c"].as_string(), std::string("d"));
    CHECK(n["missing"].is_null());

    // string escapes round-trip
    Json s = Json("a\"b\\c\nd\t\x01");
    Json s2 = Json::parse(s.dump());
    CHECK_EQ(s2.as_string(), s.as_string());

    // unicode escape decode
    CHECK_EQ(Json::parse("\"\\u0041\"").as_string(), std::string("A"));

    // malformed input rejected
    Json tmp;
    CHECK(!Json::try_parse("{bad", tmp));
    CHECK(!Json::try_parse("[1,2", tmp));
    CHECK(!Json::try_parse("", tmp));

    if (mc5test::failures() == 0) std::printf("test_json: OK\n");
    return mc5test::failures();
}
