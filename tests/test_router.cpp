#include "../server/core/http.hpp"
#include "check.hpp"

using namespace mc5;

static Request make(const std::string& method, const std::string& path) {
    Request r;
    r.method = method;
    r.path = path;
    return r;
}

int main() {
    // helpers
    CHECK_EQ(url_decode("a%20b+c"), std::string("a b c"));
    auto q = parse_urlencoded("x=1&y=hello%20world&z");
    CHECK_EQ(q["x"], std::string("1"));
    CHECK_EQ(q["y"], std::string("hello world"));
    CHECK(q.count("z") == 1);

    // split normalizes duplicate slashes
    auto segs = split_path("//config//1924:5//datacenters");
    CHECK_EQ(segs.size(), std::size_t(3));
    CHECK_EQ(segs[0], std::string("config"));
    CHECK_EQ(segs[2], std::string("datacenters"));

    Router router;
    router.add("GET", "config/{clientId}/datacenters", [](const Request& r) {
        return Response::text("dc:" + r.param("clientId"));
    });
    router.add("GET", "config/{clientId}/datacenters/{dc}/urls", [](const Request& r) {
        return Response::text("urls:" + r.param("dc"));
    });
    router.add("*", "storage/profiles/{cred}/myprofile/{*selector}", [](const Request& r) {
        return Response::text("sel:" + r.param("selector"));
    });
    bool fell_back = false;
    router.set_fallback([&](const Request&) { fell_back = true; return Response::json("{}"); });

    // one-segment capture
    Request a = make("GET", "/config/CID/datacenters");
    CHECK_EQ(router.route(a).body, std::string("dc:CID"));

    // deeper route with its own capture, and the // tolerance
    Request b = make("GET", "//config/CID/datacenters/mc5/urls");
    CHECK_EQ(router.route(b).body, std::string("urls:mc5"));

    // tail capture across multiple segments, any method
    Request c = make("POST", "/storage/profiles/abc/myprofile/_mc5/gameProfile");
    CHECK_EQ(router.route(c).body, std::string("sel:_mc5/gameProfile"));

    // tail capture with zero trailing segments
    Request d = make("GET", "/storage/profiles/abc/myprofile");
    CHECK_EQ(router.route(d).body, std::string("sel:"));

    // length mismatch -> fallback, not a false match
    Request e = make("GET", "/config/CID/datacenters/extra/segment/here");
    router.route(e);
    CHECK(fell_back);

    if (mc5test::failures() == 0) std::printf("test_router: OK\n");
    return mc5test::failures();
}
