// HTTP/1.1 types, router and a small socket server for MC5 Offline.
//
// Gaia talks plain HTTP/1.1 with form-urlencoded bodies and JSON responses, so a
// minimal server on raw sockets is enough and keeps the embedded .so free of a
// web-framework dependency. TLS is layered on top separately (M0.3) for the
// loopback case; this file is transport-agnostic and also drives the desktop
// dev-loop host over plain HTTP.
//
// C++17.
#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace mc5 {

struct Request {
    std::string method;                         // "GET", "POST", ...
    std::string path;                           // decoded path, no query
    std::string raw_target;                     // original request target
    std::string query;                          // raw query string (after '?')
    std::map<std::string, std::string> headers; // lower-cased header names
    std::string body;

    std::map<std::string, std::string> params;  // captured path params ({x}, {*rest})
    std::map<std::string, std::string> query_params; // parsed query
    std::map<std::string, std::string> form;    // parsed form body (if urlencoded)

    std::string param(const std::string& k) const {
        auto it = params.find(k);
        return it == params.end() ? std::string() : it->second;
    }
    // A request value: query string first, then form body (matches Gaia's placement rules).
    std::string value(const std::string& k) const {
        auto it = query_params.find(k);
        if (it != query_params.end()) return it->second;
        auto jt = form.find(k);
        return jt == form.end() ? std::string() : jt->second;
    }
    std::string header(const std::string& k) const {
        auto it = headers.find(k);
        return it == headers.end() ? std::string() : it->second;
    }
};

struct Response {
    int status = 200;
    std::string content_type = "application/json";
    std::string body;
    std::map<std::string, std::string> extra_headers;

    static Response json(const std::string& text, int status = 200) {
        Response r;
        r.status = status;
        r.content_type = "application/json";
        r.body = text;
        return r;
    }
    static Response text(const std::string& text, int status = 200) {
        Response r;
        r.status = status;
        r.content_type = "text/plain";
        r.body = text;
        return r;
    }
};

using Handler = std::function<Response(const Request&)>;

// URL-decode and form/query parsing helpers (shared with services).
std::string url_decode(const std::string& s);
std::map<std::string, std::string> parse_urlencoded(const std::string& s);
std::vector<std::string> split_path(const std::string& path); // normalizes // and strips empties

// Routes are (method, pattern) where a pattern segment may be a literal, "{name}"
// (one segment capture) or "{*name}" (captures the rest of the path).
class Router {
public:
    void add(const std::string& method, const std::string& pattern, Handler h);
    void set_fallback(Handler h) { fallback_ = std::move(h); }

    // Service names that pandora/locate hands out as a path prefix
    // (base + "<service>/"). When a request does not match any route and its
    // first segment is one of these, routing is retried with that segment
    // stripped, so both "/auth/authorize" and "/authorize" resolve. eve's own
    // "config/..." routes are registered directly and match before any strip.
    void set_service_prefixes(std::vector<std::string> names) { prefixes_ = std::move(names); }

    // Returns the matched response. Fills req.params on a match. Uses the
    // fallback (or a 404) when nothing matches.
    Response route(Request& req) const;

    // For diagnostics: the registered route list.
    std::vector<std::string> routes() const;

private:
    struct Route {
        std::string method;
        std::vector<std::string> segments;
        bool tail = false;              // last segment is {*name}
        std::string tail_name;
        Handler handler;
    };
    // Tries to match req against the registered routes using the given segments.
    // On a match, fills req.params and sets out. Returns false on no match.
    bool match(Request& req, const std::vector<std::string>& segs, Response& out) const;

    std::vector<Route> routes_;
    std::vector<std::string> prefixes_;
    Handler fallback_;
};

} // namespace mc5
