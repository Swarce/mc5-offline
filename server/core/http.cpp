#include "http.hpp"

namespace mc5 {

std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%' && i + 2 < s.size()) {
            auto hex = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return -1;
            };
            int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        if (c == '+') out += ' ';
        else out += c;
    }
    return out;
}

std::map<std::string, std::string> parse_urlencoded(const std::string& s) {
    std::map<std::string, std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t amp = s.find('&', i);
        if (amp == std::string::npos) amp = s.size();
        std::string pair = s.substr(i, amp - i);
        std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            if (!pair.empty()) out[url_decode(pair)] = "";
        } else {
            out[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
        }
        i = amp + 1;
    }
    return out;
}

std::vector<std::string> split_path(const std::string& path) {
    std::vector<std::string> segs;
    std::string cur;
    for (char c : path) {
        if (c == '/') {
            if (!cur.empty()) { segs.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) segs.push_back(cur);
    return segs;
}

void Router::add(const std::string& method, const std::string& pattern, Handler h) {
    Route r;
    r.method = method;
    r.handler = std::move(h);
    for (const auto& seg : split_path(pattern)) {
        if (seg.size() >= 3 && seg.front() == '{' && seg.back() == '}' && seg[1] == '*') {
            r.tail = true;
            r.tail_name = seg.substr(2, seg.size() - 3);
            r.segments.push_back(seg); // marker; handled in route()
        } else {
            r.segments.push_back(seg);
        }
    }
    routes_.push_back(std::move(r));
}

bool Router::match(Request& req, const std::vector<std::string>& reqsegs, Response& out) const {
    for (const auto& r : routes_) {
        if (r.method != req.method && r.method != "*") continue;
        std::map<std::string, std::string> caps;
        bool ok = true;
        std::size_t i = 0;
        for (; i < r.segments.size(); ++i) {
            const std::string& pat = r.segments[i];
            bool is_tail = r.tail && i + 1 == r.segments.size();
            if (is_tail) {
                std::string rest;
                for (std::size_t j = i; j < reqsegs.size(); ++j) {
                    if (j > i) rest += '/';
                    rest += reqsegs[j];
                }
                caps[r.tail_name] = rest;
                i = r.segments.size();
                // tail consumes everything, even zero segments
                goto matched;
            }
            if (i >= reqsegs.size()) { ok = false; break; }
            if (pat.size() >= 2 && pat.front() == '{' && pat.back() == '}') {
                caps[pat.substr(1, pat.size() - 2)] = reqsegs[i];
            } else if (pat != reqsegs[i]) {
                ok = false;
                break;
            }
        }
        if (ok && i == r.segments.size() && reqsegs.size() != r.segments.size()) ok = false;
    matched:
        if (ok) {
            req.params = std::move(caps);
            out = r.handler(req);
            return true;
        }
    }
    return false;
}

Response Router::route(Request& req) const {
    auto reqsegs = split_path(req.path);
    Response out;
    if (match(req, reqsegs, out)) return out;

    // No direct match: if the first segment is a service name pandora handed out
    // as a prefix (base + "<service>/"), retry with it stripped.
    if (!reqsegs.empty()) {
        for (const auto& p : prefixes_) {
            if (reqsegs[0] == p) {
                std::vector<std::string> stripped(reqsegs.begin() + 1, reqsegs.end());
                if (match(req, stripped, out)) return out;
                break;
            }
        }
    }
    if (fallback_) return fallback_(req);
    return Response::json("{}", 200);
}

std::vector<std::string> Router::routes() const {
    std::vector<std::string> out;
    for (const auto& r : routes_) {
        std::string p = r.method + " /";
        for (std::size_t i = 0; i < r.segments.size(); ++i) {
            if (i) p += '/';
            p += r.segments[i];
        }
        out.push_back(p);
    }
    return out;
}

} // namespace mc5
