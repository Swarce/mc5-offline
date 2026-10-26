// Minimal dependency-free JSON for MC5 Offline.
//
// The embedded server runs inside the game process, so the core avoids heavy
// third-party libraries (as MCVS Offline did with its MiniJson). This supports
// objects, arrays, strings, numbers, booleans and null, with order-preserving
// objects so responses are reproducible. It is not a general-purpose library:
// it is only as complete as the Gaia/TS protocol needs.
//
// C++17, header-only.
#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mc5 {

class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Json() : type_(Type::Null) {}
    Json(std::nullptr_t) : type_(Type::Null) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(int v) : type_(Type::Int), int_(v) {}
    Json(long long v) : type_(Type::Int), int_(v) {}
    Json(double v) : type_(Type::Double), dbl_(v) {}
    Json(const char* s) : type_(Type::String), str_(s) {}
    Json(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }

    bool as_bool(bool def = false) const { return type_ == Type::Bool ? bool_ : def; }
    long long as_int(long long def = 0) const {
        if (type_ == Type::Int) return int_;
        if (type_ == Type::Double) return static_cast<long long>(dbl_);
        return def;
    }
    double as_double(double def = 0) const {
        if (type_ == Type::Double) return dbl_;
        if (type_ == Type::Int) return static_cast<double>(int_);
        return def;
    }
    const std::string& as_string() const { return str_; }
    std::string as_string(const std::string& def) const { return type_ == Type::String ? str_ : def; }

    // Object access. operator[] on a non-object turns it into one (write path).
    Json& operator[](const std::string& key) {
        if (type_ != Type::Object) { type_ = Type::Object; members_.clear(); }
        for (auto& kv : members_) if (kv.first == key) return kv.second;
        members_.emplace_back(key, Json());
        return members_.back().second;
    }
    const Json& operator[](const std::string& key) const {
        static const Json null;
        if (type_ == Type::Object)
            for (auto& kv : members_) if (kv.first == key) return kv.second;
        return null;
    }
    bool contains(const std::string& key) const {
        if (type_ != Type::Object) return false;
        for (auto& kv : members_) if (kv.first == key) return true;
        return false;
    }
    const std::vector<std::pair<std::string, Json>>& items() const { return members_; }

    // Array access.
    void push_back(Json v) {
        if (type_ != Type::Array) { type_ = Type::Array; elems_.clear(); }
        elems_.push_back(std::move(v));
    }
    std::size_t size() const {
        if (type_ == Type::Array) return elems_.size();
        if (type_ == Type::Object) return members_.size();
        return 0;
    }
    const Json& at(std::size_t i) const { return elems_.at(i); }
    const std::vector<Json>& elements() const { return elems_; }

    // --- serialization ---
    std::string dump() const {
        std::string out;
        write(out);
        return out;
    }

    // --- parsing; throws std::runtime_error on malformed input ---
    static Json parse(const std::string& text) {
        Parser p{text, 0};
        p.skip_ws();
        Json v = p.parse_value();
        p.skip_ws();
        if (p.pos != text.size()) throw std::runtime_error("trailing data in JSON");
        return v;
    }
    static bool try_parse(const std::string& text, Json& out) {
        try { out = parse(text); return true; } catch (...) { return false; }
    }

private:
    Type type_;
    bool bool_ = false;
    long long int_ = 0;
    double dbl_ = 0;
    std::string str_;
    std::vector<Json> elems_;
    std::vector<std::pair<std::string, Json>> members_;

    static void write_string(std::string& out, const std::string& s) {
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        static const char* hex = "0123456789abcdef";
                        out += "\\u00";
                        out += hex[(c >> 4) & 0xf];
                        out += hex[c & 0xf];
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        out += '"';
    }

    void write(std::string& out) const {
        switch (type_) {
            case Type::Null: out += "null"; break;
            case Type::Bool: out += bool_ ? "true" : "false"; break;
            case Type::Int: out += std::to_string(int_); break;
            case Type::Double: {
                // Compact round-trippable double.
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%.17g", dbl_);
                out += buf;
                break;
            }
            case Type::String: write_string(out, str_); break;
            case Type::Array: {
                out += '[';
                for (std::size_t i = 0; i < elems_.size(); ++i) {
                    if (i) out += ',';
                    elems_[i].write(out);
                }
                out += ']';
                break;
            }
            case Type::Object: {
                out += '{';
                for (std::size_t i = 0; i < members_.size(); ++i) {
                    if (i) out += ',';
                    write_string(out, members_[i].first);
                    out += ':';
                    members_[i].second.write(out);
                }
                out += '}';
                break;
            }
        }
    }

    struct Parser {
        const std::string& s;
        std::size_t pos;

        void skip_ws() {
            while (pos < s.size()) {
                char c = s[pos];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos;
                else break;
            }
        }
        [[noreturn]] void fail(const char* msg) { throw std::runtime_error(std::string("JSON: ") + msg); }
        char peek() { if (pos >= s.size()) fail("unexpected end"); return s[pos]; }

        Json parse_value() {
            skip_ws();
            char c = peek();
            switch (c) {
                case '{': return parse_object();
                case '[': return parse_array();
                case '"': return Json(parse_string());
                case 't': case 'f': return parse_bool();
                case 'n': expect("null"); return Json(nullptr);
                default: return parse_number();
            }
        }
        void expect(const char* lit) {
            for (const char* p = lit; *p; ++p) {
                if (pos >= s.size() || s[pos] != *p) fail("bad literal");
                ++pos;
            }
        }
        Json parse_bool() {
            if (s[pos] == 't') { expect("true"); return Json(true); }
            expect("false");
            return Json(false);
        }
        Json parse_number() {
            std::size_t start = pos;
            bool is_double = false;
            if (pos < s.size() && (s[pos] == '-' || s[pos] == '+')) ++pos;
            while (pos < s.size()) {
                char c = s[pos];
                if (c >= '0' && c <= '9') { ++pos; }
                else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { is_double = true; ++pos; }
                else break;
            }
            if (pos == start) fail("invalid number");
            std::string num = s.substr(start, pos - start);
            try {
                if (is_double) return Json(std::stod(num));
                return Json(static_cast<long long>(std::stoll(num)));
            } catch (...) { fail("number out of range"); }
        }
        std::string parse_string() {
            if (peek() != '"') fail("expected string");
            ++pos;
            std::string out;
            while (true) {
                if (pos >= s.size()) fail("unterminated string");
                char c = s[pos++];
                if (c == '"') break;
                if (c == '\\') {
                    if (pos >= s.size()) fail("bad escape");
                    char e = s[pos++];
                    switch (e) {
                        case '"': out += '"'; break;
                        case '\\': out += '\\'; break;
                        case '/': out += '/'; break;
                        case 'b': out += '\b'; break;
                        case 'f': out += '\f'; break;
                        case 'n': out += '\n'; break;
                        case 'r': out += '\r'; break;
                        case 't': out += '\t'; break;
                        case 'u': {
                            unsigned cp = parse_hex4();
                            if (cp >= 0xD800 && cp <= 0xDBFF && pos + 1 < s.size() && s[pos] == '\\' && s[pos + 1] == 'u') {
                                pos += 2;
                                unsigned lo = parse_hex4();
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            encode_utf8(out, cp);
                            break;
                        }
                        default: fail("bad escape char");
                    }
                } else {
                    out += c;
                }
            }
            return out;
        }
        unsigned parse_hex4() {
            if (pos + 4 > s.size()) fail("bad \\u");
            unsigned v = 0;
            for (int i = 0; i < 4; ++i) {
                char c = s[pos++];
                v <<= 4;
                if (c >= '0' && c <= '9') v |= c - '0';
                else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
                else fail("bad hex");
            }
            return v;
        }
        static void encode_utf8(std::string& out, unsigned cp) {
            if (cp <= 0x7F) out += static_cast<char>(cp);
            else if (cp <= 0x7FF) {
                out += static_cast<char>(0xC0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp <= 0xFFFF) {
                out += static_cast<char>(0xE0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                out += static_cast<char>(0xF0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        Json parse_array() {
            Json arr = Json::array();
            ++pos; // [
            skip_ws();
            if (peek() == ']') { ++pos; return arr; }
            while (true) {
                arr.push_back(parse_value());
                skip_ws();
                char c = peek();
                if (c == ',') { ++pos; continue; }
                if (c == ']') { ++pos; break; }
                fail("expected , or ]");
            }
            return arr;
        }
        Json parse_object() {
            Json obj = Json::object();
            ++pos; // {
            skip_ws();
            if (peek() == '}') { ++pos; return obj; }
            while (true) {
                skip_ws();
                std::string key = parse_string();
                skip_ws();
                if (peek() != ':') fail("expected :");
                ++pos;
                obj[key] = parse_value();
                skip_ws();
                char c = peek();
                if (c == ',') { ++pos; continue; }
                if (c == '}') { ++pos; break; }
                fail("expected , or }");
            }
            return obj;
        }
    };
};

} // namespace mc5
