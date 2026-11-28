// xbox2pc/src/json_reader.cpp — recursive-descent reader for the runtime's
// own JSON (see include/xbox2pc/json_reader.hpp).

#include "xbox2pc/json_reader.hpp"

#include <cmath>
#include <cstdlib>
#include <cstring>

namespace xbox2pc::json {
namespace {

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text) {}

    Json parse() {
        Json value = this->value();
        skip_space();
        if (pos_ != s_.size()) fail("trailing characters");
        return value;
    }

private:
    const std::string& s_;
    std::size_t pos_ = 0;
    int depth_ = 0;

    [[noreturn]] void fail(const std::string& what) const {
        throw JsonParseError(what + " at byte " + std::to_string(pos_));
    }

    void skip_space() {
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            ++pos_;
        }
    }

    char peek() const {
        if (pos_ >= s_.size()) fail("unexpected end of input");
        return s_[pos_];
    }

    void expect(char c) {
        if (peek() != c) fail(std::string("expected '") + c + "'");
        ++pos_;
    }

    bool literal(const char* word) {
        const std::size_t n = std::strlen(word);
        if (s_.compare(pos_, n, word) == 0) {
            pos_ += n;
            return true;
        }
        return false;
    }

    static void append_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80u) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800u) {
            out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp < 0x10000u) {
            out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else {
            out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        }
    }

    std::uint32_t hex4() {
        std::uint32_t v = 0;
        for (int n = 0; n < 4; ++n) {
            const char c = peek();
            ++pos_;
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
            else fail("bad \\u escape");
        }
        return v;
    }

    Json string() {
        expect('"');
        std::string out;
        for (;;) {
            const char c = peek();
            ++pos_;
            if (c == '"') break;
            if (c == '\\') {
                const char esc = peek();
                ++pos_;
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        std::uint32_t cp = hex4();
                        if (cp >= 0xD800u && cp <= 0xDBFFu) {
                            if (pos_ + 1 < s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
                                pos_ += 2;
                                const std::uint32_t low = hex4();
                                if (low < 0xDC00u || low > 0xDFFFu) fail("bad low surrogate");
                                cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
                            } else {
                                fail("unpaired high surrogate");
                            }
                        } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                            fail("unpaired low surrogate");
                        }
                        append_utf8(out, cp);
                        break;
                    }
                    default: fail("bad escape");
                }
            } else if (static_cast<unsigned char>(c) < 0x20u) {
                fail("control character in string");
            } else {
                out.push_back(c);
            }
        }
        return Json(std::move(out));
    }

    Json number() {
        const std::size_t start = pos_;
        bool is_double = false;
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c == '.' || c == 'e' || c == 'E') is_double = true;
            if ((c < '0' || c > '9') && c != '-' && c != '+' && c != '.' && c != 'e' && c != 'E') break;
            ++pos_;
        }
        if (pos_ == start) fail("expected a value");
        const std::string token = s_.substr(start, pos_ - start);
        if (is_double) {
            char* end = nullptr;
            const double d = std::strtod(token.c_str(), &end);
            if (end == nullptr || *end != '\0' || std::isnan(d)) fail("bad number");
            return Json(d);
        }
        std::int64_t v = 0;
        std::size_t n = 0;
        bool negative = false;
        if (token[0] == '-') { negative = true; n = 1; }
        if (n >= token.size()) fail("bad number");
        for (; n < token.size(); ++n) {
            const int digit = token[n] - '0';
            if (digit < 0 || digit > 9) fail("bad number");
            if (v > (9223372036854775807LL - digit) / 10) fail("integer overflow");
            v = v * 10 + digit;
        }
        return Json(negative ? -v : v);
    }

    Json array() {
        ++depth_;
        if (depth_ > kMaxParseDepth) fail("nesting deeper than the limit");
        expect('[');
        Json out = Json::array();
        skip_space();
        if (peek() == ']') { ++pos_; --depth_; return out; }
        for (;;) {
            out.push_back(value());
            skip_space();
            const char c = peek();
            ++pos_;
            if (c == ']') break;
            if (c != ',') fail("expected ',' or ']'");
        }
        --depth_;
        return out;
    }

    Json object() {
        ++depth_;
        if (depth_ > kMaxParseDepth) fail("nesting deeper than the limit");
        expect('{');
        Json out = Json::object();
        skip_space();
        if (peek() == '}') { ++pos_; --depth_; return out; }
        for (;;) {
            skip_space();
            if (peek() != '"') fail("expected a string key");
            const Json key = string();
            skip_space();
            expect(':');
            out.set(key.as_string(), value());
            skip_space();
            const char c = peek();
            ++pos_;
            if (c == '}') break;
            if (c != ',') fail("expected ',' or '}'");
        }
        --depth_;
        return out;
    }

    Json value() {
        skip_space();
        switch (peek()) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't':
                if (literal("true")) return Json(true);
                fail("bad literal");
            case 'f':
                if (literal("false")) return Json(false);
                fail("bad literal");
            case 'n':
                if (literal("null")) return Json(nullptr);
                fail("bad literal");
            default: return number();
        }
    }
};

}  // namespace

Json parse(const std::string& text) {
    Parser parser(text);
    return parser.parse();
}

}  // namespace xbox2pc::json
