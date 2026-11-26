// xbox2pc/json_writer.cpp — implementation of the strict JSON writer.

#include "xbox2pc/json_writer.hpp"

#include <cmath>
#include <cstdio>
#include <utility>

namespace xbox2pc::json {

void Json::push_back(Json v) {
    if (type_ != Type::Array) throw JsonError("push_back on non-array Json");
    arr_->push_back(std::move(v));
}

void Json::set(const std::string& key, Json v) {
    if (type_ != Type::Object) throw JsonError("set on non-object Json");
    for (auto& kv : *obj_) {
        if (kv.first == key) {
            kv.second = std::move(v);
            return;
        }
    }
    obj_->emplace_back(key, std::move(v));
}

const char* Json::type_name() const {
    switch (type_) {
        case Type::Null: return "null";
        case Type::Bool: return "bool";
        case Type::Int: return "int";
        case Type::Double: return "double";
        case Type::String: return "string";
        case Type::Array: return "array";
        case Type::Object: return "object";
    }
    return "?";
}

std::size_t Json::size() const {
    if (type_ == Type::Array) return arr_->size();
    if (type_ == Type::Object) return obj_->size();
    throw JsonError("size on non-container Json");
}

const Json& Json::at(std::size_t i) const {
    if (type_ != Type::Array) throw JsonError("at on non-array Json");
    if (i >= arr_->size()) throw JsonError("array index out of range");
    return (*arr_)[i];
}

const Json& Json::get(const std::string& key) const {
    if (type_ != Type::Object) throw JsonError("get on non-object Json");
    for (const auto& kv : *obj_) {
        if (kv.first == key) return kv.second;
    }
    throw JsonError("missing object key '" + key + "'");
}

const std::string& Json::as_string() const {
    if (type_ != Type::String) throw JsonError("as_string on non-string Json");
    return str_;
}

std::int64_t Json::as_int() const {
    if (type_ != Type::Int) throw JsonError("as_int on non-int Json");
    return int_;
}

// ── escaping ──────────────────────────────────────────────────────────────
//
// Byte-oriented: every byte < 0x20 plus 0x7F is escaped (as \uXXXX for
// control characters, with the two JSON shorthands \b \f \n \r \t); quote
// and backslash use the standard short escapes; other bytes (including
// UTF-8 continuation bytes >= 0x80) pass through unchanged so byte-strings
// from PE files survive a round trip.

std::string Json::escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const char& raw : s) {
        const auto c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c));
                    out += b;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

// ── serialization ────────────────────────────────────────────────────────

void Json::serialize_to(std::string& out, int indent, int depth, bool compact) const {
    // A negative width or depth would wrap to an enormous length; treat it as 0.
    const std::size_t width = indent > 0 ? static_cast<std::size_t>(indent) : 0;
    const std::size_t level = depth > 0 ? static_cast<std::size_t>(depth) : 0;
    const std::string pad = compact ? "" : std::string(width * level, ' ');
    const std::string pad_in = compact ? "" : std::string(width * (level + 1), ' ');
    const std::string nl = compact ? "" : "\n";

    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Int: {
            char b[32];
            std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(int_));
            out += b;
            break;
        }
        case Type::Double: {
            if (!std::isfinite(double_)) {
                throw JsonError("cannot serialize non-finite double (NaN/Inf)");
            }
            char b[64];
            std::snprintf(b, sizeof(b), "%.17g", double_);
            out += b;
            // Preserve double-ness: integral %.17g values would look like ints.
            if (std::snprintf(nullptr, 0, "%lld", static_cast<long long>(double_)) > 0 &&
                out.find('.') == std::string::npos && out.find('e') == std::string::npos &&
                out.find("inf") == std::string::npos) {
                out += ".0";
            }
            break;
        }
        case Type::String:
            out += '"';
            out += escape(str_);
            out += '"';
            break;
        case Type::Array: {
            out += '[';
            if (!arr_->empty()) {
                out += nl;
                for (std::size_t i = 0; i < arr_->size(); ++i) {
                    out += pad_in;
                    (*arr_)[i].serialize_to(out, indent, depth + 1, compact);
                    if (i + 1 < arr_->size()) out += ',';
                    out += nl;
                }
                out += pad;
            }
            out += ']';
            break;
        }
        case Type::Object: {
            out += '{';
            if (!obj_->empty()) {
                out += nl;
                for (std::size_t i = 0; i < obj_->size(); ++i) {
                    out += pad_in;
                    out += '"';
                    out += escape(obj_->operator[](i).first);
                    out += compact ? "\":" : "\": ";
                    obj_->operator[](i).second.serialize_to(out, indent, depth + 1, compact);
                    if (i + 1 < obj_->size()) out += ',';
                    out += nl;
                }
                out += pad;
            }
            out += '}';
            break;
        }
    }
}

std::string Json::serialize(int indent) const {
    std::string out;
    serialize_to(out, indent, 0, false);
    return out;
}

std::string Json::serialize_compact() const {
    std::string out;
    serialize_to(out, 0, 0, true);
    return out;
}

}  // namespace xbox2pc::json
