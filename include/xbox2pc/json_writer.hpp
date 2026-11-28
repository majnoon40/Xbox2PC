#pragma once
// xbox2pc/json_writer.hpp — minimal strict JSON writer for M2 serialization.
//
// Design:
//   1. A Json object is an explicit tree (null/bool/number/string/array/
//      object) — no implicit conversions, so nothing can silently serialize
//      a pointer or an invalid value.
//   2. `serialize` produces canonical output: 2-space indent, deterministic
//      key order (insertion order), UTF-8 escaping for control chars, quote,
//      backslash; \uXXXX for control characters below 0x20.
//   3. Numbers are stored as either a typed integer or double; integers are
//      emitted exactly; doubles are emitted with %.17g and validated as
//      finite (NaN/Inf rejected) so output is always valid JSON.
//   3. All strings are byte strings; non-ASCII bytes pass through unchanged
//      (PE names are byte strings, JSON allows UTF-8 pass-through), but any
//      byte < 0x20 and 0x7F is escaped so the output stays printable-safe.
//
// This component intentionally has no dependencies outside the standard
// library so it can be reused by every later milestone.

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace xbox2pc::json {

// Thrown when a value cannot be serialized to valid JSON (e.g. NaN/Inf).
class JsonError : public std::runtime_error {
public:
    explicit JsonError(const std::string& what) : std::runtime_error(what) {}
};

class Json;
using JsonArray = std::vector<Json>;
using JsonObject = std::vector<std::pair<std::string, Json>>;  // ordered

class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    // ── constructors ──
    Json() : type_(Type::Null) {}
    Json(std::nullptr_t) : type_(Type::Null) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(std::int64_t v) : type_(Type::Int), int_(v) {}
    Json(int v) : type_(Type::Int), int_(v) {}
    Json(std::uint64_t v) : type_(Type::Int), int_(static_cast<std::int64_t>(v)) {}
    Json(std::uint32_t v) : type_(Type::Int), int_(static_cast<std::int64_t>(v)) {}
    Json(double v) : type_(Type::Double), double_(v) {}
    Json(const char* s) : type_(Type::String), str_(s) {}
    Json(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    // ── mutation ──
    void push_back(Json v);                    // array append
    void set(const std::string& key, Json v);   // object insert/overwrite

    // ── access ──
    Type type() const { return type_; }
    const char* type_name() const;
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }

    std::size_t size() const;                  // array/object element count
    const Json& at(std::size_t i) const;       // array element
    const Json& get(const std::string& key) const;  // object member; throws if absent
    // Object member or nullptr (M12 P0: readers of run reports need a
    // non-throwing lookup).
    const Json* find(const std::string& key) const noexcept;
    const std::string& as_string() const;
    std::int64_t as_int() const;

    // ── serialization ──
    // Canonical pretty form (2-space indent). Throws JsonError on NaN/Inf.
    std::string serialize(int indent = 2) const;
    // Compact single-line form.
    std::string serialize_compact() const;

    // Escape a raw string into a JSON string literal body (no quotes).
    static std::string escape(const std::string& s);

private:
    void serialize_to(std::string& out, int indent, int depth, bool compact) const;

    Type type_;
    bool bool_ = false;
    std::int64_t int_ = 0;
    double double_ = 0.0;
    std::string str_;
    std::shared_ptr<JsonArray> arr_ = std::make_shared<JsonArray>();
    std::shared_ptr<JsonObject> obj_ = std::make_shared<JsonObject>();
};

}  // namespace xbox2pc::json
