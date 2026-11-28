#pragma once
// xbox2pc/json_reader.hpp — a reader for the JSON the runtime writes (M12 P0).
//
// Objects, arrays, strings (with the six short escapes and \uXXXX, surrogate
// pairs included), 64-bit integers, doubles, true, false and null -- the same
// value type json_writer produces. Depth is bounded so hostile input cannot
// overflow the stack; trailing garbage and malformed input are rejected with
// the byte offset. Nothing here is a general-purpose JSON library.

#include <stdexcept>
#include <string>

#include "xbox2pc/json_writer.hpp"

namespace xbox2pc::json {

class JsonParseError : public std::runtime_error {
public:
    explicit JsonParseError(const std::string& what) : std::runtime_error(what) {}
};

constexpr int kMaxParseDepth = 64;

// Throws JsonParseError (message ends with " at byte N").
Json parse(const std::string& text);

}  // namespace xbox2pc::json
