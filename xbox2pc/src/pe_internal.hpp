#pragma once
// pe_internal.hpp — declarations shared between pe_parser.cpp and
// pe_tables.cpp (internal, not part of the public include tree).

#include <cstdint>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::pe {

// Import/export table parsing (pe_tables.cpp). Callers pass the whole-file
// buffer; implementations do their own bounds checking.
void parse_imports(PeImage& img, const std::uint8_t* data, std::uint64_t size,
                  diag::Diagnostics& diags);
void parse_exports(PeImage& img, const std::uint8_t* data, std::uint64_t size,
                  diag::Diagnostics& diags);

}  // namespace xbox2pc::pe
