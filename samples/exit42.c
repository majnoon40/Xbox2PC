// M11 Phase 5 sample: exit-code-42 through the native import ring.
// Entry returns 0; ExitProcess(42) travels the ring as CallClass::ExitProcess.
#include <stdint.h>
__attribute__((ms_abi)) uint64_t ExitProcess(uint64_t code);
__attribute__((ms_abi)) uint64_t entry(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)a; (void)b; (void)c; (void)d;
    ExitProcess(42);
    return 0;  // unreachable
}
