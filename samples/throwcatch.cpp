// M11 Phase 5 sample: C++ throw/catch under native execution.
// MSVC-style SEH is not available; the child uses host Itanium EH, which
// the forked child inherits. The throw/catch round trip proves the child
// runs real compiler-generated code (unwind tables + personality).
struct Payload { unsigned magic; };
int main() { return 0; }
extern "C" __attribute__((ms_abi)) unsigned long entry(unsigned long a, unsigned long b,
                                                      unsigned long c, unsigned long d) {
    (void)a; (void)b; (void)c; (void)d;
    try {
        Payload p{0x1337};
        throw p;
    } catch (const Payload& caught) {
        return caught.magic == 0x1337 ? 7 : 9;
    }
}
