/*
 * Rung F — cxxthrow: a C++ exception thrown in an inner frame and caught in
 * a middle frame, across nested non-inlined frames, built by the freestanding
 * toolchain (clang, x86_64-pc-windows-msvc, no CRT).  Exit-code contract:
 * exit code == 42.
 *
 * Until P1 section 4.5 lands the vcruntime path, cxxthrow_runtime.c provides
 * the two runtime symbols the MSVC-ABI EH references as stubs: the throw
 * helper ends the process with 99 and the frame handler declines every
 * exception.  The rung is therefore "blocked" (exit 99), never "passing".
 */
typedef unsigned long DWORD;
#define WINAPI __stdcall
#define DLLIMPORT __declspec(dllimport)
#define NOINLINE __attribute__((noinline))
extern "C" DLLIMPORT void WINAPI ExitProcess(DWORD exit_code);
#define RUNG_EXIT(code) do { ExitProcess(static_cast<DWORD>(code)); for (;;) { } } while (0)

NOINLINE static int throw_from_inner_frame() { throw 42; }

NOINLINE static int catch_in_middle_frame() {
    try {
        return throw_from_inner_frame();
    } catch (int value) {
        return value;
    }
}

NOINLINE static int outer_frame() { return catch_in_middle_frame(); }

extern "C" void WINAPI entry(void) {
    const int result = outer_frame();
    RUNG_EXIT(result == 42 ? 42 : 140);
}
