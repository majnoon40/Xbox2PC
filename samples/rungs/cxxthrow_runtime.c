/*
 * cxxthrow_runtime.c — freestanding stand-ins for the two vcruntime symbols
 * that clang's MSVC-ABI exception handling references from rung F.
 *
 * These are NOT an exception runtime: the throw helper ends the process with
 * code 99 and the frame handler declines every exception (ContinueSearch).
 * P1 section 4.5 replaces them with the real vcruntime path; until then the
 * rung's status is "blocked", and scripts/rung_check.py reports it so.
 */
#define WINAPI __stdcall
#define DLLIMPORT __declspec(dllimport)
typedef unsigned long DWORD;

DLLIMPORT void WINAPI ExitProcess(DWORD exit_code);

/* clang's catch-by-type path emits a type descriptor whose vfptr is the
 * type_info vtable, even with -fno-rtti. Define an empty one under the
 * mangled name the MSVC ABI uses; nothing calls into it before the real
 * frame handler exists. */
__asm__(".section .rdata,\"dr\"\n"
        ".globl \"??_7type_info@@6B@\"\n"
        "\"??_7type_info@@6B@\":\n"
        ".quad 0\n"
        ".quad 0\n"
        ".text\n");

int __CxxFrameHandler3(void *exception_record, void *establisher_frame,
                       void *context_record, void *dispatcher_context) {
    (void)exception_record;
    (void)establisher_frame;
    (void)context_record;
    (void)dispatcher_context;
    return 1;   /* ExceptionContinueSearch */
}

void _CxxThrowException(void *object, void *exception_info) {
    (void)object;
    (void)exception_info;
    ExitProcess(99);
    for (;;) { }
}
