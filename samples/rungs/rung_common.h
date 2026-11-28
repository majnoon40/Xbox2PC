/*
 * rung_common.h — freestanding declarations shared by the M12 rung fixtures.
 *
 * No CRT, no Windows SDK or GDK header: every type, constant and prototype
 * here is written for these fixtures (docs/input-policy.md). The import
 * libraries come from our own stub DLL sources (stub_*.c) built by
 * scripts/build-rung-fixtures.sh; the runtime decides what each import does.
 */
#ifndef XBOX2PC_RUNG_COMMON_H
#define XBOX2PC_RUNG_COMMON_H

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef int BOOL;
typedef int INT;
typedef unsigned int UINT;
typedef long LONG;
typedef unsigned long long UINT64;
typedef long long INT64;
typedef unsigned long long SIZE_T;
typedef long long LRESULT;
typedef long long LPARAM;
typedef unsigned long long WPARAM;
typedef long HRESULT;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *HMENU;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef unsigned short WCHAR;
typedef const WCHAR *LPCWSTR;
typedef WCHAR *LPWSTR;
typedef WORD ATOM;
typedef DWORD *LPDWORD;

#define WINAPI __stdcall
#define CALLBACK __stdcall
#define DLLIMPORT __declspec(dllimport)

#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)
typedef long long INT_PTR;
#define INVALID_HANDLE_VALUE ((HANDLE)(INT_PTR)-1)

static inline void rung_zero(void *p, SIZE_T n) {
    BYTE *b = (BYTE *)p;
    while (n--) *b++ = 0;
}

/* FNV-1a, 64-bit, over bytes: the rung C and D hash. */
static inline UINT64 rung_fnv1a(const BYTE *data, SIZE_T n) {
    UINT64 h = 0xcbf29ce484222325ull;
    SIZE_T i;
    for (i = 0; i < n; ++i) {
        h ^= (UINT64)data[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

/* Every rung ends here: the documented exit code, or the trap of the first
 * import the runtime does not implement (--unimplemented=trap). */
DLLIMPORT void WINAPI ExitProcess(DWORD exit_code);
#define RUNG_EXIT(code) do { ExitProcess((DWORD)(code)); for (;;) { } } while (0)

#endif /* XBOX2PC_RUNG_COMMON_H */
