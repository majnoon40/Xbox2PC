/*
 * Freestanding x64 Windows PE fixture: no CRT, no headers, custom entry.
 * The only imported DLL is kernel32.dll. The linker-generated import library
 * is produced from our own build-only stub source, never from Microsoft files.
 */
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
typedef void *HANDLE;
typedef const unsigned short *LPCWSTR;
typedef int BOOL;

typedef struct MEMORY_BASIC_INFORMATION {
    void *BaseAddress;
    void *AllocationBase;
    DWORD AllocationProtect;
    DWORD _padding0;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
    DWORD _padding1;
} MEMORY_BASIC_INFORMATION;

#define WINAPI __stdcall
#define DLLIMPORT __declspec(dllimport)
#define MEM_COMMIT 0x1000u
#define MEM_RESERVE 0x2000u
#define MEM_RELEASE 0x8000u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define WAIT_OBJECT_0 0u

DLLIMPORT DWORD WINAPI GetCurrentProcessId(void);
DLLIMPORT DWORD WINAPI GetCurrentThreadId(void);
DLLIMPORT void *WINAPI VirtualAlloc(void *address, SIZE_T size,
                                   DWORD allocation_type, DWORD protection);
DLLIMPORT SIZE_T WINAPI VirtualQuery(const void *address,
                                     MEMORY_BASIC_INFORMATION *information,
                                     SIZE_T information_size);
DLLIMPORT BOOL WINAPI VirtualProtect(void *address, SIZE_T size,
                                     DWORD protection, DWORD *old_protection);
DLLIMPORT BOOL WINAPI VirtualFree(void *address, SIZE_T size, DWORD free_type);
DLLIMPORT HANDLE WINAPI CreateEventW(void *attributes, BOOL manual_reset,
                                     BOOL initially_set, LPCWSTR name);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE event);
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE handle, DWORD timeout);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE handle);
DLLIMPORT void WINAPI SetLastError(DWORD error);
DLLIMPORT DWORD WINAPI GetLastError(void);
DLLIMPORT void WINAPI ExitProcess(DWORD exit_code);

/* The Windows loader writes this TLS index before entry. */
DWORD _tls_index = 0;
__declspec(thread) volatile DWORD tls_word = 0x13579BDFu;

__declspec(noinline) static DWORD entry_body(void) {
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();
    if (pid == 0 || tid == 0) return 51;

    void *allocation = VirtualAlloc((void *)0, 4096,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == (void *)0) return 52;

    MEMORY_BASIC_INFORMATION information;
    if (VirtualQuery(allocation, &information, sizeof(information)) !=
        sizeof(information)) return 53;

    DWORD old_protection = 0;
    if (!VirtualProtect(allocation, 4096, PAGE_READONLY, &old_protection))
        return 54;
    if (!VirtualFree(allocation, 0, MEM_RELEASE)) return 55;

    HANDLE event = CreateEventW((void *)0, 1, 0, (LPCWSTR)0);
    if (event == (HANDLE)0) return 56;
    if (!SetEvent(event)) return 57;
    if (WaitForSingleObject(event, 0) != WAIT_OBJECT_0) return 58;
    if (!CloseHandle(event)) return 59;

    SetLastError(0x1234u);
    if (GetLastError() != 0x1234u) return 60;
    if (tls_word != 0x13579BDFu) return 61;
    return 42;
}

void WINAPI entry(void) {
    const DWORD exit_code = entry_body();
    ExitProcess(exit_code);
    for (;;) { }
}
