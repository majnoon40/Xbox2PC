/* Build-only import-library producer. This DLL is never loaded by the sample. */
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
typedef void *HANDLE;
typedef const unsigned short *LPCWSTR;
typedef int BOOL;

#define EXPORT __declspec(dllexport)
#define WINAPI __stdcall

EXPORT DWORD WINAPI GetCurrentProcessId(void) { return 1; }
EXPORT DWORD WINAPI GetCurrentThreadId(void) { return 1; }
EXPORT void *WINAPI VirtualAlloc(void *address, SIZE_T size,
                                 DWORD allocation_type, DWORD protection) {
    (void)address; (void)size; (void)allocation_type; (void)protection;
    return (void *)0;
}
EXPORT SIZE_T WINAPI VirtualQuery(const void *address, void *information,
                                  SIZE_T information_size) {
    (void)address; (void)information; (void)information_size;
    return 0;
}
EXPORT BOOL WINAPI VirtualProtect(void *address, SIZE_T size, DWORD protection,
                                  DWORD *old_protection) {
    (void)address; (void)size; (void)protection; (void)old_protection;
    return 0;
}
EXPORT BOOL WINAPI VirtualFree(void *address, SIZE_T size, DWORD free_type) {
    (void)address; (void)size; (void)free_type;
    return 0;
}
EXPORT HANDLE WINAPI CreateEventW(void *attributes, BOOL manual_reset,
                                  BOOL initially_set, LPCWSTR name) {
    (void)attributes; (void)manual_reset; (void)initially_set; (void)name;
    return (HANDLE)0;
}
EXPORT BOOL WINAPI SetEvent(HANDLE event) { (void)event; return 0; }
EXPORT DWORD WINAPI WaitForSingleObject(HANDLE handle, DWORD timeout) {
    (void)handle; (void)timeout;
    return 0xFFFFFFFFu;
}
EXPORT BOOL WINAPI CloseHandle(HANDLE handle) { (void)handle; return 0; }
EXPORT void WINAPI SetLastError(DWORD error) { (void)error; }
EXPORT DWORD WINAPI GetLastError(void) { return 0; }
EXPORT void WINAPI ExitProcess(DWORD exit_code) { (void)exit_code; }
