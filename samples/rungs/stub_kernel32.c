/*
 * stub_kernel32.c — build-only export producer for the rung fixtures.
 * Compiled and linked as a DLL by scripts/build-rung-fixtures.sh only to
 * emit kernel32.lib; it is never loaded by a fixture and is not a Microsoft
 * file. Every export has the documented arity and an empty body.
 */
#define EXPORT __declspec(dllexport)
#define WINAPI __stdcall
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
typedef int BOOL;
typedef unsigned int *LPDWORD;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef const unsigned short *LPCWSTR;

EXPORT HMODULE WINAPI GetModuleHandleW(LPCWSTR name) { (void)name; return (HMODULE)0; }
EXPORT HANDLE WINAPI GetProcessHeap(void) { return (HANDLE)0; }
EXPORT LPVOID WINAPI HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes) { (void)heap; (void)flags; (void)bytes; return (LPVOID)0; }
EXPORT BOOL WINAPI HeapFree(HANDLE heap, DWORD flags, LPVOID memory) { (void)heap; (void)flags; (void)memory; return 0; }
EXPORT HANDLE WINAPI CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPVOID security,
                                 DWORD disposition, DWORD flags, HANDLE template_file) {
    (void)name; (void)access; (void)share; (void)security; (void)disposition; (void)flags; (void)template_file;
    return (HANDLE)0;
}
EXPORT BOOL WINAPI ReadFile(HANDLE file, LPVOID buffer, DWORD bytes, LPDWORD read, LPVOID overlapped) {
    (void)file; (void)buffer; (void)bytes; (void)read; (void)overlapped; return 0;
}
EXPORT BOOL WINAPI GetFileSizeEx(HANDLE file, LPVOID size) { (void)file; (void)size; return 0; }
EXPORT BOOL WINAPI CloseHandle(HANDLE handle) { (void)handle; return 0; }
EXPORT HANDLE WINAPI CreateThread(LPVOID security, SIZE_T stack, LPVOID start, LPVOID parameter,
                                  DWORD flags, LPDWORD thread_id) {
    (void)security; (void)stack; (void)start; (void)parameter; (void)flags; (void)thread_id;
    return (HANDLE)0;
}
EXPORT HANDLE WINAPI CreateEventW(LPVOID security, BOOL manual_reset, BOOL initial, LPCWSTR name) {
    (void)security; (void)manual_reset; (void)initial; (void)name; return (HANDLE)0;
}
EXPORT BOOL WINAPI SetEvent(HANDLE event) { (void)event; return 0; }
EXPORT DWORD WINAPI WaitForSingleObject(HANDLE handle, DWORD milliseconds) { (void)handle; (void)milliseconds; return 0xFFFFFFFFu; }
EXPORT BOOL WINAPI WaitForMultipleObjects(DWORD count, HANDLE *handles, BOOL wait_all, DWORD milliseconds) {
    (void)count; (void)handles; (void)wait_all; (void)milliseconds; return 0;
}
EXPORT void WINAPI Sleep(DWORD milliseconds) { (void)milliseconds; }
EXPORT DWORD WINAPI GetLastError(void) { return 0; }
EXPORT void WINAPI SetLastError(DWORD error) { (void)error; }
EXPORT void WINAPI ExitProcess(DWORD exit_code) { (void)exit_code; }
