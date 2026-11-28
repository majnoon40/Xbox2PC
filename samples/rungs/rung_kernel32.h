/* rung_kernel32.h — the kernel32 imports the rung fixtures use. */
#ifndef XBOX2PC_RUNG_KERNEL32_H
#define XBOX2PC_RUNG_KERNEL32_H
#include "rung_common.h"

DLLIMPORT HMODULE WINAPI GetModuleHandleW(LPCWSTR name);
DLLIMPORT HANDLE WINAPI GetProcessHeap(void);
DLLIMPORT LPVOID WINAPI HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
DLLIMPORT BOOL WINAPI HeapFree(HANDLE heap, DWORD flags, LPVOID memory);
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define OPEN_EXISTING 3u
DLLIMPORT HANDLE WINAPI CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPVOID security,
                                    DWORD disposition, DWORD flags, HANDLE template_file);
DLLIMPORT BOOL WINAPI ReadFile(HANDLE file, LPVOID buffer, DWORD bytes, LPDWORD read, LPVOID overlapped);
DLLIMPORT BOOL WINAPI GetFileSizeEx(HANDLE file, LPVOID size);   /* LARGE_INTEGER* */
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE handle);
typedef DWORD WINAPI (*LPTHREAD_START_ROUTINE)(LPVOID parameter);
DLLIMPORT HANDLE WINAPI CreateThread(LPVOID security, SIZE_T stack_size, LPTHREAD_START_ROUTINE start,
                                     LPVOID parameter, DWORD flags, LPDWORD thread_id);
DLLIMPORT HANDLE WINAPI CreateEventW(LPVOID security, BOOL manual_reset, BOOL initial_state, LPCWSTR name);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE event);
#define WAIT_OBJECT_0 0u
#define INFINITE 0xFFFFFFFFu
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE handle, DWORD milliseconds);
DLLIMPORT DWORD WINAPI WaitForMultipleObjects(DWORD count, HANDLE *handles, BOOL wait_all, DWORD milliseconds);
DLLIMPORT void WINAPI Sleep(DWORD milliseconds);
DLLIMPORT DWORD WINAPI GetLastError(void);
DLLIMPORT void WINAPI SetLastError(DWORD error);

#endif /* XBOX2PC_RUNG_KERNEL32_H */
