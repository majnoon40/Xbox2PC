/* rung_user32.h — the user32 imports and types the window rung uses. */
#ifndef XBOX2PC_RUNG_USER32_H
#define XBOX2PC_RUNG_USER32_H
#include "rung_common.h"

typedef struct rung_point { LONG x; LONG y; } POINT;
typedef struct rung_msg {
    HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt;
} MSG;
typedef LRESULT (CALLBACK *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef struct rung_wndclassexw {
    UINT cbSize; UINT style; WNDPROC lpfnWndProc; INT cbClsExtra; INT cbWndExtra;
    HINSTANCE hInstance; LPVOID hIcon; LPVOID hCursor; LPVOID hbrBackground;
    LPCWSTR lpszMenuName; LPCWSTR lpszClassName; LPVOID hIconSm;
} WNDCLASSEXW;

#define WM_CLOSE 0x0010
#define WM_QUIT 0x0012
#define PM_REMOVE 1u
#define SW_SHOW 5
#define WS_OVERLAPPEDWINDOW 0x00CF0000u

DLLIMPORT ATOM WINAPI RegisterClassExW(const WNDCLASSEXW *wc);
DLLIMPORT HWND WINAPI CreateWindowExW(DWORD ex_style, LPCWSTR class_name, LPCWSTR window_name, DWORD style,
                                       INT x, INT y, INT width, INT height, HWND parent, HMENU menu,
                                       HINSTANCE instance, LPVOID parameter);
DLLIMPORT BOOL WINAPI ShowWindow(HWND window, INT command);
DLLIMPORT BOOL WINAPI PeekMessageW(MSG *message, HWND window, UINT first, UINT last, UINT remove);
DLLIMPORT BOOL WINAPI TranslateMessage(const MSG *message);
DLLIMPORT LRESULT WINAPI DispatchMessageW(const MSG *message);
DLLIMPORT BOOL WINAPI DestroyWindow(HWND window);

#endif /* XBOX2PC_RUNG_USER32_H */
