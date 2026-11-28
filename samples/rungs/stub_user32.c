/*
 * stub_user32.c — build-only export producer for the rung fixtures (user32).
 * See stub_kernel32.c. The window procedure signature follows the public
 * Win32 declaration so the fixture's call has the documented shape.
 */
#define EXPORT __declspec(dllexport)
#define WINAPI __stdcall
#define CALLBACK __stdcall
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef int INT;
typedef unsigned short WORD;
typedef unsigned short ATOM;
typedef long LONG;
typedef long long LRESULT;
typedef long long LPARAM;
typedef unsigned long long WPARAM;
typedef void *HINSTANCE;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HMENU;
typedef void *HWND;
typedef void *LPVOID;
typedef const unsigned short *LPCWSTR;

typedef struct tagWNDCLASSEXW {
    UINT cbSize; UINT style; LRESULT (CALLBACK *lpfnWndProc)(HWND, UINT, WPARAM, LPARAM);
    INT cbClsExtra; INT cbWndExtra; HINSTANCE hInstance; HICON hIcon; HCURSOR hCursor;
    HBRUSH hbrBackground; LPCWSTR lpszMenuName; LPCWSTR lpszClassName; HICON hIconSm;
} WNDCLASSEXW;
typedef struct tagPOINT { LONG x; LONG y; } POINT;
typedef struct tagMSG { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt; } MSG;

EXPORT ATOM WINAPI RegisterClassExW(const WNDCLASSEXW *wc) { (void)wc; return (ATOM)0; }
EXPORT HWND WINAPI CreateWindowExW(DWORD ex_style, LPCWSTR class_name, LPCWSTR window_name, DWORD style,
                                   INT x, INT y, INT width, INT height, HWND parent, HMENU menu,
                                   HINSTANCE instance, LPVOID parameter) {
    (void)ex_style; (void)class_name; (void)window_name; (void)style; (void)x; (void)y; (void)width;
    (void)height; (void)parent; (void)menu; (void)instance; (void)parameter; return (HWND)0;
}
EXPORT BOOL WINAPI ShowWindow(HWND window, INT command) { (void)window; (void)command; return 0; }
EXPORT BOOL WINAPI PeekMessageW(MSG *message, HWND window, UINT first, UINT last, UINT remove) {
    (void)window; (void)first; (void)last; (void)remove;
    message->hwnd = (HWND)0; message->message = 0; message->wParam = 0; message->lParam = 0;
    message->time = 0; message->pt.x = 0; message->pt.y = 0;
    return 0;
}
EXPORT BOOL WINAPI TranslateMessage(const MSG *message) { (void)message; return 0; }
EXPORT LRESULT WINAPI DispatchMessageW(const MSG *message) { (void)message; return 0; }
EXPORT BOOL WINAPI DestroyWindow(HWND window) { (void)window; return 0; }
