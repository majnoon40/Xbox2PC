/*
 * Rung B — bootloop: a window, a message pump and a present loop for FRAMES
 * frames.  Exit-code contract: exit code == FRAMES (60).
 *
 * Today the runtime has no windowing (P2 wave 4) and no swap chain (P3), so
 * under --unimplemented=trap the run stops at the first import it does not
 * implement; samples/rungs/golden records which one.
 */
#include "rung_common.h"
#include "rung_kernel32.h"
#include "rung_user32.h"

#define FRAMES 60

static LRESULT CALLBACK rung_wndproc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    (void)wparam;
    (void)lparam;
    if (message == WM_CLOSE) DestroyWindow(window);
    return 0;
}

void WINAPI entry(void) {
    WNDCLASSEXW wc;
    MSG msg;
    HWND window;
    DWORD frames;
    HINSTANCE instance = GetModuleHandleW(NULL);
    if (instance == NULL) RUNG_EXIT(101);
    rung_zero(&wc, (SIZE_T)sizeof wc);
    wc.cbSize = (UINT)sizeof wc;
    wc.lpfnWndProc = rung_wndproc;
    wc.hInstance = instance;
    wc.lpszClassName = L"RungBootloop";
    if (RegisterClassExW(&wc) == 0) RUNG_EXIT(102);
    window = CreateWindowExW(0, L"RungBootloop", L"M12 rung B", WS_OVERLAPPEDWINDOW,
                             0, 0, 320, 240, NULL, NULL, instance, NULL);
    if (window == NULL) RUNG_EXIT(103);
    ShowWindow(window, SW_SHOW);
    frames = 0;
    while (frames < FRAMES) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) RUNG_EXIT(104);
        }
        /* Presenting the frame is the swap chain's job (rung D, P3); the
         * loop counts the frame here. */
        frames = frames + 1;
    }
    DestroyWindow(window);
    RUNG_EXIT(frames);
}
