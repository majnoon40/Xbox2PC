/*
 * stub_d3d12.c — build-only export producer for the rung fixtures (d3d12).
 * See stub_kernel32.c. COM interfaces stay opaque: the fixture never
 * dereferences the device the runtime would create.
 */
#define EXPORT __declspec(dllexport)
#define WINAPI __stdcall
typedef unsigned long DWORD;
typedef long HRESULT;
typedef void *LPVOID;
typedef const void *LPCVOID;

EXPORT HRESULT WINAPI D3D12CreateDevice(LPCVOID adapter, DWORD minimum_feature_level,
                                        LPCVOID iid, LPVOID *device_out) {
    (void)adapter; (void)minimum_feature_level; (void)iid; (void)device_out;
    return (HRESULT)0x80004005L;   /* E_FAIL */
}
