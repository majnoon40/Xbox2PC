/*
 * Rung D — gpucompute: create a D3D12 device, dispatch a compute shader that
 * writes a checkerboard into a 64x64 UAV buffer, read it back and hash it.
 * Exit-code contract: exit code == (FNV-1a of the readback) & 0xFF.
 *
 * Only device creation is expressed today: the queue, list, heap and shader
 * steps need the graphics provider (P3) and the shader translator (P4).
 * Under --unimplemented=trap the run stops at d3d12!D3D12CreateDevice.
 */
#include "rung_common.h"
#include "rung_d3d12.h"

void WINAPI entry(void) {
    LPVOID device = NULL;
    const HRESULT hr = D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, IID_ID3D12Device_BYTES, &device);
    if (hr < 0) RUNG_EXIT(121);
    /* The dispatch and readback follow here once a provider exists. */
    RUNG_EXIT(122);
}
