/* rung_d3d12.h — the one d3d12 import the compute rung starts with. */
#ifndef XBOX2PC_RUNG_D3D12_H
#define XBOX2PC_RUNG_D3D12_H
#include "rung_common.h"

typedef struct rung_guid {
    unsigned int data1; unsigned short data2; unsigned short data3;
    unsigned char data4[8];
} GUID;

/* Public ID3D12Device interface identifier. */
static const GUID IID_ID3D12Device = {
    0x189819f1u, 0x1db6u, 0x4b57u, {0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7} };

#define D3D_FEATURE_LEVEL_11_0 0xb000u
#define IID_ID3D12Device_BYTES ((const GUID *)&IID_ID3D12Device)

DLLIMPORT HRESULT WINAPI D3D12CreateDevice(LPCVOID adapter, DWORD minimum_feature_level,
                                           const GUID *iid, LPVOID *device_out);

#endif /* XBOX2PC_RUNG_D3D12_H */
