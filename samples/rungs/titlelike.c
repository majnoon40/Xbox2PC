/*
 * Rung G — titlelike: D + E + C in one program.  A device for a compute
 * pass, worker threads that rendezvous, and a streamed asset, in the order a
 * larger program would touch them.  Exit-code contract: exit code ==
 * (thread checksum 36) + (asset hash & 0x3F) once every part is real.
 *
 * Every part is synthetic and project-authored; nothing here is derived from
 * any product.  Under --unimplemented=trap the run stops at the first import
 * the runtime lacks; samples/rungs/golden records which one.
 */
#include "rung_common.h"
#include "rung_kernel32.h"
#include "rung_d3d12.h"

#define RUNG_G_THREADS 2
#define RUNG_G_ASSET_BYTES 256

static HANDLE rung_gate;
static HANDLE rung_threads[RUNG_G_THREADS];
static LONG rung_results[RUNG_G_THREADS];

static DWORD WINAPI rung_worker(LPVOID parameter) {
    const DWORD index = (DWORD)(SIZE_T)parameter;
    WaitForSingleObject(rung_gate, INFINITE);
    rung_results[index] = (LONG)(index + 1);
    return index + 1;
}

void WINAPI entry(void) {
    LPVOID device = NULL;
    HANDLE heap;
    HANDLE file;
    LPVOID buffer;
    DWORD i;
    LONG sum = 0;
    INT64 size = 0;
    DWORD read = 0;

    /* D: the device for the compute pass. */
    if (D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, IID_ID3D12Device_BYTES, &device) < 0)
        RUNG_EXIT(151);

    /* E: threads that rendezvous. */
    rung_zero(rung_results, (SIZE_T)sizeof rung_results);
    rung_gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (rung_gate == NULL) RUNG_EXIT(152);
    for (i = 0; i < RUNG_G_THREADS; ++i) {
        rung_threads[i] = CreateThread(NULL, 0, rung_worker, (LPVOID)(SIZE_T)i, 0, NULL);
        if (rung_threads[i] == NULL) RUNG_EXIT(153);
    }
    if (!SetEvent(rung_gate)) RUNG_EXIT(154);
    for (i = 0; i < RUNG_G_THREADS; ++i) {
        if (WaitForSingleObject(rung_threads[i], INFINITE) != WAIT_OBJECT_0) RUNG_EXIT(155);
        CloseHandle(rung_threads[i]);
        sum = sum + rung_results[i];
    }
    CloseHandle(rung_gate);

    /* C: a streamed asset. */
    heap = GetProcessHeap();
    if (heap == NULL) RUNG_EXIT(156);
    buffer = HeapAlloc(heap, 0, RUNG_G_ASSET_BYTES);
    if (buffer == NULL) RUNG_EXIT(157);
    file = CreateFileW(L"assets\\rung_g.bin", GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) RUNG_EXIT(158);
    if (!GetFileSizeEx(file, &size)) RUNG_EXIT(159);
    if (size != RUNG_G_ASSET_BYTES) RUNG_EXIT(160);
    if (!ReadFile(file, buffer, RUNG_G_ASSET_BYTES, &read, NULL)) RUNG_EXIT(161);
    CloseHandle(file);
    {
        const UINT64 hash = rung_fnv1a((const BYTE *)buffer, (SIZE_T)read);
        HeapFree(heap, 0, buffer);
        RUNG_EXIT((DWORD)sum + (DWORD)(hash & 0x3Fu));
    }
}
