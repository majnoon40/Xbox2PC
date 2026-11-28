/*
 * Rung C — assetload: open an asset, stream it, hash it.  Exit-code
 * contract: exit code == (FNV-1a of the asset bytes) & 0xFF.  The asset is
 * produced by scripts/build-rung-fixtures.sh as assets/rung_c.bin (4096
 * bytes, byte i == (i * 7 + 3) & 0xFF); that script prints the expected
 * value, and the rung is "passing" only when the runtime's VFS serves the
 * file and the hash matches (P2 wave 3).
 */
#include "rung_common.h"
#include "rung_kernel32.h"

#define RUNG_C_ASSET_BYTES 4096

void WINAPI entry(void) {
    HANDLE heap;
    HANDLE file;
    LPVOID buffer;
    INT64 size = 0;
    DWORD read = 0;
    UINT64 hash;
    heap = GetProcessHeap();
    if (heap == NULL) RUNG_EXIT(111);
    buffer = HeapAlloc(heap, 0, RUNG_C_ASSET_BYTES);
    if (buffer == NULL) RUNG_EXIT(112);
    file = CreateFileW(L"assets\\rung_c.bin", GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) RUNG_EXIT(113);
    if (!GetFileSizeEx(file, &size)) RUNG_EXIT(114);
    if (size != RUNG_C_ASSET_BYTES) RUNG_EXIT(115);
    if (!ReadFile(file, buffer, RUNG_C_ASSET_BYTES, &read, NULL)) RUNG_EXIT(116);
    if (read != RUNG_C_ASSET_BYTES) RUNG_EXIT(117);
    CloseHandle(file);
    hash = rung_fnv1a((const BYTE *)buffer, (SIZE_T)read);
    HeapFree(heap, 0, buffer);
    RUNG_EXIT(hash & 0xFFu);
}
