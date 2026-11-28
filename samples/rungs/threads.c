/*
 * Rung E — threads: RUNG_E_THREADS guest threads block on one event, are
 * released together (rendezvous), record their index and exit.  Exit-code
 * contract: exit code == 1 + 2 + ... + RUNG_E_THREADS (36 for 8), the
 * schedule checksum: independent of the order the threads run in.
 *
 * Guest threads do not exist in the runtime until P1; under
 * --unimplemented=trap the run stops at the first import it lacks.
 */
#include "rung_common.h"
#include "rung_kernel32.h"

#define RUNG_E_THREADS 8

static HANDLE rung_gate;
static HANDLE rung_threads[RUNG_E_THREADS];
static LONG rung_results[RUNG_E_THREADS];

static DWORD WINAPI rung_worker(LPVOID parameter) {
    const DWORD index = (DWORD)(SIZE_T)parameter;
    WaitForSingleObject(rung_gate, INFINITE);   /* rendezvous */
    rung_results[index] = (LONG)(index + 1);
    Sleep(0);
    return index + 1;
}

void WINAPI entry(void) {
    DWORD i;
    LONG sum = 0;
    rung_zero(rung_results, (SIZE_T)sizeof rung_results);
    rung_gate = CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual reset, cleared */
    if (rung_gate == NULL) RUNG_EXIT(131);
    for (i = 0; i < RUNG_E_THREADS; ++i) {
        rung_threads[i] = CreateThread(NULL, 0, rung_worker, (LPVOID)(SIZE_T)i, 0, NULL);
        if (rung_threads[i] == NULL) RUNG_EXIT(132);
    }
    if (!SetEvent(rung_gate)) RUNG_EXIT(133);           /* release them together */
    for (i = 0; i < RUNG_E_THREADS; ++i) {
        if (WaitForSingleObject(rung_threads[i], INFINITE) != WAIT_OBJECT_0) RUNG_EXIT(134);
        CloseHandle(rung_threads[i]);
        sum = sum + rung_results[i];
    }
    CloseHandle(rung_gate);
    RUNG_EXIT((DWORD)sum);
}
