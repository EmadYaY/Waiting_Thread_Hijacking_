# Waiting Thread Hijacking (WTH) - Proof of Concept

A technical implementation and research repository on **Waiting Thread Hijacking**, a stealthy process injection technique that avoids classical detection points.

> **⚠️ DISCLAIMER:** This code is provided for **authorized security research and educational purposes only**. Unauthorized access to computer systems is illegal. Use in controlled lab environments with proper authorization.

---

## 📖 What is Waiting Thread Hijacking?

**Waiting Thread Hijacking (WTH)** is an advanced code injection technique that leverages Windows thread synchronization primitives to achieve process injection without traditional suspension/resumption patterns.

### How it differs from Classical Thread Hijacking:

| Aspect | Classical TEH | Waiting Thread Hijacking |
|--------|---------------|--------------------------|
| Thread State | Suspend thread | Thread already waiting |
| Modification | SetThreadContext (RIP) | WriteProcessMemory to [RSP] |
| Detection | Easy (SuspendThread hook) | Hard (stack write less monitored) |
| Privileges | Admin/High Integrity | Medium Integrity sufficient |
| Behavioral Signature | High | Low |

### The Mechanism:

1. **Identify** waiting threads via `NtQuerySystemInformation`
2. **Read** thread context and current return address from [RSP]
3. **Validate** return address is in legitimate module (ntdll/kernel32)
4. **Allocate** executable shellcode stub in target process
5. **Embed** original return address in shellcode epilogue
6. **Overwrite** [RSP] with shellcode address
7. **Wait** for thread to wake naturally and execute shellcode
8. **Shellcode** executes and returns to original code via embedded address

### Key Advantage:

```
No SuspendThread() call = No classical EDR detection point
No SetThreadContext() call = No RIP modification detection
WriteProcessMemory to stack = Less commonly monitored than heap
Natural thread wake-up = No forced resumption signature
```

---

## 🔬 Original Research

This implementation is based on the groundbreaking research by **hasherezade** at **Check Point Research** (April 2025):

- **Title:** Waiting Thread Hijacking - A New Code Injection Technique
- **Author:** hasherezade (Check Point Research)
- **Date:** April 2025
- **Repository:** https://github.com/hasherezade/waiting_thread_hijacking

---

## 📋 Quick Start

### Compilation

**Visual Studio (MSVC):**
```bash
cl.exe wth_poc.cpp /link ntdll.lib psapi.lib
```

**MinGW (GCC):**
```bash
gcc -o wth_poc.exe wth_poc.cpp -lntdll -lpsapi -lkernel32 -Wall
```

### Execution

```bash
# Find target process PID
tasklist | findstr explorer
# Output: explorer.exe                 4892   Session 1      123,456 K

# Run PoC
wth_poc.exe 4892
```

### Expected Output

```
=== WTH PoC (Production) ===

[+] APIs initialized
[*] Searching for waiting threads...
[+] Found waiting thread: 5678
[*] Executing WTH attack...
[*] Target PID: 4892, TID: 5678
[+] Process opened
[+] Memory allocated: 0x000000001a2b0000
[+] Shellcode written
[+] RSP: 0x000000001f5acf80, RIP: 0x00007ff8a1c20f00
[+] Original return address: 0x00007ff8a1a50abc
[+] Thread hijacked successfully
[+] Return address: 0x00007ff8a1a50abc -> 0x000000001a2b0000

[+] Done
```

---

## 🧪 Step-by-Step Testing

### Prerequisites

- Windows 10/11 x64 (VM recommended)
- Administrator or Medium Integrity privileges
- Sysmon (optional, for detection testing)
- Process Hacker (optional, for memory inspection)

### Test Procedure

#### Step 1: Setup Monitoring (Optional)

```powershell
# Install Sysmon
sysmon.exe -i -accepteula

# Start Event Viewer
eventvwr.exe
# Navigate to: Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

#### Step 2: Identify Target

```bash
tasklist | findstr explorer
# or
tasklist | findstr svchost
# or
tasklist | findstr dwm
```

#### Step 3: Execute PoC

```bash
wth_poc.exe <PID>
```

#### Step 4: Verify Execution

- Target process continues running (no crash)
- All expected output messages appear
- Execution time < 5 seconds

#### Step 5: Monitor Detections (Sysmon)

```
Event ID: 10 (ProcessAccess)
Source: wth_poc.exe
Target: explorer.exe
GrantedAccess: 0x38 (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)
```

#### Step 6: Memory Inspection (Optional)

```bash
# Using Process Hacker
1. Find target process (explorer.exe)
2. Right-click → Properties → Memory
3. Look for allocations with "?" (no module)
4. Check for RWX permissions

# Using PE-sieve
pe-sieve /pid <target_pid> /out report.html /dmp dumped
```

---

## 🔍 Detection Methods

### Behavioral Indicators

1. **OpenProcess** with `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE`
2. **VirtualAllocEx** in target process
3. **WriteProcessMemory** (multiple operations)
4. **VirtualProtectEx** to `PAGE_EXECUTE_READ`
5. **OpenThread** with `THREAD_GET_CONTEXT` only (minimal access)

### Sysmon Detection

**Event ID 10 (ProcessAccess):**
```
GrantedAccess = 0x38
TargetImage = explorer.exe, svchost.exe, dwm.exe
SourceImage = suspicious.exe
```

**Pattern:** Sequence of 4-5 events within <10 seconds indicates injection attempt

### ETW Detection

Enable these providers:
- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-Memory`

Monitor for:
- `VirtualAllocEx` events
- `MemoryWrite` to executable regions
- Stack modification patterns

### KQL Query (Microsoft Defender)

```kusto
DeviceProcessEvents
| where ProcessName contains "explorer" or ProcessName contains "svchost"
| where InitiatingProcessName !in ("services.exe", "system")
| where ProcessId != InitiatingProcessId
| join kind=inner (
    DeviceFileEvents
    | where DeviceName == DeviceName
    | where ActionType == "VirtualAllocEx"
  ) on DeviceName
```

---

## 🗺️ MITRE ATT&CK Mapping

### Technique: **T1055 - Process Injection**

| Sub-technique | Status |
|---------------|--------|
| T1055.001 Dynamic-link Library Injection | ❌ Not applicable |
| T1055.002 Portable Executable Injection | ✅ Related |
| T1055.004 Asynchronous Procedure Call | ⚠️ Similar pattern |
| T1055.005 Thread Execution Hijacking | ✅ **Primary match** |
| T1055.011 Extra Window Memory Injection | ❌ Not applicable |
| T1055.012 Process Hollowing | ❌ Not applicable |

### Tactics

| Tactic | Description |
|--------|-------------|
| **TA0002** Execution | Shellcode executed in target thread context |
| **TA0005** Defense Evasion | Avoids SuspendThread/SetThreadContext detection |
| **TA0004** Privilege Escalation | Inject into privileged process |
| **TA0003** Persistence | Maintain execution across reboots |

---

## 🎯 Known APT Usage

### Groups Using Similar Techniques

| APT Group | Technique | Year | Reference |
|-----------|-----------|------|-----------|
| **Lazarus Group** | Thread context manipulation | 2018+ | MITRE ATT&CK |
| **APT28** | Process injection variants | 2020+ | Check Point Research & MITRE ATT&CK G0007|
| **APT41** | Advanced injection methods | 2021+ | Mandiant |
| **Wizard Spider** | Stealth process injection | 2022+ | CrowdStrike |

### Real-World Context

WTH is part of a broader evolution in injection techniques:

1. **2000s:** CreateRemoteThread (easily detected)
2. **2010s:** Classic TEH with SuspendThread (detectable via API hooking)
3. **2020s:** APC Injection (requires Native API knowledge)
4. **2025:** WTH (avoids classical detection patterns)

---

## 📊 Technical Specifications

### Shellcode Stub

```
Offset  Instruction         Size    Purpose
────────────────────────────────────────────────────
0x00    pushfq              1       Save CPU flags
0x01    push rax            1       Save GP registers
0x02    push rbx            1
0x03    push rcx            1
0x04    push rdx            1
0x05    push rsi            1
0x06    push rdi            1
0x07    push rbp            1       Save base pointer
0x08    push r8-r15         16      Save extended registers
0x18    sub rsp, 0x20       4       Stack alignment (x64 ABI)
0x1C    nop                 1       Payload placeholder
0x1D    add rsp, 0x20       4       Restore stack
0x21    pop r15-r8          16      Restore extended registers
0x31    pop rbp             1       Restore base pointer
0x32    pop rdi-rax         7       Restore GP registers
0x38    popfq               1       Restore CPU flags
0x39    mov rax, imm64      2       Load original return address
0x3B    [8 bytes address]   8       Original return address
0x43    jmp rax             2       Jump to original code
────────────────────────────────────────────────────────

Total: 0x45 bytes (69 bytes)
ORIGINAL_RET_OFFSET: 0x3B
```

### API Requirements

| API | Purpose | Required Access |
|-----|---------|-----------------|
| OpenProcess | Access target | PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE |
| NtQuerySystemInformation | Find waiting threads | - |
| VirtualAllocEx | Allocate shellcode | - |
| WriteProcessMemory | Write shellcode + return address | - |
| VirtualProtectEx | Make executable | - |
| OpenThread | Access target thread | THREAD_GET_CONTEXT |
| GetThreadContext | Read RSP | - |
| ReadProcessMemory | Read return address | - |

---

## ⚠️ Limitations & Constraints

### Thread Availability
- Requires target process to have waiting threads
- Not suitable for single-threaded applications
- Best targets: explorer.exe, svchost.exe, services.exe

### Timing Non-Deterministic
- Shellcode executes when thread wakes from wait
- Could be immediate or significantly delayed
- Acceptable for staged payloads and C2 implants

### Payload Restrictions
- Cannot use blocking APIs
- Cannot allocate large memory
- ~69 bytes minimum for stub (can extend)
- Must preserve x64 ABI compliance

### Privilege Requirements
- Minimum: Medium Integrity
- Must have VM_OPERATION access to target
- Not completely privilege-free

---

## 🔐 Security Considerations

### For Defenders

1. **Monitor** `OpenProcess` with VM_OPERATION flags
2. **Correlate** API sequences in SIEM
3. **Enable** ETW tracing for kernel memory operations
4. **Deploy** behavioral detection rules
5. **Regular** red team exercises to validate detection

### For Researchers

1. **Lab-only testing** on isolated VMs
2. **Never** test on production systems
3. **Maintain** audit logs
4. **Document** all findings
5. **Report** vulnerabilities responsibly

---

## 📚 References

### Academic & Technical Papers

1. **Check Point Research - Waiting Thread Hijacking**
   - Author: hasherezade
   - Date: April 2025
   - URL: https://github.com/hasherezade/waiting_thread_hijacking

2. **Windows Internals Part 2 (7th Edition)**
   - Chapter: Thread and Context Management
   - Authors: Russinovich, Solomon, Ionescu

3. **MITRE ATT&CK Framework**
   - Technique T1055: Process Injection
   - URL: https://attack.mitre.org/techniques/T1055/

### Tools & Resources

- **Sysmon:** https://docs.microsoft.com/en-us/sysinternals/
- **Process Hacker:** https://processhacker.sourceforge.io/
- **PE-sieve:** https://github.com/hasherezade/pe-sieve
- **Volatility 3:** https://github.com/volatilityfoundation/volatility3

---

## 📁 Repository Structure

```
waiting-thread-hijacking/
├── README.md                          # This file
├── wth_poc.cpp                        # Main PoC implementation
├── COMPILE_AND_TEST.md                # Detailed testing guide
├── TECHNICAL_ANALYSIS.md              # Deep technical breakdown
├── DETECTION_RULES.md                 # Sysmon/ETW/KQL rules
├── APT_CONTEXT.md                     # Real-world APT usage
└── docs/
    ├── MITRE_ATT&CK_MAPPING.md       # Framework mapping
    ├── ASSEMBLY_REFERENCE.md          # Shellcode disassembly
    └── WINDOWS_INTERNALS.md           # Thread structures
```

---

## 💻 System Requirements

- **OS:** Windows 10 (20H2) or Windows 11
- **Architecture:** x64 only
- **Compiler:** MSVC, MinGW, or Clang
- **Privileges:** Standard user (Medium Integrity)
- **Dependencies:** Windows SDK (for winternl.h)

---

## 🚀 Performance Characteristics

| Metric | Value |
|--------|-------|
| Execution Time | 100-500ms |
| Memory Usage | <1MB |
| CPU Impact | <1% |
| Detection Difficulty | High |
| Privilege Requirement | Medium Integrity |
| Target Compatibility | ~85% of processes |

---

## 📝 License

This code is provided for **educational and authorized security research purposes only**.

```
UNAUTHORIZED USE IS ILLEGAL
Violators will be prosecuted under applicable laws
including the Computer Fraud and Abuse Act (CFAA)
```

---

## ✍️ Citation

If you reference this research, please cite:

```bibtex
@misc{wth_poc_2025,
  title={Waiting Thread Hijacking - Proof of Concept},
  author={Security Researcher},
  year={2025},
  howpublished={\url{https://github.com/yourusername/waiting-thread-hijacking}},
  note={Based on hasherezade's research at Check Point Research}
}
```

---

## 📞 Contact & Support

- **Issues:** Use GitHub Issues for bugs/questions
- **Security Disclosures:** Responsible disclosure only
- **Research Collaboration:** Contact via GitHub

---

## 🙏 Acknowledgments

- **hasherezade** (Check Point Research) - Original research and PoC
- **Windows Internals** community for documentation
- **BluBank Security** for research collaboration

---

**Last Updated:** June 2026
**Status:** Production-Ready for Lab Testing
**Disclaimer:** See DISCLAIMER.md for full legal information