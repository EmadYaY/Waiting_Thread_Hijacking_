# 🔍 DETECTION RULES FOR WTH

Detection rules for **Waiting Thread Hijacking** across multiple platforms.

---

## 🔔 Sysmon Detection Rules

### Sysmon Event ID 10: ProcessAccess

**Rule Name:** Suspicious Cross-Process Memory Access (WTH Indicator)

```xml
<RuleGroup groupRelation="or">
  <ProcessAccess onmatch="include">
    <!-- Target: Any process commonly injected -->
    <TargetImage condition="image">explorer.exe;svchost.exe;dwm.exe;rundll32.exe;services.exe</TargetImage>
    
    <!-- Source: Any suspicious process -->
    <SourceImage condition="image">explorer.exe</SourceImage>
    
    <!-- Access Mask: VM_OPERATION | VM_READ | VM_WRITE = 0x38 -->
    <GrantedAccess condition="is">0x38</GrantedAccess>
    
    <!-- Exclude: System processes -->
    <SourceParentImage condition="exclude">services.exe;system.exe;svchost.exe</SourceParentImage>
  </ProcessAccess>
</RuleGroup>
```

**What it detects:**
- OpenProcess call with suspicious access masks
- Cross-process VM_OPERATION access
- Unusual process-to-process relationships

---

### Sysmon Event ID 8: CreateRemoteThread

**Rule Name:** Suspicious Remote Thread Creation (WTH Alternative)

```xml
<RuleGroup groupRelation="or">
  <CreateRemoteThread onmatch="include">
    <!-- Any attempt to create remote thread -->
    <TargetImage condition="image">explorer.exe;svchost.exe;services.exe</TargetImage>
    <SourceImage condition="exclude">services.exe;svchost.exe</SourceImage>
  </CreateRemoteThread>
</RuleGroup>
```

---

### Sysmon Event ID 11: FileCreate (Behavioral Correlation)

**Rule Name:** Memory Allocation + Write Pattern (Multi-Event)

```xml
<!-- Combined detection: OpenProcess + VirtualAllocEx + WriteProcessMemory -->
<!-- Monitor for this pattern within 5 seconds -->

Event Sequence:
1. ProcessAccess (Event ID 10)
   - GrantedAccess: 0x38
   - Within 5 seconds

2. Followed by:
   - CreateRemoteThread (Event ID 8) OR
   - Memory allocation pattern (timing)

3. Followed by:
   - File write to injected memory region OR
   - Memory permission change
```

---

## 📊 ETW Detection Rules

### Enable Tracing

```powershell
# Start kernel process tracing
logman start WTH_Trace -p "Microsoft-Windows-Kernel-Process" -o wthtrace.etl -ets

# Also enable memory provider
logman start WTH_Trace -p "Microsoft-Windows-Kernel-Memory" -o wthtrace.etl -ets

# Stop tracing
logman stop WTH_Trace -ets

# View events
tracerpt wthtrace.etl -o result.xml
```

### Detection Patterns

**Pattern 1: VirtualAllocEx + MemoryWrite**

```
ETW Event Sequence:
1. Process/Thread Handle Open
   - GrantedAccess = PROCESS_VM_OPERATION
   
2. VirtualAllocEx
   - Base address
   - Size
   - Allocate flags (MEM_COMMIT | MEM_RESERVE)
   - Protect = PAGE_READWRITE
   
3. MemoryWrite
   - Virtual address = allocated region
   - Size = shellcode size (~69 bytes)
   
4. MemoryProtect
   - Base address = same as allocation
   - NewAccessProtection = PAGE_EXECUTE_READ
   
Detection: This sequence is rare and highly suspicious
```

**Pattern 2: Stack Modification**

```
ETW Event: MemoryWrite
- Address range: [RSP] - [RSP+0x20] (stack)
- Source: Another process
- Context: Thread in waiting state

Detection: Stack writes from external process = critical
```

---

## 🔍 KQL Queries (Microsoft Defender)

### Query 1: Basic ProcessAccess Detection

```kusto
DeviceProcessEvents
| where TargetProcessName has_any ("explorer.exe", "svchost.exe", "dwm.exe")
| where InitiatingProcessName !has_any ("services.exe", "system")
| where InitiatingProcessIntegrityLevel in ("medium", "high")
| where ProcessId != InitiatingProcessId
| project Timestamp, InitiatingProcessName, TargetProcessName, ProcessId, InitiatingProcessId
```

### Query 2: Memory Allocation + Write Pattern

```kusto
DeviceProcessEvents
| where TargetProcessName has_any ("explorer.exe", "svchost.exe")
| where ActionType == "VirtualAllocEx"
| join kind=inner (
    DeviceProcessEvents
    | where ActionType == "WriteProcessMemory"
    | where Timestamp > ago(10s)
  ) on DeviceId, Timestamp
| where datediff(second, Timestamp, Timestamp1) < 5
| project Timestamp, InitiatingProcessName, TargetProcessName
```

### Query 3: Cross-Process Thread Access

```kusto
DeviceProcessEvents
| where ActionType == "ThreadAccess"
| where TargetProcessName != InitiatingProcessName
| where InitiatingProcessIntegrityLevel == "medium"
| where InitiatingProcessName !has_any ("services.exe", "system")
| project Timestamp, InitiatingProcessName, TargetProcessName, ThreadId
```

### Query 4: Behavioral Correlation (Advanced)

```kusto
let ProcessAccessEvents = DeviceProcessEvents
    | where ActionType == "ProcessAccess"
    | where GrantedAccess == "0x38"
    | project Timestamp, InitiatingProcessName, TargetProcessName, DeviceId
    | order by Timestamp desc;

let VirtualAllocEvents = DeviceProcessEvents
    | where ActionType == "VirtualAllocEx"
    | project Timestamp, InitiatingProcessName, TargetProcessName, DeviceId
    | order by Timestamp desc;

ProcessAccessEvents
| join kind=inner VirtualAllocEvents on InitiatingProcessName, TargetProcessName, DeviceId
| where Timestamp - Timestamp1 between (0s .. 5s)
| summarize Count=count() by InitiatingProcessName, TargetProcessName
| where Count >= 2
```

---

## 📈 Sigma Rules

### Sigma Rule: WTH Detection

```yaml
title: Waiting Thread Hijacking Detection
id: wth-injection-detection
status: experimental
description: Detects potential WTH process injection
author: Security Team
date: 2025/06/24

logsource:
  product: windows
  service: sysmon

detection:
  # Pattern 1: ProcessAccess with suspicious flags
  process_access:
    EventID: 10
    TargetImage|endswith:
      - explorer.exe
      - svchost.exe
      - dwm.exe
      - services.exe
    GrantedAccess: '0x38'
    SourceParentImage|endswith:
      - services.exe
      - system.exe
    SourceParentImage|exclude:
      - services.exe
      - svchost.exe

  # Pattern 2: Memory allocation in target
  virtual_alloc:
    EventID: 11
    CallStack|contains: VirtualAllocEx
    ProtectionMask: '0x04'  # PAGE_READWRITE

  # Pattern 3: Memory write to allocated region
  write_memory:
    EventID: 11
    TargetImage|endswith:
      - explorer.exe
      - svchost.exe
    CallStack|contains: WriteProcessMemory

  # Correlation: All three within 10 seconds
  selection: process_access and virtual_alloc and write_memory
  timeframe: 10s

falsepositives:
  - Legitimate process migration tools
  - VM management software
  - System utilities with high privileges

level: high
tags:
  - process_injection
  - defense_evasion
  - execution
```

---

## 🎯 Real-Time Detection

### Using WinDBG/LiveKD

```windbg
# Enable breakpoint on suspicious pattern
bp wth_poc!ExecuteWTH

# Show thread stack
!dumpstack

# Examine memory allocations
!address -summary

# List threads
!threads
```

---

## 🔧 Detection Tuning

### False Positives to Handle

| Application | Reason | Mitigation |
|-------------|--------|-----------|
| Adobe Reader | Plugin injection | Whitelist AdobeReader.exe |
| Java VM | Class loading | Whitelist java.exe |
| WMI | Script execution | Monitor WMI calls separately |
| Antivirus | Memory scanning | Whitelist antivirus processes |

### Tuning Parameters

```
Baseline Analysis Period: 2-4 weeks
Event Window: 10 seconds max
Minimum Event Count: 3 per window
Alert Threshold: Medium (score > 60)
Response: Isolate process, collect memory dump
```

---

## 📝 Incident Response

### Detection → Response Workflow

```
1. Alert Triggered
   └─→ WTH pattern detected

2. Immediate Actions
   └─→ Isolate system from network
   └─→ Collect memory dump
   └─→ Preserve event logs

3. Investigation
   └─→ Analyze shellcode
   └─→ Identify source process
   └─→ Trace command and control

4. Containment
   └─→ Kill malicious process
   └─→ Block C2 communications
   └─→ Scan for lateral movement

5. Recovery
   └─→ Restore from clean backup
   └─→ Patch vulnerabilities
   └─→ Update detection rules
```

---

## 🧪 Testing Detection Rules

### Validation Procedure

```bash
# 1. Compile WTH PoC
cl.exe wth_poc.cpp /link ntdll.lib psapi.lib

# 2. Enable logging
sysmon -i -accepteula
logman start WTH_Trace -p "Microsoft-Windows-Kernel-Process" -ets

# 3. Execute PoC
wth_poc.exe <target_pid>

# 4. Verify alerts
# Check: Sysmon logs, ETW traces, KQL results

# 5. Document findings
# Record: Event IDs, timestamps, correlation quality
```

### Expected Detection Results

| Detection Method | Expected | Actual | Status |
|------------------|----------|--------|--------|
| Sysmon Event ID 10 | ✅ Yes | ? | TODO |
| ETW VirtualAllocEx | ✅ Yes | ? | TODO |
| KQL Pattern Match | ✅ Yes | ? | TODO |
| Behavioral Correlation | ✅ Yes | ? | TODO |
| Memory Forensics | ✅ Yes | ? | TODO |

---

## 📊 Metrics

### Detection Effectiveness

```
True Positive Rate (TPR):  ___%
False Positive Rate (FPR): ___%
Detection Latency:         ___ seconds
Mean Time to Detection:    ___ minutes
```

---

**Last Updated:** June 2026
**Status:** Ready for Deployment