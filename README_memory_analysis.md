# Memory Analysis for Detecting Zeus Banking Trojan

This document outlines the process of analyzing memory to identify and confirm the presence of the Zeus Banking Trojan using Volatility.

---

## Determining the Profile
To begin, determine the memory image profile with the `imageinfo` plugin:
```bash
python2 vol.py -f zeus2x4.vmem imageinfo
```
The analysis identified the system as running Windows XP. From the recommended profiles, we selected "WinXPSP2x86."

---

## Examining Processes
1. **List Processes**: Use the `psscan` plugin to list processes:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 psscan
   ```
   Observations: Process counts and names appeared normal.

2. **Analyze Process Tree**: Use the `pstree` plugin to examine parent-child relationships:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 pstree
   ```
   Observations: No irregularities were detected in the relationships.

---

## Investigating Network Connections
Network activity was analyzed for signs of suspicious behavior:
```bash
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 connections
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 connscan
```
Results: Suspicious IP addresses were identified, warranting further investigation via VirusTotal.

---

## Analyzing the Malicious Process
1. **Filter Process by PID**:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 psscan | grep 1752
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 pstree | grep 1752
   ```
2. **Check Process Path**:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 cmdline | grep 1752
   ```
   Observations: Process path appeared legitimate.

---

## Investigating Code Injection
To identify malicious code injection:
```bash
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 malfind -p 1752
```
Results: The process exhibited an MZ header and the `PAGE_EXECUTE_READWRITE` memory protection, indicating executable and writable memory regions—a hallmark of code injection.

---

## Dumping Malicious Artifacts
1. **Dump Process**:
   ```bash
   mkdir procdump
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 procdump -p 1752 -D procdump/
   ```
   Check the hash of the dumped executable:
   ```bash
   sha256sum procdump/executable.1752.exe
   ```

2. **Dump Injected Memory Region**:
   ```bash
   mkdir vaddump
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 vaddump -p 1752 -b 0x3080000 -D vaddump/
   sha256sum vaddump/
   ```
Results: The memory dump confirmed malicious activity.

---

## Findings
1. **Active and Injected Processes**: The process with PID 1752 exhibited suspicious behavior and memory injection consistent with Zeus malware.
2. **Network Connections**: Connections to external IPs linked to command-and-control (C2) servers, with encrypted communication traces.
3. **Malware Artifacts**: Dumped executable and memory regions aligned with known Zeus signatures, confirmed via hash analysis.

---

This analysis demonstrates the presence of Zeus Banking Trojan through memory analysis, process investigation, and artifact dumping for further correlation with known malware databases.
