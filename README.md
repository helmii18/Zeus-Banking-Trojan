# Zeus-Banking-Trojan
Detect and analyze the Zeus Banking Trojan using various tools and techniques, including malware simulation, network monitoring, memory analysis, and signature-based detection

# Suricata
Using Suricata to monitor network traffic and use the default rules to detect common threats:
Set interface :
![image](https://github.com/user-attachments/assets/f02a6905-8832-4272-9301-c4925864be71)

##Set the rules to the default on the suricata.yaml

![image](https://github.com/user-attachments/assets/1f05998d-f6ce-4481-88ad-e339ce73ae31)

##Run Suricata
![image](https://github.com/user-attachments/assets/0bdb18d8-dfcd-47fe-8f8a-c1d46d98b6db)

##Logs created
![image](https://github.com/user-attachments/assets/fcb0e015-f731-469c-85c7-1ca10cc644f8)

##Write custom Suricata rules to detect Zeus-specific network patterns

##The rules we will use:

![image](https://github.com/user-attachments/assets/a9e7fe38-aa4c-4b25-a22c-a55b4e0983ad)
![image](https://github.com/user-attachments/assets/755aaaf0-44ea-4357-af44-6e035968263c)
![image](https://github.com/user-attachments/assets/7e049d85-b899-4739-abc8-47045eace521)

##Run Suricata
![image](https://github.com/user-attachments/assets/38450362-a465-45c3-a518-bf8714f394f7)

##Logs created
![image](https://github.com/user-attachments/assets/ad206dfe-f418-49a6-9ec4-a04ad9ab5f47)


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

