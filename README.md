# Zeus-Banking-Trojan
Detect and analyze the Zeus Banking Trojan using various tools and techniques, including malware simulation, network monitoring, memory analysis, and signature-based detection

# Suricata
Using Suricata to monitor network traffic and use the default rules to detect common threats:
## Set interface :
![image](https://github.com/user-attachments/assets/f02a6905-8832-4272-9301-c4925864be71)

## Set the rules to the default on the suricata.yaml

![image](https://github.com/user-attachments/assets/1f05998d-f6ce-4481-88ad-e339ce73ae31)

## Run Suricata
![image](https://github.com/user-attachments/assets/0bdb18d8-dfcd-47fe-8f8a-c1d46d98b6db)

## Logs created
![image](https://github.com/user-attachments/assets/fcb0e015-f731-469c-85c7-1ca10cc644f8)

## Write custom Suricata rules to detect Zeus-specific network patterns

## The rules we will use:

![image](https://github.com/user-attachments/assets/a9e7fe38-aa4c-4b25-a22c-a55b4e0983ad)
![image](https://github.com/user-attachments/assets/755aaaf0-44ea-4357-af44-6e035968263c)
![image](https://github.com/user-attachments/assets/7e049d85-b899-4739-abc8-47045eace521)

## Run Suricata
![image](https://github.com/user-attachments/assets/38450362-a465-45c3-a518-bf8714f394f7)

## Logs created
![image](https://github.com/user-attachments/assets/ad206dfe-f418-49a6-9ec4-a04ad9ab5f47)

# Splunk 

## Ingesting Suricata logs and system logs into Splunk.
![image](https://github.com/user-attachments/assets/50321962-ccc7-4a6e-931c-656766088825)

## We used event_type = alert, which returned some events all with "Network trojan was detected!" and "Blocked trojan communication".
![image](https://github.com/user-attachments/assets/dfa3c7e5-ea8c-4a68-b166-b933455e2454)
![image](https://github.com/user-attachments/assets/43ada466-e9fc-4c51-ae86-eb7c9fb7c650)

## Creating visual dashboards in Splunk to monitor malicious activity, highlighting the timestamps of alert generation.
![image](https://github.com/user-attachments/assets/7d76b2c8-6375-4c37-8be9-6a475f2f6e4f)

# Memory Analysis for Detecting Zeus Banking Trojan

This document outlines the process of analyzing memory to identify and confirm the presence of the Zeus Banking Trojan using Volatility.

---

## Determining the Profile
To begin, determine the memory image profile with the `imageinfo` plugin:
```bash
python2 vol.py -f zeus2x4.vmem imageinfo
```
![image](https://github.com/user-attachments/assets/f8ccbe6e-5405-4d5f-bec0-36227a095691)

The analysis identified the system as running Windows XP. From the recommended profiles, we selected "WinXPSP2x86."

---

## Examining Processes
1. **List Processes**: Use the `psscan` plugin to list processes:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 psscan
   ```
   ![image](https://github.com/user-attachments/assets/cd255f7a-abba-4761-ab60-8be2d51541ad)

   Observations: Process counts and names appeared normal.

2. **Analyze Process Tree**: Use the `pstree` plugin to examine parent-child relationships:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 pstree
   ```
   ![image](https://github.com/user-attachments/assets/888f9526-c273-4c51-9068-f4f669388b68)

   Observations: No irregularities were detected in the relationships.

---

## Investigating Network Connections
Network activity was analyzed for signs of suspicious behavior:
```bash
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 connections
```
![image](https://github.com/user-attachments/assets/971b58f0-4d1f-40d0-b875-d6e5cfbad3ee)
```bash
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 connscan
```
![image](https://github.com/user-attachments/assets/a9c7c3f4-40d0-402c-8593-7a377a42dc90)

Results: Suspicious IP addresses were identified, warranting further investigation via VirusTotal.
![image](https://github.com/user-attachments/assets/4ce04361-3688-4e18-bb54-22976c47fc9a)
![image](https://github.com/user-attachments/assets/98dfd443-70ee-4792-9902-68d62c1b20de)
![image](https://github.com/user-attachments/assets/ea3058c3-ea60-419b-a777-b36887270710)

---

## Analyzing the Malicious Process
1. **Filter Process by PID**:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 psscan | grep 1752
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 pstree | grep 1752
   ```
   ![image](https://github.com/user-attachments/assets/d1b4e54a-2ce1-4e5c-bdaf-3cd12370df01)
![image](https://github.com/user-attachments/assets/44e334dc-b9e6-4b82-9aa0-44dc6335ab71)

2. **Check Process Path**:
   ```bash
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 cmdline | grep 1752
   ```
   Observations: Process path appeared legitimate.
![image](https://github.com/user-attachments/assets/a7f9098b-952f-4e0f-9ee7-9a4cc8a27232)

---

## Investigating Code Injection
To identify malicious code injection:
```bash
python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 malfind -p 1752
```
![image](https://github.com/user-attachments/assets/5102cb0c-63f7-491b-8d4e-e140f253d43d)
![image](https://github.com/user-attachments/assets/c63779ae-81f6-4b40-a211-e51b57e6932e)

Results: The process exhibited an MZ header and the `PAGE_EXECUTE_READWRITE` memory protection, indicating executable and writable memory regions—a hallmark of code injection.

---

## Dumping Malicious Artifacts
1. **Dump Process**:
   ```bash
   mkdir procdump
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 procdump -p 1752 -D procdump/
   ```
   ![image](https://github.com/user-attachments/assets/f7a75435-ea76-4323-991f-64f2f32089ac)
![image](https://github.com/user-attachments/assets/0d97b5a5-1dcf-4e34-8faa-58d0b7a65631)

   Check the hash of the dumped executable:
   ```bash
   sha256sum procdump/executable.1752.exe
   ```
![image](https://github.com/user-attachments/assets/9469cd5f-99a3-46d5-8255-88d8cb938da7)
![image](https://github.com/user-attachments/assets/9a12e11f-d2f0-4ded-9414-d9f0e90ad720)

2. **Dump Injected Memory Region**:
   ```bash
   mkdir vaddump
   python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 vaddump -p 1752 -b 0x3080000 -D vaddump/
   sha256sum vaddump/
   ```
   ![image](https://github.com/user-attachments/assets/4ac9f2a3-b6d8-48e5-87bb-0bc4450aa8b0)

Results: The memory dump confirmed malicious activity.
![image](https://github.com/user-attachments/assets/5fea93ee-2611-4a14-ac92-1e85f35dc0d2)
![image](https://github.com/user-attachments/assets/c40ae166-a9a7-4d89-9612-13e5965e32cd)

---

## Findings
1. **Active and Injected Processes**: The process with PID 1752 exhibited suspicious behavior and memory injection consistent with Zeus malware.
2. **Network Connections**: Connections to external IPs linked to command-and-control (C2) servers, with encrypted communication traces.
3. **Malware Artifacts**: Dumped executable and memory regions aligned with known Zeus signatures, confirmed via hash analysis.

---



# Zeus Malware Detection YARA Rule
## Overview
This repository contains an advanced YARA rule designed to detect variants of the Zeus malware family. The rule implements multiple detection methods including file characteristics, function names, network indicators, and process behaviors.
Author
```bash
Author: George Fady
Rule Name: Zeus_Advanced
```
Technical Details
Rule Structure
The YARA rule is composed of several key components that work together to identify potential Zeus malware variants:
Magic Byte Detection
yaraCopy$PE_magic_byte = "MZ" ascii
Verifies that the target is a valid Windows Portable Executable (PE) file by checking for the MZ header at offset 0.
Detection Strings
The rule looks for the following indicators:

Suspicious File Names
yaraCopy$file_name = "invoice_2318362983713_823931342io.pdf.exe" ascii
Targets executables masquerading as PDF documents, a common social engineering tactic.
Malicious Function Names
yaraCopy$function_name = "CellrotoCrudUntohighCols" ascii
Identifies specific function names associated with Zeus variants.
Binary Patterns
yaraCopy$hex_string = {43 61 6D 65 56 61 6C 65 57 61 75 6C 65 72}
Matches specific byte sequences found in Zeus malware.
Network Indicators
yaraCopy$C2_domain = "zeus-malicious-domain.com" ascii
Detects known Command & Control (C2) domain patterns.
Process Artifacts
yaraCopy$mutex_name = "Global\\ZeusMutex" ascii
Identifies mutex names used by Zeus for process management.
## API Usage
yaraCopy$malicious_API = "InternetOpenA" ascii
Detects potentially malicious Windows API calls commonly used by Zeus.

## Condition Logic
yaraCopycondition:
    $PE_magic_byte at 0 and
    ($file_name or $function_name or $hex_string or $C2_domain or $mutex_name or $malicious_API)
The rule triggers when:

The file is a valid PE file (MZ header at offset 0)
AND at least one of the defined indicators is present

## Usage
Basic Scanning
To scan a specific file with this rule:
bashCopyyara Zeus_Advanced.yar /path/to/suspicious/file
Example
bashCopyyara Zeus_Advanced.yar invoice_2318362983713_823931342io.pdf.exe
Detection Strategy
This rule implements a multi-faceted detection approach:

## Validates file format (PE structure)
Checks for social engineering indicators in filenames
Searches for known malicious code patterns
Identifies network communication attempts
Detects process manipulation techniques
Monitors suspicious API usage

## Notes

The rule is designed to be flexible, allowing for detection even if only some indicators are present
False positives may occur with legitimate files using similar API calls
Regular updates to C2 domains and file patterns are recommended
Consider this rule as part of a broader detection strategy

## Contributing
To enhance this rule, consider:

Adding new Zeus variant signatures
Updating C2 domain patterns
Including additional API call patterns
Improving condition logic for better accuracy

This analysis demonstrates the presence of Zeus Banking Trojan through memory analysis, process investigation, and artifact dumping for further correlation with known malware databases.

