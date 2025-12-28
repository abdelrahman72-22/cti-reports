# Threat Intelligence Analysis Report  
## Yellow Cockatoo 

  **This assessment evaluates whether Yellow Cockatoo represents a user-driven initial access threat capable of bypassing traditional perimeter- and email-based security controls, with a focus on behavioral tradecraft and detection implications.**
  

---

## 1. Executive Summary

This report assesses a malware sample associated with the _Yellow Cockatoo_ malware family, repeatedly observed delivered through loaders overlapping with **Jupyter Infostealer–like activity**. The malware is primarily distributed via **search engine abuse techniques**, including SEO poisoning and malvertising, leading users to download and execute malicious executables masquerading as legitimate software or document-related tools.

The threat presents a **high operational risk** due to its reliance on **normal user behavior rather than software exploitation**, allowing it to bypass traditional perimeter defenses and email-based security controls. Once executed, the malware establishes command-and-control (C2) communication, enabling data exfiltration and follow-on payload delivery.

This intelligence primarily supports **SOC, detection engineering, and blue team operations** by highlighting a user-driven initial access model that requires **behavioral and execution-based detection** rather than signature- or attachment-focused controls.

---

## 2. Scope & Data Sources

### Analyzed Data:
- Malware sample hash (SHA-256)
- Public malware metadata
- Known campaign indicators
- Open-source threat intelligence reporting

### Not Available:
- Full sandbox detonation telemetry
- Original malicious landing pages
- Victim-side browser and endpoint logs

The absence of landing page telemetry limits confidence in specific SEO poisoning mechanics but does not materially impact the behavioral assessment of post-execution tradecraft.

---

## 3. Observed Behavior

The malware is implemented as a **.NET assembly** designed for **in-memory execution** using `System.Reflection.Assembly`. Upon execution, it performs system profiling, generates a unique hardware identifier (HWID), and initiates outbound communication with attacker-controlled infrastructure.

Observed behaviors include:
- Host and environment reconnaissance
- HTTP/HTTPS-based C2 beaconing
- Download and execution of secondary payloads
- Process injection via process hollowing
- PowerShell-based execution chains

These behaviors collectively **support the assessment** that Yellow Cockatoo relies on **user-initiated execution** rather than exploitation, aligning with a user-driven initial access model.

---

## 4. TTP Analysis (MITRE ATT&CK)

|Tactic|Technique|Justification|
|---|---|---|
|Execution|T1204|User manually executes a masqueraded binary|
|Defense Evasion|T1036|Masquerading as legitimate software or documents|
|Execution|T1059.001|PowerShell used within execution chain|
|Execution|T1047|WMI used for execution and system interaction|
|Privilege Escalation / Injection|T1055.012|Process hollowing into `msinfo32.exe`|
|Discovery|T1016|Network configuration discovery|
|Discovery|T1046|Network service discovery|
|Command and Control|T1071|Application layer protocol (HTTP/HTTPS)|

---

## 5. Threat Infrastructure & Context

The malware communicates with the following C2 pattern:
- https://gogohid%5B.%5Dcom/gate?q=ENCODED_HOST_INFO

Collected host parameters include:
- `hwid`: Randomly generated identifier stored in `solarmarker.dat`
- `pn`: Computer name
- `os`: Windows OS version
- `x`: System architecture
- `prm`: Privilege level
- `wg`: Workgroup
- `ver`: Malware version identifier (DN-DN/FB1)

Infrastructure observations indicate the use of:
- Recently registered domains
- Dynamic payload delivery
- Minimal static indicators

This infrastructure model reduces the effectiveness of blocklist-based defenses and increases dwell time prior to detection, emphasizing the need for behavioral controls.

---

## 6. Threat Actor Assessment

The activity shows strong overlap with known Yellow Cockatoo campaigns and tooling associated with Jupyter Infostealer.

**Attribution Confidence: Medium**

Limitations:
- No exclusive infrastructure ownership
- Shared tooling across campaigns
- Commodity loader behavior

Attribution does not materially alter defensive recommendations, as observed behaviors remain relevant regardless of actor identity.

---

## 7. Assessment & Confidence Levels

**High Confidence**
- Initial access relies on search engine abuse and user execution
- In-memory execution used to evade disk-based detection
- C2 communication enables follow-on payload delivery

**Medium Confidence**
- Consistent infection chain across multiple observations
- Association with Yellow Cockatoo activity clusters

**Low Confidence**
- Exact SEO poisoning mechanics
- Original malvertising landing page content

---

## 8. Detection & Mitigation Considerations

### Immediate Detection Opportunities:
- Alert on browser-initiated executable downloads
- Detect rapid execution of newly downloaded binaries
- Identify first-seen binaries executing from user directories
- Detect abnormal PowerShell execution chains
- Detect process hollowing into legitimate system binaries

### Strategic Mitigations:
- Restrict executable downloads from browsers
- Enforce DNS filtering for newly registered domains
- Implement behavioral EDR detections
- Disable hidden file extensions
- Apply Zero Trust principles to user execution

---

## 9. What We Don’t Know

- Full redirection logic used in the SEO poisoning chain
- Exact user interaction flow prior to download
- Additional infrastructure used beyond observed C2
- Extent of lateral movement in victim environments

These gaps represent priority collection requirements for future intelligence cycles.

---

## Appendix: Indicators

- SHA-256: 30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85
- Dropped file: `%USERPROFILE%\AppData\Roaming\solarmarker.dat`
- Suspicious IP: 52.158.209.219 , 45.146.165[.]X
