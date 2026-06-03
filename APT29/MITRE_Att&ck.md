# MITRE ATT&CK – APT29 (Reference)

## Scope
This document provides a focused mapping of consistent and operationally relevant MITRE ATT&CK techniques associated with APT29.
It is intended as a reference for detection engineering, threat hunting, and purple team activities, not as a comprehensive technique inventory.

---

## Key Techniques

### Initial Access
- T1566 – Phishing
- T1078 – Valid Accounts

---

### Execution
- T1059 – Command and Scripting Interpreter

---

### Persistence
- T1098 – Account Manipulation
- T1136 – Create Account

---

### Privilege Escalation
- T1068 – Exploitation for Privilege Escalation

---

### Defense Evasion
- T1027 – Obfuscated Files or Information
- T1036 – Masquerading

---

### Credential Access
- T1550 – Use Alternate Authentication Material
- T1556 – Modify Authentication Process

---

### Discovery
- T1087 – Account Discovery
- T1046 – Network Service Discovery

---

### Lateral Movement
- T1021 – Remote Services

---

### Command and Control
- T1071 – Application Layer Protocol
- T1090 – Proxy

---

## Notes
- APT29 exhibits strong technique stability, with long-term reuse of identity- and access-related ATT&CK techniques.
- Innovation is primarily observed in execution context (cloud identity, OAuth, trusted services) rather than the introduction of novel techniques.
- Malware usage is selective and minimized, with greater emphasis on credential access, account manipulation, and persistence through identity.
- This mapping intentionally excludes one-off or campaign-specific techniques to preserve analytical clarity.
