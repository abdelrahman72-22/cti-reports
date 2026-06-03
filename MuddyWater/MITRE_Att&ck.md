# MITRE ATT&CK – MuddyWater (Reference)

## Scope
This document provides a focused mapping of consistent and operationally relevant MITRE ATT&CK techniques associated with MuddyWater.
It is intended as a reference for detection engineering, threat hunting, and purple team activities, not as a comprehensive technique inventory.

---

## Key Techniques

### Initial Access
- T1566 – Phishing
- T1190 – Exploit Public-Facing Application

---

### Execution
- T1059 – Command and Scripting Interpreter

---

### Persistence
- T1547 – Boot or Logon Autostart Execution
- T1053 – Scheduled Task/Job

---

### Privilege Escalation
- T1068 – Exploitation for Privilege Escalation

---

### Defense Evasion
- T1027 – Obfuscated Files or Information
- T1036 – Masquerading

---

### Credential Access
- T1003 – OS Credential Dumping

---

### Discovery
- T1082 – System Information Discovery
- T1083 – File and Directory Discovery

---

### Lateral Movement
- T1021 – Remote Services

---

### Command and Control
- T1071 – Application Layer Protocol
- T1105 – Ingress Tool Transfer

---

## Notes
- MuddyWater demonstrates high technique stability over time, favoring reliable and low-risk ATT&CK techniques.
- Innovation is typically observed in delivery mechanisms, infrastructure usage, and operational pacing rather than novel techniques.
- Commodity tooling and scripting are deliberately used to blend with normal administrative activity and reduce operational friction.
- This mapping intentionally excludes rarely observed or one-off techniques to preserve analytical signal.
