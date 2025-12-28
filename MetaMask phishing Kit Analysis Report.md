# Threat Intelligence Analysis Report  
## MetaMask Phishing Kit

**This assessment evaluates whether the analyzed MetaMask phishing kit represents a user-driven credential access threat capable of bypassing traditional perimeter- and endpoint-based security controls, with a focus on behavioral tradecraft and detection implications.**

---

## 1. Executive Summary

This report assesses a phishing kit designed to impersonate **MetaMask**, a widely used cryptocurrency wallet, with the objective of harvesting **Secret Recovery Phrases (seed phrases)** from victims.

The threat relies entirely on **user trust and voluntary disclosure** rather than technical exploitation, allowing it to bypass traditional perimeter defenses, endpoint protection, and email-based security controls. Victims are socially engineered into submitting their recovery phrases through a spoofed web interface that closely mimics legitimate MetaMask recovery workflows.

Once obtained, the seed phrase enables the attacker to immediately import the victim’s wallet and irreversibly drain associated cryptocurrency assets. The kit further leverages **legitimate third-party services (Telegram)** for real-time data exfiltration, reducing attacker infrastructure requirements and detection surface.

This intelligence primarily supports **SOC analysts, detection engineers, and blue team operations** by highlighting a high-impact, low-complexity credential access threat driven by user behavior rather than malware execution.

---

## 2. Scope & Data Sources

### Analyzed Data:
- Phishing kit file structure
- Frontend HTML pages impersonating MetaMask
- Backend PHP credential-handling scripts
- Local credential storage artifacts
- Embedded Telegram Bot API configuration

### Not Available:
- Original phishing delivery vector (email, social media, malvertising)
- Victim-side browser telemetry
- Blockchain transaction data post-compromise
- Hosting provider logs for the phishing infrastructure

The absence of delivery telemetry limits assessment of campaign scale and distribution methods but does not materially affect understanding of the phishing kit’s operational tradecraft.

---

## 3. Observed Behavior

The phishing kit consists of a static frontend paired with a **PHP-based backend** responsible for credential collection and exfiltration.

Observed behaviors include:
- Visual impersonation of MetaMask branding and language
- Explicit prompting for Secret Recovery Phrases
- Server-side processing of user-submitted credentials via `$_POST`
- Local plaintext logging of harvested seed phrases
- Real-time credential exfiltration via Telegram Bot API

No malware execution or exploitation occurs on the victim endpoint. The compromise is completed entirely through **user-driven credential disclosure**.

These behaviors collectively support the assessment that the threat operates as a **pure credential harvesting campaign**, rather than a malware-based intrusion.

---

## 4. TTP Analysis (MITRE ATT&CK)

| Tactic | Technique | Justification |
|------|----------|---------------|
| Initial Access | T1566.002 | Credential harvesting via phishing |
| Credential Access | T1552 | Collection of sensitive credentials |
| Exfiltration | T1041 | Exfiltration over application-layer protocols |
| Command and Control | T1102 | Use of legitimate services (Telegram) |
| Defense Evasion | T1036 | Masquerading as a legitimate service |

Reference: https://attack.mitre.org/

---

## 5. Threat Infrastructure & Context

The phishing kit does not rely on dedicated attacker-controlled C2 infrastructure. Instead, it abuses **Telegram’s Bot API** for real-time data delivery.

Observed infrastructure characteristics include:
- Hardcoded Telegram bot token and chat ID
- HTTPS-based communication with Telegram API endpoints
- Local credential storage (`log.txt`) as a redundancy mechanism

This model minimizes infrastructure cost and blends malicious traffic with legitimate encrypted application traffic, reducing detection opportunities based on network indicators alone.

---

## 6. Threat Actor Assessment

The phishing kit demonstrates low technical sophistication and does not exhibit advanced obfuscation or custom infrastructure.

Indicators suggest:
- Commodity phishing kit usage
- Potential reuse across multiple campaigns
- Developer attribution limited to embedded aliases or comments

**Attribution Confidence: Low**

Attribution is not required to inform defensive action, as the observed tradecraft is generic and widely reproducible.

---

## 7. Assessment & Confidence Levels

**High Confidence**
- Credential compromise relies on social engineering and user disclosure
- Seed phrase theft results in immediate and irreversible asset loss
- Legitimate services are abused for data exfiltration

**Medium Confidence**
- Campaigns targeting MetaMask users are widespread and recurring
- Similar kits are commonly reused with minimal modification

**Low Confidence**
- Original phishing lure mechanisms
- Total victim count and financial impact
- Post-compromise fund laundering methods

---

## 8. Detection & Mitigation Considerations

### Immediate Detection Opportunities:
- Web pages requesting cryptocurrency seed phrases
- Backend scripts handling recovery phrase input
- Abuse of Telegram Bot API for data exfiltration
- Plaintext credential logging on web servers

### Strategic Mitigations:
- User education emphasizing that seed phrases are never requested online
- Blocking known phishing domains and lookalike sites
- Monitoring outbound traffic to messaging APIs from web servers
- Browser-based phishing protection enhancements

---

## 9. What We Don’t Know

- Original phishing distribution channels
- Scale and geographic distribution of victims
- Blockchain transaction tracing post-compromise
- Overlap with other cryptocurrency phishing campaigns

These gaps represent priority intelligence collection opportunities.

---

## Appendix: Indicators

### Files
- `metamask.php`
- `log.txt`

### Network
- Telegram Bot API endpoints

### Credential Targets
- MetaMask Secret Recovery Phrase (Seed Phrase)
