# SOC – APT29

## What Matters
- APT29 consistently prioritizes credential-based and identity-centric access over exploit-heavy intrusions.
- Initial access is frequently achieved via spear-phishing using socially plausible lures rather than technical sophistication.
- Post-compromise activity often lacks traditional malware indicators and relies on legitimate cloud and enterprise services.
- Long dwell times are expected, with activity blending into normal administrative behavior.

## Detection Focus
- Anomalous cloud authentication patterns, especially token reuse or session anomalies.
- Unusual permission changes within Microsoft 365 and cloud identity platforms.
- Email access activity inconsistent with historical user behavior.
- Use of legitimate platforms or services for command-and-control–like behavior.

## Alert Types Likely to Fail

- Signature-based malware detections.
- Isolated endpoint alerts without correlated identity or cloud context.
- Single authentication failures without behavioral patterns.