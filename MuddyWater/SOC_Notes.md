# SOC – APT29

## What Matters

- MuddyWater consistently relies on **spear-phishing** as its primary initial access vector, often using simple, contextually relevant lures.
    
- Post-compromise activity tends to be **low-to-moderate noise** but persistent, prioritizing continued access over rapid expansion.
    
- The actor favors **commodity tooling and scripting** rather than advanced or bespoke malware.
    
- Lateral movement is typically slow and constrained within existing trust boundaries.
    

## Detection Focus

- Repeated phishing activity targeting government, telecommunications, or infrastructure-adjacent organizations.
    
- PowerShell or script execution without a clear operational justification.
    
- Creation or modification of basic persistence mechanisms (e.g., autostart entries, scheduled tasks).
    
- Unusual outbound HTTPS traffic from systems not expected to initiate external connections.

### Alert Types Likely to Fail

- Signature-only malware detections.
    
- Single-event alerts without temporal or behavioral correlation.
    
- Dismissing “low-sophistication” tooling as low-risk activity.