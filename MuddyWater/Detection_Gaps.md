# Detection Gaps – APT29

## Assumed Detections That May Be Weak

- Over-reliance on endpoint security controls (AV/EDR) as primary detection mechanisms.
    
- Assumptions that low-complexity phishing cannot result in sustained compromise.
    
- Limited linkage between phishing incidents and downstream post-compromise behavior.
    

## Likely Blind Spots

- Simple persistence mechanisms (scheduled tasks, registry-based autostart).
    
- Abuse of commonly used administrative tools assumed to be benign.
    
- Low-volume, long-dwell activity that does not trigger threshold-based alerts.
    

## Defensive Assumptions to Validate

- Are phishing incidents analyzed as campaigns rather than isolated events?
    
- Is post-phishing execution consistently monitored and correlated?
    
- Are persistence mechanisms audited on a recurring basis?