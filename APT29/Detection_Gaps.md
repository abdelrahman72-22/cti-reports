# Detection Gaps – APT29

## Assumed Detections That May Be Weak
- Heavy reliance on endpoint-based detection for intrusion identification.
- Assumptions that legitimate cloud services cannot be abused for command-and-control.
- Limited correlation between authentication events and post-compromise activity.

## Likely Blind Spots
- OAuth token abuse and session hijacking.
- Low-volume credential misuse that mimics legitimate access.
- Abuse of trusted collaboration or cloud services for persistence.
## Defensive Assumptions to Validate
- Are cloud identity logs centrally collected and behaviorally analyzed?
- Are service and test accounts monitored with the same rigor as user accounts?
- Are conditional access and permission changes regularly reviewed?