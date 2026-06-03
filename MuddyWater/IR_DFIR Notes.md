# IR – APT29

## Investigation Expectations

- Extended dwell time should be assumed.
    
- Malware artifacts may be limited or unsophisticated.
    
- Initial compromise is often phishing-driven, followed by gradual internal movement.
    

## Where to Look

- Email logs and phishing telemetry preceding the suspected compromise window.
    
- Script execution logs (PowerShell, command-line activity).
    
- Persistence mechanisms such as scheduled tasks, registry entries, and startup scripts.
    
- Outbound HTTPS communication patterns from non-standard systems.
