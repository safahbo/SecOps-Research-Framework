# System Architecture & Data Flow

This document visualizes the **Continuous Verification (CV)** loop implemented in the SecOps Research Framework.

## The Autonomous Self-Check Loop
The following diagram illustrates how the `Watchdog` module validates the detection capabilities in real-time.

```mermaid
sequenceDiagram
    participant Admin as SRF-CLI (User)
    participant WD as Watchdog Script
    participant OS as Syslog / OS
    participant Agent as Wazuh Agent
    participant SIEM as Wazuh Manager (Engine)
    
    Note over Admin, SIEM: Phase 1: Trigger
    Admin->>WD: Run Auto-Test (Option 2)
    WD->>OS: Inject Fake Threat Log (JSON)
    OS->>Agent: Read Log File
    Agent->>SIEM: Ship Log Event (Encrypted)

    Note over Admin, SIEM: Phase 2: Detection
    SIEM->>SIEM: Analyze with Rule ID 100099
    SIEM-->>SIEM: Generate Alert

    Note over Admin, SIEM: Phase 3: Verification
    WD->>WD: Wait 5 Seconds (Buffer)
    WD->>SIEM: API Query: "Did you see test ID?"
    
    alt Detection Successful
        SIEM-->>WD: API Response: "Yes, Alert Found"
        WD-->>Admin: [PASS] System Healthy
    else Detection Failed
        SIEM-->>WD: API Response: "Null / No Data"
        WD-->>Admin: [FAIL] BLIND SPOT DETECTED!
    end
