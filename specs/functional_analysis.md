# Functional Analysis & Logic Design
**Module:** Autonomous Defense Engine

## 1. Problem Statement
Traditional SOC (Security Operations Center) architectures are **static**.
* **Blind Spots:** Security teams often do not realize a detection rule is broken until a real breach occurs.
* **Silent Failures:** If the log shipper (Agent) stops working, the SIEM remains silent, creating a false sense of security.

## 2. Solution Architecture: "Active Verification"
SRF introduces a **Continuous Verification (CV)** loop inspired by CI/CD principles. The system does not just "wait" for attacks; it actively simulates them to verify its own health.

### 2.1. The Watchdog Mechanism (Auto-Test)
The `secops-watchdog.sh` module operates on the following logic:

1.  **Injection (Trigger):**
    * The system generates a synthetic log entry: `{"status": "simulation_active", "id": "AUTOTEST-..."}`.
    * This simulates a specific threat pattern (TTP) without causing harm.

2.  **Telemetry Check:**
    * The watchdog waits for `T+5 seconds` to allow for log shipping and indexing.

3.  **Verification (API Query):**
    * It queries the SIEM API: *"Did you see the log with ID AUTOTEST-X?"*
    * **Logic:** `IF count > 0 THEN System_Healthy ELSE System_Blind`.

## 3. Failure Modes & Handling
| Scenario | Detection Method | System Action |
| :--- | :--- | :--- |
| **Agent Failure** | API returns `0` alerts for simulation. | Log error to `secops-test.log`, Alert Admin. |
| **API Down** | `curl` returns HTTP 500/Connection Refused. | Watchdog exits safely, retries in next cycle. |
| **Rule Disabled** | Log shipped but no alert generated. | Flags "Logic Error" in the report. |

## 4. Security Considerations
* **API Tokens:** Tokens are generated dynamically and never stored on disk (In-Memory usage).
* **Simulation Safety:** Test payloads are tagged as `secops-autotest` to prevent confusion with real incidents.
