# System Requirements Specification (SRS)
**Project:** SecOps Research Framework (SRF)
**Version:** 1.0.0
**Date:** 2024-01-20

## 1. Operating System Environment
The framework is designed and tested on Linux-based systems.
* **Recommended OS:** Ubuntu 22.04 LTS (Jammy Jellyfish) or newer.
* **Kernel:** Linux 5.15+ generic.
* **Shell:** Bash 5.0+ (Required for CLI & Watchdog automation).

## 2. Dependencies & Packages
The following packages must be installed for the automation modules to function correctly.

| Package | Version | Purpose |
| :--- | :--- | :--- |
| `curl` | 7.81+ | Used for API communication with Wazuh Manager. |
| `jq` | 1.6+ | Required for JSON-First parsing and type-safe data handling. |
| `python3` | 3.10+ | Required for advanced data analysis scripts (future modules). |
| `wazuh-agent`| 4.x | Must be active to receive simulation telemetry. |

## 3. Network Requirements
The framework requires local loopback connectivity for API calls.
* **Wazuh API Port:** `55000/TCP` (HTTPS)
* **Agent Communication:** `1514/TCP` or `1514/UDP`
* **API Authentication:** Requires a valid JWT Token generation capability.

## 4. Hardware Constraints
* **Minimum RAM:** 4 GB (due to Elastic/Wazuh stack requirements).
* **Storage:** Minimum 20 GB free space for log retention.
