| 📡 **[Mission Report](Report.md)** | 🧠 **[Mental Model](The-Artifact-Echo.md)** |

# Syntropy Defense Protocol | [54nK4lP3x3]

## 🛡️ Detection Engineering: PRTG Exploitation (CVE-2018-9276)

### 1. Threat Context
**Vulnerability:** Authenticated Remote Code Execution (RCE) in PRTG Network Monitor.
**Attack Vector:** Attackers inject OS commands into the "Parameter" field of the Notification settings.
**Significance:** As seen in the [Netmon Operation](Report.md), this allows instant elevation to `NT AUTHORITY\SYSTEM`.

---

### 2. Sigma Rule (Endpoint)
**Title:** PRTG Core Service Spawning Shell
**Description:** Detects the PRTG core service process (`PRTG Core Server.exe`) spawning a command line interpreter (`cmd.exe`, `powershell.exe`). This is a high-fidelity indicator of the CVE-2018-9276 exploit chain.

```yaml
title: PRTG Core Service Spawning Shell
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\PRTG Network Monitor\PRTG Core Server.exe'
            - '\PRTG Network Monitor\PRTG Probe.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059
```
---
