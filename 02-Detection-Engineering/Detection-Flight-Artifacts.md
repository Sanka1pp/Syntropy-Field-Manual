| 📡 **[Mission Report](../01-HackTheBox/Windows/Flight/Report.md)** | 🧠 **[Mental Model](../00-Mental-Models/The-Watering-Hole-Principle.md)** |

# Syntropy Defense Protocol | [54nK4lP3x3]

## 🛡️ Detection Engineering: Flight Artifacts

### 1. Threat Context
The [Flight Operation](../01-HackTheBox/Windows/Flight/Report.md) utilized two distinct high-fidelity attack techniques: **RunasCs** for credential-based impersonation and **Rubeus** for Kerberos ticket manipulation.

### 2. Sigma Rule: RunasCs Execution
**Title:** RunasCs Process Creation
**Description:** Detects the execution of `RunasCs.exe`, a tool commonly used to bypass UAC and execute commands with explicit credentials in a new logon session.

```yaml
title: RunasCs Usage Detected
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Detects the binary name or the specific command line flags
        Image|endswith: '\RunasCs.exe'
        CommandLine|contains:
            - ' -r '    # Remote listener flag
            - ' --bypass-uac'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1134
