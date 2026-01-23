# Detection Engineering: Samba Map Script (CVE-2007-2447)

> **Syntropy Intel:** 🐧 [Case Study: Lame (Linux)](../01-HackTheBox/Linux/Lame/Report.md) | 🧠 [Mental Model: The Legacy Bridge](../00-Mental-Models/The-Legacy-Bridge.md)

## 1. Executive Summary

**Vulnerability:** CVE-2007-2447 (Samba "Username Map Script" Command Execution)
**Severity:** Critical (CVSS 9.0)
**Rule ID:** `SID:1000003`
**Status:** ✅ Verified (Lab Tested)

This detection module targets the exploitation of the `username map script` option in Samba 3.0.20. Attackers exploit this by injecting shell metacharacters (specifically backticks or shell pipe operators) into the username field during the SMB Session Setup phase. This allows arbitrary command execution as `root` without authentication.

---

## 2. Technical Context

**The Mechanism:**
Samba allows administrators to map Windows usernames to Unix users via a script defined in `smb.conf`. In vulnerable versions, the input provided in the username field is passed directly to `/bin/sh` without sanitization.

**Attack Signature:**
* **Network:** The presence of shell invocation strings (e.g., `/bin/sh`, `nohup`) or shell metacharacters inside the SMB `Session Setup AndX` request.
* **Endpoint:** The `smbd` daemon (Samba) spawning a shell (`sh`, `bash`) or network utilities (`nc`) as child processes.

---

## 3. Network Defense (Snort 3)

To replicate this detection in a lab environment (Kali Linux), create the following two files.

### A. The Rule File (`samba.rules`)
This rule detects the default Metasploit payload artifact (`/bin/sh`) traversing the SMB protocol.

```bash
# Save as: samba.rules
alert tcp $EXTERNAL_NET any -> $HOME_NET 139,445 (msg:"Syntropy-Detection: Samba Username Map Script Injection"; flow:to_server,established; content:"/bin/sh"; fast_pattern; metadata:service netbios-ssn; sid:1000003; rev:3;)
```

### B. The Configuration (minimal.lua)
A clean-room configuration to run Snort without external dependencies.

```
-- Save as: minimal.lua
-- Syntropy Minimal Config
stream = { }
stream_tcp = { }
ips = { enable_builtin_rules = true }
```

### C. Execution Command
Run Snort in alert mode, pointing to your new rule and config.

```
sudo snort -c minimal.lua -R samba.rules -i tun0 -A alert_fast -k none
```

## 4. Evidence & Proof of Work

**Methodology:**
1.  **Attacker:** Kali Linux executing Metasploit `exploit/multi/samba/usermap_script`.
2.  **Defender:** Snort 3 running locally on the attacker interface (`tun0`) to intercept outbound exploit traffic.
3.  **Victim:** HTB Lame (`10.129.2.224`) running vulnerable Samba 3.0.20.

**Telemetry Analysis:**
The evidence below captures the exact moment of compromise.
* **Left Panel (Network):** Snort triggers `SID:1000003` immediately as the `/bin/sh` payload is transmitted.
* **Right Panel (Endpoint):** The process tree (`ps axjf`) confirms that the `smbd` service (PID 5458) spawned a malicious shell hierarchy, validating the RCE.

![Combined Detection Evidence](../01-HackTheBox/Linux/Lame/Assets/Snort_Lame_alert.png)

---


### False Positives & Tuning

**Legacy Logon Scripts:** Some older Samba configurations use logon script = %U.bat. If your environment relies on this, whitelist the specific script paths.

**Printers:** Some printer driver installation scripts may trigger this behavior temporarily.
