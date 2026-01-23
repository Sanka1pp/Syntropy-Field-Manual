# Detection Engineering: Samba Map Script (CVE-2007-2447)

> **Syntropy Intel:** 🐧 [Case Study: Lame (Linux)](../01-HackTheBox/Linux/Lame/Report.md) | 🧠 [Mental Model: The Legacy Bridge](../00-Mental-Models/The-Legacy-Bridge.md)

### 1. Conceptual Framework
**The Artifact:**
The CVE-2007-2447 exploit abuses the `username map script` configuration in Samba. It injects shell metacharacters (like backticks `` ` ``) directly into the username field during the SMB Session Setup phase.

**The Logic:**
* **Network:** We detect the default Metasploit payload artifact (`/bin/sh`) inside the username field.
* **Endpoint:** We detect the anomaly of the Samba daemon (`smbd`) spawning an interactive shell, which violates standard file server behavior.

---

### 2. Network Signature (Snort)
**Status:** ✅ `Verified` (Context: Default Metasploit Payload)
**Description:** Detects the explicit path `/bin/sh` sent during the SMB Session Setup.
**Audit Note:** This rule is specific to the `multi/samba/usermap_script` module default payload. Advanced attackers may bypass this by using different shells (e.g., `bash`, `ash`) or encoding.

```bash
# Rule: Syntropy Samba Username Map Script (Default Payload)
alert tcp $EXTERNAL_NET any -> $HOME_NET 139,445 (msg:"Syntropy-Detection: Samba Username Map Script Injection"; flow:to_server,established; content:"/bin/sh"; fast_pattern; metadata:service netbios-ssn; sid:1000003; rev:2;)
```
---
