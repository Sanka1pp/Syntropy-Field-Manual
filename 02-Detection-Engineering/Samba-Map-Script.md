# Detection Engineering: Samba Map Script (CVE-2007-2447)

> **Syntropy Intel:** 🐧 [Case Study: Lame (Linux)](../01-HackTheBox/Linux/Lame/Report.md) | 🧠 [Mental Model: The Legacy Bridge](../00-Mental-Models/The-Legacy-Bridge.md)

### 1. Conceptual Framework
**The Artifact:**
The CVE-2007-2447 exploit abuses the `username map script` configuration in Samba. It injects shell metacharacters (like backticks `` ` `` or `;`) directly into the username field during the SMB Session Setup phase.

**The Logic:**
Instead of looking for specific payloads, we detect the anomaly of a shell invocation command (`/bin/sh`, `nohup`) appearing inside the username string of an SMB packet, or the `smbd` daemon spawning a shell on the endpoint.

---

### 2. Network Signature (Snort/Suricata)
**Status:** ✅ `Verified` (Snort 3.x / Kali Linux Lab)
**Description:** Detects the presence of `/bin/sh` embedded within the SMB Session Setup AndX request username field.

```bash
# Rule: Syntropy Samba Username Map Script Injection
alert tcp $EXTERNAL_NET any -> $HOME_NET 139,445 (msg:"Syntropy-Detection: Samba Username Map Script Injection"; flow:to_server,established; content:"|00|"; depth:1; content:"/bin/sh"; distance:0; metadata:service netbios-ssn; sid:1000003; rev:1;)
