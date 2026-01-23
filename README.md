# 🛡️ Syntropy Field Manual

> **"Defensive Resilience through Offensive Insight."**

### Manifesto
This repository documents the operational tradecraft of **Syntropy Security**. Unlike standard CTF write-ups, these logs focus on the *strategic decision-making* behind the exploit chains ("Mental Models") and the *detection engineering* required to stop them.

**Operator:** `54nK4IP3x3` | **Status:** Active

---

### The Syntropy Protocol
Every engagement documented here follows the **Reporter Protocol**, emphasizing three layers of value:
1.  **Tactical Execution:** Frictionless, reproducible exploit paths.
2.  **Strategic Analysis:** Documenting the *Mental Models* (the "Why") behind the hack.
3.  **Detection Engineering:** Translating attacks into Blue Team logic (FIM, SIEM, Snort).


### 📂 Operational Archives

| Target | Class | Difficulty | 🧠 Strategic Insight (Mental Model) | 🛡️ Defensive Logic (Detection) |
| :--- | :---: | :---: | :--- | :--- |
| **[Nibbles](https://github.com/Sanka1pp/Syntropy-Field-Manual/blob/main/01-HackTheBox/Linux/Nibbles/Hack%20The%20Box%20(HTB)%20Nibbles%20Machine%20Writeup%20%5B54nK4l%202ed8aeddd8dc80f99963c9bc0e180d93.md)** | 🐧 | `Easy` | [The False Failure Paradox](00-Mental-Models/The-False-Failure-Paradox.md) | [Universal FIM Rules](02-Detection-Engineering/Universal-FIM-Rules.md) |
| **[Legacy](01-HackTheBox/Windows/Legacy/Report.md)** | 🪟 | `Easy` | [Protocol Decay](00-Mental-Models/Protocol-Decay.md) | [MS08-067 Signatures](02-Detection-Engineering/MS08-067-Rules.md) |
| **[Lame](01-HackTheBox/Linux/Lame/Report.md)** | 🐧 | `Easy` | [The Legacy Bridge](00-Mental-Models/The-Legacy-Bridge.md) | [Samba Map Script](02-Detection-Engineering/Samba-Map-Script.md) |

---

### Detection Engineering
We believe that an exploit without a remediation plan is just vandalism. Refer to the `/02-Detection-Engineering` folder for consolidated Sigma and Snort rules derived from these operations.

---
*© Syntropy Security. For Educational and Defensive Research Purposes Only.*
