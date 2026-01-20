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

### Operational Archives

| Target | OS | Difficulty | Key Mental Model | Detection Value |
| :--- | :---: | :---: | :--- | :--- |
| **[Nibbles](01-HackTheBox/Linux/Nibbles/Report.md)** | 🐧 | `Easy` | *The False Failure Paradox* | FIM for Admin Scripts |

---

### Detection Engineering
We believe that an exploit without a remediation plan is just vandalism. Refer to the `/02-Detection-Engineering` folder for consolidated Sigma and Snort rules derived from these operations.

---
*© Syntropy Security. For Educational and Defensive Research Purposes Only.*
