| 📡 **[Mission Report](../01-HackTheBox/Windows/Flight/Report.md)** | 🛡️ **[Detection Rules](../02-Detection-Engineering/Detection-Flight-Artifacts.md)** |

# Syntropy Mental Models | [54nK4lP3x3]

## 🧠 The Watering Hole Principle

> *"You do not need to hunt the prey if you control the water they drink."*

### 1. The Concept
In penetration testing, we often look for active exploits (RCE, SQLi). However, **Passive Dominance** is often superior.

A **Watering Hole** in a Windows domain is any location where multiple users congregate or access resources. This is typically a **Writable SMB Share**.

### 2. The Flight Case Study
In the [Flight Operation](../01-HackTheBox/Windows/Flight/Report.md), we gained access to a share named `Shared`. It contained no sensitive files.
* **Novice View:** "This share is empty. Dead end."
* **Syntropy View:** "This share is writable. Who else comes here?"

By placing a passive trigger (`desktop.ini` or `.scf`), we turned the share into a trap. We didn't attack `C.Bum` directly; we waited for `C.Bum` to come to the water.

### 3. The Application
When you find a Writable Share, run the **Actor Analysis**:

| Actor | Typical Impact | Attack Vector |
| :--- | :--- | :--- |
| **Human** | Hash Capture | LNK / SCF / desktop.ini |
| **Web Server** | Forced Auth | Webshell Upload |
| **Service** | Priv Esc | DLL Hijacking |
| **Admin** | Domain Compromise | Malicious Configs |

**Rule:** Writable access is not the vulnerability. The *traffic* to that writable location is the vulnerability.
