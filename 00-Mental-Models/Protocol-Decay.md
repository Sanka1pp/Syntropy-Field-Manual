# Mental Model: Protocol Decay

### Definition
**Protocol Decay** is the inevitable degradation of security in legacy communication standards over time. Unlike software bugs, which are implementation errors, protocol decay occurs when the design of the protocol itself (e.g., SMBv1, Telnet, SSLv3) becomes fundamentally incompatible with modern threat models.

### Operational Context
In the *Legacy* operation, the target was vulnerable not because of a misconfiguration, but because it spoke a dead language (SMBv1).
* **The Operator's Advantage:** We did not need to guess credentials. We attacked the *grammar* of the protocol itself (MS08-067).
* **The Defender's Blind Spot:** Many organizations assume that "Internal Only" means "Safe." Protocol decay ignores firewalls; if the packet can reach the service, the service is compromised.

### Defensive Application
You cannot patch a decayed protocol; you must **deprecate** it.
* **Audit:** Identify all services negotiating SMBv1, TLS 1.0, or NTLMv1.
* **Segregate:** If a legacy machine *must* exist (e.g., for manufacturing hardware), it must be air-gapped or micro-segmented into a "Zombie Vlan" with no internet access and strict ACLs.

### Case Study: HTB Legacy
In the Legacy operation, the target (Windows XP) exposed SMBv1.

* **Signal:** Nmap revealed smb-vuln-ms08-067 and smb-vuln-ms17-010.

* **Reality:** The vulnerability allowed us to corrupt the kernel memory via a malformed RPC request.

* **Lesson:** The firewall allowed Port 445 traffic, assuming it was "Business Valid." Because the protocol was decayed, the "Valid" traffic carried a lethal payload.

---
*Syntropy Security Tradecraft Archives*
