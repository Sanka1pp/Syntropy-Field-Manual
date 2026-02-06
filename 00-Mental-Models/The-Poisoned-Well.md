# Mental Model: The Poisoned Well (Supply Chain Compromise)

> **Syntropy Intel:** 🪟 [Case Study: Knife (Linux)](../01-HackTheBox/Linux/Knife/Report.md) | 🛡️ [Detection Logic: PHP Backdoor](../02-Detection-Engineering/PHP-Backdoor-UserAgentt.md)

### Definition
**The Poisoned Well** refers to a **Supply Chain Attack** where the upstream source code or update mechanism of a trusted software dependency is compromised. The target organization does not need to make a configuration error; they simply install "trusted" software that contains hidden malice.

### Operational Context
In the **Knife** operation, the target ran **PHP 8.1.0-dev**.
* **The Event:** In March 2021, attackers compromised the official PHP Git server and injected a backdoor disguised as a "typo fix."
* **The Mechanism:** The code looked for the HTTP header `User-Agentt` (double 't'). If present, it executed the content.
* **The Lesson:** "Dev" and "Nightly" builds often lack the rigorous signing and verification processes of "Stable" releases.

### Defense Depth
* **Binaries, Not Source:** Production systems should run signed binaries from trusted repositories, not raw source code or development builds.
* **Egress Filtering:** A server suddenly initiating a reverse shell connection to an unknown IP is the universal indicator of compromise, regardless of the exploit used.
* **SBOM (Software Bill of Materials):** You cannot defend what you don't know you are running. maintain an inventory of all software versions.

---
*Syntropy Security Tradecraft Archives*
