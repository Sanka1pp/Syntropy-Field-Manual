# Detection Engineering: PHP 8.1.0-dev Backdoor

> **Syntropy Intel:** 🪟 [Case Study: Knife (Linux)](../01-HackTheBox/Linux/Knife/Report.md) | 🧠 [Mental Model: The Poisoned Well](../00-Mental-Models/The-Poisoned-Well.md)

## 1. Executive Summary
**Attack Vector:** HTTP Header Injection (Supply Chain Backdoor)
**Severity:** Critical (Unauthenticated RCE)
**Status:** ✅ Verified

The "User-Agentt" backdoor affects PHP version 8.1.0-dev. It allows attackers to execute arbitrary code by sending a specially crafted HTTP header starting with the string `zerodium`.

---

## 2. Network Defense (Snort 3)
**Logic:** Detects the presence of the typo-header `User-Agentt` in HTTP traffic. This header is non-standard and highly indicative of this specific exploit attempt.

```bash
# Save as: php_backdoor.rules
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Syntropy-Detection: PHP 8.1.0-dev Backdoor Attempt"; flow:to_server,established; content:"User-Agentt|3a|"; http_header; fast_pattern; content:"zerodium"; http_header; metadata:service http; sid:1000006; rev:1;)
```

**Breakdown:**
```
content:"User-Agentt|3a|": Looks for the header name plus the colon.
content:"zerodium": The specific magic string required to trigger the backdoor.
```
