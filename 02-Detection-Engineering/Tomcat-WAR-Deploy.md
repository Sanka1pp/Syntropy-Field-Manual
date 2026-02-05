# Detection Engineering: Tomcat WAR Deployment

> **Syntropy Intel:** 🪟 [Case Study: Jerry (Windows)](../01-HackTheBox/Windows/Jerry/Report.md) | 🧠 [Mental Model: The Exposed Console](../00-Mental-Models/The-Exposed-Console.md)

## 1. Executive Summary
**Attack Vector:** Malicious Web Archive (.war) Deployment
**Severity:** Critical (Remote Code Execution)
**Status:** ✅ Verified

Attackers with access to the Tomcat Manager App can upload a malicious `.war` file containing a JSP web shell. The server automatically unpacks and executes this payload.

---

## 2. Network Defense (Snort 3)
**Logic:** Detects the HTTP PUT/POST request used to upload a file to the `/manager` endpoint.

To replicate this detection, create the following files:

### A. The Rule File (`tomcat.rules`)
```bash
# Save as: tomcat.rules
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Syntropy-Detection: Tomcat Manager WAR Upload"; flow:to_server,established; content:"POST"; http_method; content:"/manager/html/upload"; http_uri; content:".war"; fast_pattern; metadata:service http; sid:1000005; rev:1;)
```

### B. The Configuration (`minimal.lua`)
```lua
-- Save as: minimal.lua
stream = { }
stream_tcp = { }
ips = { enable_builtin_rules = true }
```

### C. Execution
```bash
sudo snort -c minimal.lua -R tomcat.rules -i tun0 -A alert_fast -k none
```

---

## 3. Endpoint Defense (Sigma)
**Logic:** A Java web server process (`tomcat.exe`, `java.exe`) should rarely spawn a command shell (`cmd.exe`, `powershell.exe`). This is a high-fidelity indicator of a webshell.

```yaml
title: Web Shell Spawned by Tomcat
id: syntropy-windows-tomcat-webshell
status: experimental
description: Detects a command shell spawned by the Apache Tomcat service.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\tomcat.exe'
            - '\tomcat7.exe'
            - '\tomcat8.exe'
            - '\java.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1505.003
```

---
*Syntropy Security Field Manual*
