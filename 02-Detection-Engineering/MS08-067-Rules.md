# Detection Logic: MS08-067 (NetAPI)

### Concept: The Buffer Overflow Artifact
Attackers leveraging MS08-067 must send a malformed RPC request to the Server Service. This leaves distinct network artifacts (long paths with canonicalization errors) and endpoint artifacts (svchost spawning shells).

### Network Signature (Snort/Suricata)
**Description:** Detects the specific byte sequence of the MS08-067 exploit attempt targeting the NetAPI path canonicalization vulnerability.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"Syntropy-Detection: MS08-067 Malformed Path/Shellcode"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; content:"|00 23|"; within:2; distance:36; metadata:service netbios-ssn; sid:1000002; rev:1;)
```

### Sigma Rule (Endpoint)
**Title:** Shell Spawned by Svchost (NetAPI Exploitation)
**Description:** Detects a shell (cmd.exe) spawned directly from the Server Service (svchost.exe -k netsvcs). This is the standard artifact of the MS08-067 Meterpreter payload.

```
title: Shell Spawned by Svchost (NetAPI Exploitation)
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    parent_process:
        Image|endswith: '\svchost.exe'
        CommandLine|contains: '-k netsvcs'
    child_process:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: parent_process and child_process
level: critical
```

### Case Study: HTB Legacy
**Protocol Decay** is the inevitable degradation of security in legacy communication standards over time. Unlike software bugs, which are implementation errors, protocol decay occurs when the design of the protocol itself (e.g., SMBv1, Telnet, SSLv3) becomes fundamentally incompatible with modern threat models.
