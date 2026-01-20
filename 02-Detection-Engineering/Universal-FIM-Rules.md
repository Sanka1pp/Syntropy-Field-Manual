# Universal File Integrity Monitoring (FIM) Rules

###  Concept: The Administrator's Fallacy
Attackers often abuse writable scripts executed by root (e.g., `monitor.sh`). Standard AV often misses this because the script itself is "legitimate."

###  Sigma Rule: Writable Script Modification
**Title:** Modification of Sudo-Executed Scripts

**Status:** Experimental

**Description:** Detects changes to scripts that are commonly configured in `/etc/sudoers`.

```
logsource:
    category: file_change
    product: linux
detection:
    selection:
        TargetFilename|endswith:
            - '/monitor.sh'
            - '/backup.sh'
            - '/cleanup.sh'
    condition: selection
level: high
```

###  Snort / Suricata Rule (Network)
**Description:** Detects the specific "My Image" plugin upload attempt in Nibbleblog.

```
alert tcp any any -> $HOME_NET 80 (msg:"Syntropy-Detection: Nibbleblog CVE-2015-6967 Upload Attempt"; content:"/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image"; http_uri; flow:to_server,established; sid:1000001; rev:1;)
```
