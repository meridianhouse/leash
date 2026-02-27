# Leash

<p align="center">
  <img src="site/leash-logo-github.png" alt="Leash logo" width="140" />
</p>

[![CI](https://img.shields.io/badge/CI-placeholder-lightgrey)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![crates.io](https://img.shields.io/badge/crates.io-placeholder-lightgrey)](#)

**Put your AI on a short leash.**

Leash is an open-source AI agent visibility tool. It monitors what AI agents (Claude Code, Codex, Cursor, GPT, etc.) actually do on your machine — every process spawned, file touched, network connection made, and credential accessed.
Current footprint: **8,270 lines of Rust** and **212 tests**.

> ⚠️ **Early release disclaimer:** Leash is early-stage software. It is designed to improve visibility and reduce risk, but it is **not foolproof** and should not be treated as a guaranteed prevention layer.
> 
> It has not yet been validated against every real-world adversary tradecraft path in live production attack scenarios. Use defense-in-depth and treat Leash as one layer in your security stack.

> You gave an AI agent access to your terminal. Do you know what it's doing?

## Why Leash?

AI coding agents run commands, read files, make network connections, and access credentials — all autonomously. Most people have **zero visibility** into what these agents actually do at the OS level.

Leash fixes that.

- 🔍 **Process Tree Tracking** — See every process an AI agent spawns, and what those processes spawn
- 📁 **File Integrity Monitoring** — Know when files are created, modified, or deleted, with cryptographic verification
- 🌐 **Network Egress Monitoring** — Track every outbound connection, per-process
- 🔑 **Credential Access Detection** — Alerts when agents touch SSH keys, configs, secrets
- 🛡️ **Self-Integrity Monitoring** — Detects tampering with the Leash binary and config
- 🗺️ **MITRE ATT&CK Mapping** — Every detection tagged with relevant ATT&CK/ATLAS techniques
- 🚨 **Real-time Alerts** — Slack, Discord, Telegram, or JSON log
- ⚡ **Single Binary** — Drop it in, run it. No runtime dependencies.

## Quick Start

### Prerequisites (Linux)

- Rust toolchain (`cargo`, `rustc`) via `rustup`
- C toolchain/linker (`cc`/`gcc`)
- `pkg-config`
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu)

Ubuntu/Debian example:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
# then install rustup from https://rustup.rs
```

```bash
# Install from source
cargo install --path .

# Generate default config
leash init

# Start watching (foreground, live output)
leash watch

# Or run as a daemon
leash start

# Check status
leash status

# Stop
leash stop
```

## Secure Installer Usage

Avoid `curl | bash`. Use download-then-verify-then-execute:

```bash
curl -fsSLo /tmp/leash-install.sh https://meridianhouse.tech/leash/install.sh
# Verify the installer checksum from a trusted release note before running:
sha256sum /tmp/leash-install.sh
bash /tmp/leash-install.sh
```

## Docker

Run Leash in a container with host namespace visibility:

```bash
docker compose up --build -d
docker compose logs -f leash
```

Notes:
- `pid: host` and `network_mode: host` are required for host-level process/network visibility.
- `LEASH_PROC_ROOT=/host/proc` makes Leash read host `/proc` data from a bind mount.
- Without host namespace settings, network telemetry is limited to the container namespace.

## What It Looks Like

```
$ leash watch
Leash v0.1.0 — AI Agent Visibility
Monitoring: claude, codex, cursor, gptools, aider, cline

🟢 [process_spawn] claude(pid:4521) → bash(pid:4522)
🟢 [process_spawn] bash(pid:4522) → git(pid:4523) args: status
🟡 [file_access]   bash(pid:4522) read ~/.ssh/config
🟠 [credential]    claude(pid:4521) accessed vault: ~/.config/secrets/
🟢 [network]       node(pid:4525) → api.anthropic.com:443
🔴 [file_modify]   bash(pid:4522) modified /etc/crontab
    ╰─ MITRE: T1053.003 (Scheduled Task/Job: Cron)
```

## Configuration

Config lives at `~/.config/leash/config.yaml`:

```yaml
# AI tools to monitor (process names)
monitored_agents:
  - claude
  - codex
  - cursor
  - gptools
  - aider
  - cline
  - copilot-agent

# Sensitive paths to watch for access
sensitive_paths:
  - ~/.ssh
  - ~/.config
  - ~/.gnupg
  - /etc/shadow
  - /etc/sudoers
  - /etc/crontab

# File integrity monitoring
fim_paths:
  - /etc
  - ~/.ssh
  - ~/.config/leash

# Response actions (opt-in, disabled by default)
response:
  enabled: false
  action: sigstop  # sigstop | alert_only

# Alert integrations
alerts:
  slack:
    enabled: false
    webhook_url: ""
  discord:
    enabled: false
    webhook_url: ""
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
  json_log:
    enabled: true
    path: "~/.local/state/leash/alerts.jsonl"
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Leash Daemon                       │
├────────────────┬──────────┬──────────┬──────────┬──────┤
│ Kernel Monitor │ Process  │   FIM    │ Network  │Watch-│
│ eBPF / CN_PROC │ Collector│ Monitor  │ Egress   │dog   │
├────────────────┴──────────┴──────────┴──────────┴──────┤
│                  Event Bus (broadcast)                  │
├──────────┬──────────┬───────────────────────────────────┤
│  MITRE   │ Response │    Alert Dispatcher               │
│  Mapper  │ Engine   │    Slack/Discord/Telegram/JSON    │
│          │(opt-in)  │                                   │
└──────────┴──────────┴───────────────────────────────────┘
```

Leash uses an async event bus architecture built on Tokio. Each subsystem runs as an independent task, communicating through a broadcast channel. This means:

- **Zero coupling** between detection and response
- **Pluggable alerting** — add new integrations without touching detection logic
- **Non-blocking** — a slow webhook doesn't delay process monitoring

### Detection Approach

**v0.1 (current):** Polls `/proc` filesystem for process and network data. Uses the `notify` crate for real-time file system events with `blake3` integrity hashing.

**v0.2:** Event-driven kernel monitoring is enabled. `--ebpf` attempts tracepoint-based eBPF hooks through `aya` first and falls back to Linux proc connector (`CN_PROC`) if unavailable. `/proc` polling remains for supplemental enrichment and egress correlation.

## MITRE ATT&CK Coverage

Leash maps detections to MITRE ATT&CK and [ATLAS](https://atlas.mitre.org/) (AI-specific) techniques:

| Detection | Technique | ID |
|-----------|-----------|-----|
| Process spawn chain | Execution | T1059 |
| Script execution | Command & Scripting Interpreter | T1059.004 |
| Credential file access | Credential Access | T1552.001 |
| SSH key access | Unsecured Credentials | T1552.004 |
| Cron modification | Scheduled Task/Job | T1053.003 |
| Sensitive file read | Data from Local System | T1005 |
| Outbound connection | Exfiltration Over C2 | T1041 |
| Config file modification | System Configuration | T1543 |

## 25 Detection Rules

Leash currently ships with 25 curated detection rules spanning process, credential access, persistence, and egress behaviors.

| Category | Rule Count | Example Rules |
|----------|------------|---------------|
| Process and execution abuse | 8 | `curl_pipe_shell`, `osascript_tmp_execution`, `fileless_pipeline_python` |
| Credential and secret access | 6 | `ai_agent_credential_access`, `kube_config_access`, `ssh_authorized_keys_modify` |
| Persistence and defense evasion | 5 | `cron_persistence`, `launchd_persistence`, `gatekeeper_bypass` |
| Supply chain and install-time abuse | 3 | `npm_postinstall_shell`, `package_install_external_ip`, `pyinstaller_network_child` |
| Network and exfiltration signals | 3 | `raw_ip_download`, `tor_egress_port`, `known_exfil_service` |

See `DETECTIONS.md` for full rule-level mappings and references.

## systemd

```bash
# Copy the service file
sudo cp leash.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable leash
sudo systemctl start leash
```

## Building from Source

```bash
git clone https://github.com/meridianhouse/leash.git
cd leash
cargo build --release
# Binary at ./target/release/leash (~6 MB stripped)
```

Requirements: Rust 1.75+, Linux (x86_64 or aarch64)

## Roadmap

- [x] v0.1 — Core visibility (process, file, network monitoring)
- [x] v0.2 — eBPF kernel hooks with proc connector fallback (event-driven monitoring)
- [ ] v0.2 — LOLRMM integration (flag known abused RMM tools via [lolrmm.io](https://lolrmm.io) dataset)
- [ ] v0.2 — LOLDrivers integration (detect vulnerable/malicious drivers via [loldrivers.io](https://www.loldrivers.io) dataset)
- [x] v0.2 — GTFOBins integration (flag risky Unix binary abuse capabilities via [gtfobins.github.io](https://gtfobins.github.io))
- [x] v0.2 — LOT Tunnels integration (flag living-off-tunnels tooling via [lottunnels.github.io](https://lottunnels.github.io))
- [x] v0.2 — LOLC2 integration (flag C2 frameworks abusing legitimate services via [lolc2.github.io](https://lolc2.github.io))
- [ ] v0.3 — Anti-tamper watchdog with mutual process monitoring
- [ ] v0.4 — Web dashboard for historical analysis
- [ ] v1.0 — macOS support

## Philosophy

Leash is **observation-first**. It watches and reports. Response actions (like SIGSTOP) exist but are opt-in and disabled by default. We believe visibility is more valuable than automated blocking — you should know what's happening before you decide what to do about it.

## Security

- Security review 1: architecture and threat-model review
- Security review 2: detection-rule evasion review
- Security review 3: alert sink and secrets-handling review
- Self-integrity monitoring continuously checks binary and config hash drift and raises tamper alerts
- Threat model: see `THREAT_MODEL.md` for in-scope/out-of-scope + assumptions

## License

MIT — because security tools should be free.

## Links

- 🌐 [meridianhouse.tech/leash](https://meridianhouse.tech/leash)
- 🐙 [GitHub](https://github.com/meridianhouse/leash)
- 🏢 [Meridian House](https://meridianhouse.tech)

---

*Built by security professionals who got tired of not knowing what their AI agents were doing.*
