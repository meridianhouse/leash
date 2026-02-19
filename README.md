# 🐕 Leash

**Put your AI on a short leash.**

Leash is an open-source AI agent visibility tool. It monitors what AI agents (Claude Code, Codex, Cursor, GPT, etc.) actually do on your machine — every process spawned, file touched, network connection made, and credential accessed.

> You gave an AI agent access to your terminal. Do you know what it's doing?

## Why Leash?

AI coding agents run commands, read files, make network connections, and access credentials — all autonomously. Most people have **zero visibility** into what these agents actually do at the OS level.

Leash fixes that.

- 🔍 **Process Tree Tracking** — See every process an AI agent spawns, and what those processes spawn
- 📁 **File Integrity Monitoring** — Know when files are created, modified, or deleted, with cryptographic verification
- 🌐 **Network Egress Monitoring** — Track every outbound connection, per-process
- 🔑 **Credential Access Detection** — Alerts when agents touch SSH keys, configs, secrets
- 🗺️ **MITRE ATT&CK Mapping** — Every detection tagged with relevant ATT&CK/ATLAS techniques
- 🚨 **Real-time Alerts** — Slack, Discord, Telegram, or JSON log
- ⚡ **Single Binary** — Drop it in, run it. No runtime dependencies.

## Quick Start

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

## What It Looks Like

```
$ leash watch
🐕 Leash v0.1.0 — AI Agent Visibility
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
┌─────────────────────────────────────────┐
│              Leash Daemon               │
├──────────┬──────────┬──────────┬────────┤
│ Process  │   FIM    │ Network  │ Watch- │
│ Collector│ Monitor  │ Egress   │ dog    │
├──────────┴──────────┴──────────┴────────┤
│            Event Bus (broadcast)         │
├──────────┬──────────┬───────────────────┤
│  MITRE   │ Response │    Alert          │
│  Mapper  │ Engine   │    Dispatcher     │
│          │(opt-in)  │ Slack/Discord/TG  │
└──────────┴──────────┴───────────────────┘
```

Leash uses an async event bus architecture built on Tokio. Each subsystem runs as an independent task, communicating through a broadcast channel. This means:

- **Zero coupling** between detection and response
- **Pluggable alerting** — add new integrations without touching detection logic
- **Non-blocking** — a slow webhook doesn't delay process monitoring

### Detection Approach

**v0.1 (current):** Polls `/proc` filesystem for process and network data. Uses the `notify` crate for real-time file system events with `blake3` integrity hashing.

**v0.2 (planned):** eBPF-based kernel hooks via the `aya` crate for zero-overhead, event-driven monitoring. Inspired by [Tetragon](https://github.com/cilium/tetragon).

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
# Binary at ./target/release/leash (7.3 MB)
```

Requirements: Rust 1.75+, Linux (x86_64 or aarch64)

## Roadmap

- [x] v0.1 — Core visibility (process, file, network monitoring)
- [ ] v0.2 — eBPF kernel hooks (zero-overhead monitoring)
- [ ] v0.3 — Anti-tamper watchdog with mutual process monitoring
- [ ] v0.4 — Web dashboard for historical analysis
- [ ] v1.0 — macOS support

## Philosophy

Leash is **observation-first**. It watches and reports. Response actions (like SIGSTOP) exist but are opt-in and disabled by default. We believe visibility is more valuable than automated blocking — you should know what's happening before you decide what to do about it.

## License

MIT — because security tools should be free.

## Links

- 🌐 [leash.meridianhouse.tech](https://leash.meridianhouse.tech)
- 🐙 [GitHub](https://github.com/meridianhouse/leash)
- 🏢 [Meridian House](https://meridianhouse.tech)

---

*Built by security professionals who got tired of not knowing what their AI agents were doing.*
