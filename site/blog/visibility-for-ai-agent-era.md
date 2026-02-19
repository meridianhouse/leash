# Leash: Visibility for the AI Agent Era

*By the Meridian House team — February 2026*

I've spent years in endpoint security. Managing EDR deployments across thousands of endpoints. Watching threats, responding to incidents, building detection rules.

When AI coding agents started running on my machine — Claude Code, Codex, Cursor — I realized something uncomfortable: **I had zero visibility into what they were actually doing.**

They had access to my files. My terminal. My credentials. And I had no tooling to see what they touched.

## The Gap

The current security landscape has a blind spot:

- **Enterprise EDR** (CrowdStrike, SentinelOne) monitors traditional threats but doesn't understand AI agent process patterns
- **LLM Guardrails** (Lakera, Langfuse) monitor API inputs and outputs but are completely blind to OS-level activity
- **Nobody** is monitoring what AI agents do at the system level

That's a problem. AI agents spawn processes, read files, make network connections, and access credentials — all autonomously. And most people running them have zero visibility into any of it.

## Enter Leash

Leash is an open-source AI agent visibility tool written in Rust. It monitors what AI agents do on your Linux machine in real-time:

- **Process Tree Tracking** — See every process an agent spawns, and what those child processes do. Full ancestry chains like `claude → bash → curl → https://example.com`
- **File Integrity Monitoring** — Cryptographic (blake3) monitoring of sensitive files. Know when SSH keys, configs, or system files are touched.
- **Network Egress Monitoring** — Per-process outbound connection tracking. See exactly where your data is going.
- **Credential Access Detection** — Alerts when agents access SSH keys, AWS credentials, `.npmrc` tokens, or secrets vaults.
- **MITRE ATT&CK Mapping** — Every detection tagged with relevant ATT&CK and ATLAS techniques. Speak the language security teams already know.

## Observation First

Leash is observation-first by design. It watches and reports. Response actions (like SIGSTOP) exist but are opt-in and disabled by default.

Why? Because visibility is more valuable than automated blocking. You need to understand what's happening before you can decide what to do about it. And most of the time, your AI agents are doing exactly what you asked — you just couldn't see it before.

## Technical Details

- Written in Rust — 3,300+ lines, single 6MB binary
- Async event bus architecture on Tokio
- Alerts to Slack, Discord, Telegram, or JSON log
- Rate limiting and severity filtering built in
- 12 unit tests, clippy-clean, CI via GitHub Actions
- v0.1 uses `/proc` polling; v0.2 will add eBPF via `aya` for kernel-level monitoring

## Get Started

```bash
git clone https://github.com/meridianhouse/leash.git
cd leash && cargo build --release
./target/release/leash init
./target/release/leash watch
```

That's it. You'll immediately see what's running on your machine.

## What's Next

- **eBPF kernel hooks** for zero-overhead monitoring
- **Anti-tamper watchdog** for production deployments  
- **macOS support**
- **Web dashboard** for historical analysis

## Why Open Source

Security tools should be free. The AI agent era is just beginning, and everyone running agents on their machine deserves to know what those agents are doing. We're releasing Leash under the MIT license because we believe visibility is a right, not a premium feature.

---

*Leash is built by Meridian House. Star us on [GitHub](https://github.com/meridianhouse/leash).*
