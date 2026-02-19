# Leash

Put your AI on a short leash.

Leash is a Rust-based Linux visibility tool for monitoring what AI agents (Claude, Codex, GPT tooling) do on your machine. It tracks process behavior, sensitive file access, file integrity changes, and network egress, then emits structured alerts.

- Website: https://leash.meridianhouse.tech
- GitHub: https://github.com/meridianhouse/leash

## Features

- Process monitoring via `/proc` (v1 collector)
- Process tree and sensitive file access heuristics
- File Integrity Monitoring (FIM) with `notify` + `blake3`
- Network egress correlation from `/proc/net/tcp` + `/proc/<pid>/fd`
- MITRE ATT&CK/ATLAS-style tagging
- Alert fan-out: local JSONL log + optional webhooks
- Response engine with opt-in `SIGSTOP`
- Async subsystem fan-out with `tokio::sync::broadcast`

## Install

```bash
cargo build --release
```

Binary path:

```bash
./target/release/leash
```

## Usage

```bash
leash start
leash watch
leash status
leash stop
```

Machine-readable mode:

```bash
leash --json status
leash --json watch
```

Custom config path:

```bash
leash --config /path/to/config.yaml start
```

## Configuration

Default location:

```text
~/.config/leash/config.yaml
```

Example config is provided at `config/config.yaml`.

## systemd

A sample unit is provided at `leash.service`.

## Current Scope

This is Phase 1/2 baseline functionality using `/proc` and userland watchers.
Future phases can replace parts of collection with eBPF for lower-latency kernel-level telemetry.
