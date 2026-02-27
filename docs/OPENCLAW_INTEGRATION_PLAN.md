# OpenClaw Integration Plan for Leash

Status: Draft implementation plan (ready for build-out)
Date: 2026-02-27

## Objective
Allow an operator to hand an agent a **single repo link** and have it:
1. install/build Leash,
2. generate sane defaults,
3. register service + health checks,
4. wire alerts into OpenClaw with low-cost triage routing,
5. start and verify end-to-end.

---

## Non-Negotiable Principle
During tuning/early rollout, **all high-frequency alert triage must use a cheap model** (GLM class) to avoid burning premium tokens.

- Cheap model (default): `glm` / `zai/glm-4.7`
- Premium model escalation only for:
  - persistent red severity incidents,
  - unclear root cause after cheap model triage,
  - public/customer-facing writeups.

---

## One-Link Bootstrap UX (target)

Input to agent:
- Repo URL (e.g. `https://github.com/meridianhouse/leash`)
- Optional overrides:
  - install path
  - monitored agent list
  - alert channels
  - response mode (`alert_only` vs `sigstop`)

Target command flow:
1. `openclaw` agent receives URL
2. runs `scripts/openclaw_integrate.sh <repo_url>`
3. prints `INTEGRATION_OK` with verification summary

---

## Integration Components

### 1) Installer/Bootstrap Script
Create `scripts/openclaw_integrate.sh`:
- clone or pull repo
- check Rust toolchain
- build release binary
- install binary into `~/.local/bin` or `/usr/local/bin`
- run `leash init` if config missing
- write/merge `~/.config/leash/config.yaml`

### 2) Service Registration
- install/enable `leash.service` (systemd user or system scope)
- start service
- verify: `leash status`

### 3) OpenClaw Hooks
Add OpenClaw scripts/cron jobs:
- `check-edr-alerts.py` (already in workspace pattern)
- cron: frequent health check (5–15 min)
- cron: daily summary digest

### 4) Alert Triage Routing (Cost-Controlled)
- First-pass parser/triage job uses `glm`
- Emits structured severity:
  - `green`: log only
  - `yellow`: summary only
  - `orange`: notify + recommend action
  - `red`: immediate notify + optional escalation
- Escalate to premium model only when severity and ambiguity justify it

### 5) Verification Gate
Integration script must verify all:
- Leash binary exists and executable
- service active
- test event generated
- OpenClaw saw test alert
- cron jobs present and scheduled

Output contract:
```text
INTEGRATION_OK
- leash_version: ...
- service: active
- alert_path: ...
- cron_jobs: [...]
- triage_model: glm
```

---

## Phased Rollout

### Phase A (MVP)
- manual repo clone + build + service
- JSON log alerts only
- OpenClaw cron parser on cheap model

### Phase B
- one-command bootstrap from repo link
- channel notifications (Telegram/Discord)
- auto-created cron jobs

### Phase C
- optional response actions (`sigstop`) with guardrails
- richer dashboards + trend scoring

---

## Security & Reliability Notes
- never hardcode tokens in scripts
- use env/secrets store only
- default response mode stays `alert_only`
- keep noisy datasets enabled but cheap-model triaged
- maintain suppression lists for known-benign repetitive events

---

## Current Testing Outcome (today)
- Installed required build toolchain on 4090 (`cargo`, `rustc`, `rustfmt`, `rust-clippy`, `pkg-config`, `libssl-dev`).
- Attempted strict technical gate (`cargo fmt`, `cargo clippy -D warnings`).
- Build currently blocked by source compatibility/lint failures (let-chain stability usage + strict clippy/test type mismatches), requiring code cleanup before release gate can pass.

---

## Next Implementation Tasks
1. Add `scripts/openclaw_integrate.sh` (real bootstrap)
2. Add `scripts/openclaw_verify.sh` (health/verification contract)
3. Patch Leash codebase to pass fmt/clippy/tests on target Rust toolchain
4. Add OpenClaw cron template file for automated registration
5. Add docs section: "Cheap-model alert triage default"
