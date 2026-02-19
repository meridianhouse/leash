# Security Audit #4 - Leash

Date: 2026-02-19
Scope: Source re-review of `src/`, `scripts/`, and runtime/service artifacts in this repository.

## Summary Table

| # | Title | Severity | File | Impact |
|---|---|---|---|---|
| 1 | Stop-password authentication can be bypassed with raw signals | HIGH | `src/app.rs:150` | Any same-UID local process can stop Leash without knowing the configured stop password |
| 2 | Stats file in `/tmp` is vulnerable to spoofing and symlink file clobber | HIGH | `src/stats.rs:9` | Local attackers can forge status output or redirect writes to arbitrary files writable by the Leash user |
| 3 | JSON alert log writer follows symlinks and does not enforce secure file permissions | MEDIUM | `src/alerts.rs:423` | If the log path is attacker-influenced, alerts can be redirected/appended to unintended files; logged telemetry may be over-exposed |
| 4 | External digest tools are executed via PATH lookup (command hijack risk) | MEDIUM | `src/watchdog.rs:157` | Running Leash with an attacker-controlled `PATH` can execute attacker binaries as the Leash user (or root if misconfigured) |
| 5 | Install script uses unauthenticated remote execution pattern (`curl | bash`) and unpinned source | HIGH | `scripts/install.sh:3` | Compromise of distribution channel or repo state leads to arbitrary code execution during install |
| 6 | systemd unit weakens hardening (`NoNewPrivileges=false`) while granting high capabilities | MEDIUM | `leash.service:18` | Increases blast radius if Leash or a dependency is compromised at runtime |

## Finding 1: Stop-password authentication can be bypassed with raw signals
- Severity: HIGH
- File: `src/app.rs:150`
- Description
  - The stop-password gate relies on a two-signal handshake (`SIGUSR1` then `SIGTERM`) tracked by global atomics.
  - `SIGUSR1` unconditionally sets `AUTH_STOP_REQUESTED` (`src/app.rs:150-152`).
  - `SIGTERM` accepts shutdown if that flag is set (`src/app.rs:154-160`).
  - Any same-UID process can send these signals directly using `kill(2)`, bypassing CLI password verification in `stop_agent`.
- PoC
  1. Configure `auth.stop_password_hash` in Leash config and start Leash.
  2. From another shell as the same user:
     - `kill -USR1 <leash_pid>`
     - `kill -TERM <leash_pid>`
  3. Leash exits without the attacker knowing the password.
- Fix
  - Remove signal-based auth bypass state for stop password.
  - Use a protected IPC control channel (Unix socket in `0700` directory, `SO_PEERCRED` check) and verify password in-process before shutdown.
  - If signals must remain, require an unforgeable token exchange (not process-global atomics).

## Finding 2: Stats file in `/tmp` is vulnerable to spoofing and symlink file clobber
- Severity: HIGH
- File: `src/stats.rs:9`
- Description
  - Stats are written to a predictable world-writable location: `const STATS_FILE: &str = "/tmp/leash-stats.json"`.
  - Writes use `std::fs::write` (`src/stats.rs:61`) with no ownership/type/symlink checks and no restrictive mode.
  - Reads use `read_to_string` from the same path (`src/stats.rs:55`) with no trust validation.
  - This enables local spoofing of status output and symlink redirection attacks against writable target files.
- PoC
  1. As attacker (same host), before Leash runs:
     - `ln -s ~/.bashrc /tmp/leash-stats.json` (or another writable target)
  2. Run Leash and trigger events so snapshot writes occur.
  3. Target file is overwritten with JSON snapshot content.
  4. Alternatively, write forged JSON to `/tmp/leash-stats.json`; `leash status --json` reports attacker-controlled values.
- Fix
  - Move stats file under user state dir (e.g., `~/.local/state/leash/stats.json`).
  - Open with secure flags: `O_CREAT|O_EXCL` on first create, `O_NOFOLLOW`, and enforce `0600`.
  - Validate owner/regular-file before read/write.

## Finding 3: JSON alert log writer follows symlinks and does not enforce secure file permissions
- Severity: MEDIUM
- File: `src/alerts.rs:423`
- Description
  - `write_local_log` uses `OpenOptions::new().create(true).append(true).open(path)` without `O_NOFOLLOW`, ownership checks, or explicit permission mode.
  - Parent directory is auto-created (`src/alerts.rs:419-421`) but no permission hardening is applied.
  - If config/log path is altered (or points into unsafe locations), log output can be redirected to unintended files. Alert payloads can contain sensitive command/path metadata.
- PoC
  1. Configure `alerts.json_log.path` to a symlink-controlled path.
  2. Point that symlink to a file writable by Leash user.
  3. Trigger alerts; Leash appends JSON lines to the symlink target.
- Fix
  - Resolve/validate target path and directory ownership.
  - Open with `O_NOFOLLOW` and reject non-regular files.
  - Enforce `0600` file mode and `0700` directory mode.

## Finding 4: External digest tools are executed via PATH lookup (command hijack risk)
- Severity: MEDIUM
- File: `src/watchdog.rs:157`
- Description
  - Integrity hashing shells out to `sha256sum` / `shasum` via `Command::new("sha256sum")` and `Command::new("shasum")`.
  - These are resolved through `PATH`, so attacker-controlled `PATH` can substitute malicious binaries.
  - Impact depends on launch context; risk is significant in privileged or loosely controlled service environments.
- PoC
  1. Create malicious executable `./sha256sum`.
  2. Launch Leash with `PATH=.:$PATH`.
  3. Watchdog executes attacker binary during integrity checks.
- Fix
  - Avoid external tools; compute SHA-256 in-process using a Rust crypto crate.
  - If external tools remain, invoke absolute trusted paths and sanitize environment (`PATH`, locale, etc.).

## Finding 5: Install script uses unauthenticated remote execution pattern (`curl | bash`) and unpinned source
- Severity: HIGH
- File: `scripts/install.sh:3`
- Description
  - Script is intended to be piped directly to shell from the network.
  - It also installs Rust via another `curl | sh` flow (`scripts/install.sh:12`) and clones the default branch head from GitHub without commit/tag pinning (`scripts/install.sh:25`).
  - This creates a high-impact supply-chain execution path if website/repo/channel is compromised.
- PoC
  1. User runs advertised install command.
  2. Any compromise of served script content, upstream rustup bootstrap path, or repo head causes immediate arbitrary code execution in installer context.
- Fix
  - Publish signed release artifacts and checksums/signatures.
  - Pin installer to immutable versioned tarballs or commit SHAs.
  - Replace pipe-to-shell guidance with download + verify + execute flow.

## Finding 6: systemd unit weakens hardening (`NoNewPrivileges=false`) while granting high capabilities
- Severity: MEDIUM
- File: `leash.service:18`
- Description
  - Service hardening section sets `NoNewPrivileges=false`, explicitly allowing privilege transitions.
  - Unit also grants elevated capabilities (`CAP_SYS_PTRACE`, `CAP_KILL`, `CAP_NET_ADMIN`) and ambient capabilities (`leash.service:19-20`).
  - Combined posture increases post-compromise impact and contradicts least-privilege hardening goals.
- PoC
  1. Run Leash via provided service unit.
  2. If Leash/dependency is compromised, process can leverage broader capability set and permissive privilege transition behavior.
- Fix
  - Set `NoNewPrivileges=true`.
  - Remove unnecessary capabilities; keep minimal required set only.
  - Consider additional hardening directives: `RestrictAddressFamilies=`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`, `PrivateDevices=true`, tighter `SystemCallFilter=` where practical.
