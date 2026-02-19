# Nova EDR — Rust Technical Architecture

> Research document for rewriting the Python EDR (~4400 lines) in Rust with eBPF-based monitoring, anti-tamper, and AI-agent-specific threat detection.

**Date:** 2026-02-19  
**Status:** Research / Pre-implementation

---

## Table of Contents

1. [Overview & Goals](#1-overview--goals)
2. [Rust Async Runtime & Module Structure](#2-rust-async-runtime--module-structure)
3. [eBPF Architecture with aya](#3-ebpf-architecture-with-aya)
4. [Hook Strategy: Tracepoints, kprobes, LSM](#4-hook-strategy-tracepoints-kprobes-lsm)
5. [Process Monitoring](#5-process-monitoring)
6. [File Integrity Monitoring](#6-file-integrity-monitoring)
7. [Network Egress Monitoring](#7-network-egress-monitoring)
8. [Anti-Tamper & Watchdog Pattern](#8-anti-tamper--watchdog-pattern)
9. [MITRE ATLAS Mapping (AI-Specific)](#9-mitre-atlas-mapping-ai-specific)
10. [Real-Time Alerting](#10-real-time-alerting)
11. [systemd Integration & Hardening](#11-systemd-integration--hardening)
12. [Performance Considerations](#12-performance-considerations)
13. [Packaging & Distribution](#13-packaging--distribution)
14. [Cargo Workspace Layout](#14-cargo-workspace-layout)
15. [Crate Dependency Matrix](#15-crate-dependency-matrix)
16. [Implementation Roadmap](#16-implementation-roadmap)

---

## 1. Overview & Goals

Nova EDR is a security daemon that monitors AI agent processes (Claude Code, Codex CLI, Gemini, etc.) running on Linux hosts. It replaces a Python polling-based collector with:

- **Event-driven eBPF hooks** — zero-latency process/file/network events without `/proc` polling
- **Kernel-resident protection** — eBPF programs survive `kill -9` of the userspace daemon
- **Anti-tamper watchdog** — mutual process monitoring, LSM-enforced signal blocking
- **AI-specific threat detection** — maps to MITRE ATLAS agentic AI techniques
- **Single static binary** — no Python runtime, no dynamic linking issues, drop-in deploy

### What Stays vs. What Changes

| Python Module | Rust Equivalent | Change |
|---|---|---|
| collector.py (/proc polling) | eBPF tracepoints (sched_process_exec/exit) | Event-driven → 0ms latency |
| egress_scanner.py | eBPF TC egress filter + sock hook | Kernel-level, per-process |
| scanner_skill.py | eBPF kprobes + async scanner task | Kernel hooks + parallel scans |
| killswitch.py | response module + LSM deny hooks | SIGSTOP + kernel enforcement |
| node_monitor.py | gRPC/WebSocket multi-node agent | Async distributed |
| mitre.py | mitre_atlas module | AI-specific ATLAS techniques |
| response.py | response engine with tokio channels | Async, rule-based |
| sanitizer.py | sanitizer module | Same logic, safer types |
| models.py | shared types crate | Zero-copy kernel↔user structs |
| context.py | context enrichment task | Parallel async enrichment |

---

## 2. Rust Async Runtime & Module Structure

### Runtime Choice: Tokio

Tokio is the clear choice:
- Multi-threaded work-stealing executor (handles both CPU-bound and IO-bound tasks)
- `tokio::sync::broadcast` for fan-out event distribution to multiple subscribers
- `tokio::sync::mpsc` for point-to-point module communication
- `tokio::time` for periodic tasks (heartbeat, GC, stats flush)
- Battle-tested in production security tools (HarfangLab EDR uses Tokio)

```rust
// main.rs skeleton
#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load eBPF programs (blocks on verification, then async)
    let ebpf = EbpfLoader::new().load(NOVA_EDR_BPF)?;
    
    // 2. Create broadcast bus for events
    let (event_tx, _) = broadcast::channel::<EdrEvent>(10_000);
    
    // 3. Spawn subsystems
    tokio::spawn(ebpf_reader::run(ebpf, event_tx.clone()));
    tokio::spawn(response_engine::run(event_tx.subscribe()));
    tokio::spawn(mitre_mapper::run(event_tx.subscribe()));
    tokio::spawn(alert_dispatcher::run(event_tx.subscribe()));
    tokio::spawn(watchdog::run());
    tokio::spawn(fim::run(event_tx.clone()));
    tokio::spawn(node_monitor::run(event_tx.subscribe()));
    
    // 4. Block on shutdown signal
    signal::ctrl_c().await?;
    Ok(())
}
```

### Event Bus Design

```
eBPF Ring Buffer
      │
      ▼
 [ebpf_reader]  ──broadcast──►  [response_engine]
                              ►  [mitre_mapper]
                              ►  [alert_dispatcher]
                              ►  [audit_logger]
                              ►  [node_monitor relay]
```

Use `tokio::sync::broadcast::channel(10_000)` — 10k event buffer is sufficient for burst handling. If a subscriber falls behind, it gets a `RecvError::Lagged` and logs a warning.

### Module Structure

```
nova-edr/
├── nova-edr/              # Userspace crate (binary)
│   ├── src/
│   │   ├── main.rs        # Runtime init, subsystem orchestration
│   │   ├── ebpf_loader.rs # Load/attach eBPF programs
│   │   ├── ebpf_reader.rs # Ring buffer consumer → event bus
│   │   ├── response.rs    # Automated response engine
│   │   ├── mitre.rs       # MITRE ATLAS mapping
│   │   ├── alert.rs       # Webhook/socket alerting
│   │   ├── fim.rs         # File integrity monitoring
│   │   ├── watchdog.rs    # Anti-tamper watchdog
│   │   ├── node.rs        # Multi-node relay
│   │   ├── context.rs     # Event enrichment
│   │   ├── sanitizer.rs   # Data sanitization
│   │   ├── config.rs      # YAML config parsing
│   │   └── audit.rs       # Forensic JSON logging
│   ├── build.rs           # aya-build: compiles eBPF programs
│   └── Cargo.toml
│
├── nova-edr-ebpf/         # eBPF kernel programs (no_std)
│   ├── src/
│   │   ├── main.rs        # Process exec/exit tracepoints
│   │   ├── fim.rs         # File open/write kprobes
│   │   ├── net.rs         # TC egress + socket hooks
│   │   ├── lsm.rs         # LSM hooks (signal, exec control)
│   │   └── maps.rs        # Shared map definitions
│   └── Cargo.toml
│
├── nova-edr-common/       # Shared types (kernel + userspace)
│   ├── src/
│   │   └── lib.rs         # ProcessEvent, FileEvent, NetEvent, etc.
│   └── Cargo.toml         # #![no_std] compatible
│
└── Cargo.toml             # Workspace root
```

---

## 3. eBPF Architecture with aya

### Why aya over libbpf-rs

| Feature | aya | libbpf-rs |
|---|---|---|
| C/libbpf dependency | None (pure Rust) | Required |
| BTF/CO-RE support | Yes (kernel 5.7+) | Yes |
| Safety | Rust type system | Unsafe FFI boundary |
| Ecosystem | aya-log, aya-obj | libbpf ecosystem |
| Async integration | Tokio-native | Manual |

aya's `AsyncPerfEventArray` / `AsyncRingBuf` integrate directly with Tokio's event loop, eliminating manual poll loops.

### Project Setup

```bash
# Prerequisites
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo install cargo-generate

# Generate from template (then customize structure above)
cargo generate --name nova-edr https://github.com/aya-rs/aya-template
```

### eBPF Program Compilation Flow

`build.rs` uses `aya-build` to:
1. Compile `nova-edr-ebpf/` with nightly Rust targeting `bpfel-unknown-none`
2. Link with `bpf-linker` (LLVM backend for BPF)
3. Embed the resulting `.o` via `include_bytes_aligned!` in the userspace binary

This means **the eBPF bytecode ships inside the same binary** — no separate `.o` files to deploy.

```rust
// build.rs
fn main() {
    aya_build::build_ebpf_programs(
        &["nova-edr-ebpf"],
        &["LINUX_VERSION_CODE"],
    ).expect("Failed to build eBPF programs");
}
```

### BTF & CO-RE (Compile Once, Run Anywhere)

aya leverages **BPF Type Format (BTF)** to produce portable bytecode:
- Compiled against kernel headers once
- Kernel automatically relocates field offsets at load time
- Supports kernels 5.7+ (LSM) or 4.18+ (kprobes/tracepoints without LSM)

---

## 4. Hook Strategy: Tracepoints, kprobes, LSM

### Decision Tree

```
What do you need?                → Hook type
─────────────────────────────────────────────────
Process exec/exit events         → Tracepoint (sched:sched_process_exec/exit)
Full argv/envp of exec           → kprobe on sys_execve / raw_tracepoint
File open/read/write events      → kprobe on vfs_open, vfs_write
Network connections              → Tracepoint (tcp:tcp_connect) or kprobe
Block/allow an action            → LSM hook (must return 0/-EPERM)
Protect EDR from signals         → LSM hook (task_kill)
Deny privilege escalation        → LSM hook (task_setuid, bprm_check_security)
```

### Tracepoints (preferred for stability)

Tracepoints are static kernel instrumentation points — stable across kernel versions, lower overhead than kprobes.

```rust
// nova-edr-ebpf/src/main.rs
#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(ctx) { Ok(_) => 0, Err(_) => 1 }
}

#[tracepoint(category = "sched", name = "sched_process_exit")]  
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_exit(ctx) { Ok(_) => 0, Err(_) => 1 }
}
```

Key tracepoints for Nova EDR:
- `sched:sched_process_exec` — new process execution (binary path, PID, UID)
- `sched:sched_process_exit` — process termination (exit code)
- `sched:sched_process_fork` — fork events (track parent/child chains)
- `tcp:tcp_connect` — outbound TCP connections
- `syscalls:sys_enter_execve` — full argv capture (for AI command monitoring)
- `syscalls:sys_enter_openat` — file open (for credential file access)

### kprobes (for deeper visibility)

kprobes attach to arbitrary kernel function entry/return points. Less stable than tracepoints (function signatures can change) but allow access to richer context.

```rust
#[kprobe(name = "nova_vfs_open")]
pub fn vfs_open(ctx: ProbeContext) -> u32 {
    // Access file path, inode, flags from struct file *
    let file: *const bindings::file = ctx.arg(0);
    // ... extract path, send to ring buffer
}
```

Key kprobes:
- `vfs_open` — file opens (path, flags, process context)
- `vfs_write` — file writes (for FIM on critical paths)
- `do_unlinkat` — file deletions
- `commit_creds` — credential changes (privilege escalation detection)

### LSM Hooks (enforcement layer)

LSM hooks are the **only** way to actively deny operations at kernel level. Requires kernel 5.7+ with `CONFIG_BPF_LSM=y` and `lsm=bpf` in kernel parameters.

Check if enabled:
```bash
cat /sys/kernel/security/lsm  # Must contain "bpf"
```

Critical LSM hooks for Nova EDR:

```rust
// Protect EDR from being killed
#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    let target_pid: pid_t = unsafe { ctx.arg(0) };
    let sig: i32 = unsafe { ctx.arg(2) };
    
    // Block signals to our own PID (set at load time via global)
    if target_pid == NOVA_EDR_PID.load(Ordering::Relaxed) {
        // Log tamper attempt, send alert
        ring_buf_submit_tamper_alert(ctx, sig);
        return -1; // EPERM — deny the kill
    }
    0 // Allow
}

// Detect credential escalation
#[lsm(hook = "task_fix_setuid")]
pub fn task_fix_setuid(ctx: LsmContext) -> i32 {
    // Check if AI agent process is gaining root
    // Log and optionally deny
    0
}

// Intercept exec attempts by monitored processes
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    // Check if the exec is from a monitored AI agent
    // Cross-reference with protected process list
    0 // or -EPERM to block
}
```

**Critical note on SIGKILL:** SIGKILL cannot be blocked by any means (including LSM). The `task_kill` LSM hook **can** intercept it before delivery, but returning -EPERM from the hook will be silently ignored for SIGKILL in most kernel configurations. See Anti-Tamper section for the correct strategy.

---

## 5. Process Monitoring

### Data Model (shared between kernel and userspace)

```rust
// nova-edr-common/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub kind: ProcessEventKind,   // Exec, Exit, Fork, Signal
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exit_code: i32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],           // task->comm (short name)
    pub filename: [u8; 256],      // Full path from exec
    pub argv_truncated: [u8; 512], // First 512 bytes of args
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum ProcessEventKind {
    Exec = 0,
    Exit = 1,
    Fork = 2,
    Signal = 3,
}
```

### Ring Buffer (preferred over perf_event_array)

The `BPF_MAP_TYPE_RINGBUF` is superior to `BPF_MAP_TYPE_PERF_EVENT_ARRAY`:
- Single shared buffer (not per-CPU) → preserves event order
- Supports `BPF_RB_NO_WAKEUP` for batched delivery
- Lower memory usage
- Available since kernel 5.8

```rust
// eBPF side
#[map(name = "PROCESS_EVENTS")]
static mut PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0); // 4MB

// Userspace side (tokio integration)
let ring = AsyncRingBuf::<ProcessEvent>::try_from(
    bpf.map_mut("PROCESS_EVENTS").unwrap()
)?;

while let Some(event) = ring.next().await {
    event_tx.send(EdrEvent::Process(*event))?;
}
```

### AI Agent Process Tracking

The Python EDR has a "protected process list" and "AI tool behavioral monitoring". Replicate this with:

1. **eBPF HashMap** — track AI agent PIDs + their ancestry chain
2. **Process tree reconstruction** — parent/child relationships from fork events
3. **Behavioral fingerprinting** — track what files/network/subprocesses an AI agent spawns

```rust
// eBPF map: PID → AIAgentMeta
#[map(name = "AI_AGENTS")]
static mut AI_AGENTS: HashMap<u32, AIAgentMeta> = HashMap::with_max_entries(1024, 0);
```

---

## 6. File Integrity Monitoring

### Dual-layer approach

**Layer 1: eBPF kprobes** (real-time, kernel-level)
- Monitor `vfs_open`, `vfs_write`, `do_unlinkat` for protected paths
- Filter in-kernel (avoid userspace round-trip for non-critical files)
- Send FileEvent to ring buffer only for critical paths

**Layer 2: fanotify** (userspace, blocking)
- `FAN_OPEN_EXEC_PERM` — block execution of modified binaries
- Allows blocking response (unlike inotify which is notification-only)
- Use the `nix` crate for raw fanotify syscalls (notify crate's fanotify support is limited)

```rust
// fim.rs — fanotify watcher for blocking exec
use nix::sys::fanotify::{Fanotify, FanotifyInitFlags, FanotifyMarkFlags, MntId};

pub async fn run_fanotify_watcher(paths: Vec<PathBuf>, event_tx: Sender<EdrEvent>) {
    let fan = Fanotify::init(
        FanotifyInitFlags::FAN_CLASS_CONTENT | FanotifyInitFlags::FAN_NONBLOCK,
        OFlags::RDONLY | OFlags::LARGEFILE,
    ).expect("fanotify init requires root + CAP_SYS_ADMIN");
    
    for path in &paths {
        fan.mark(
            FanotifyMarkFlags::FAN_MARK_ADD | FanotifyMarkFlags::FAN_MARK_FILESYSTEM,
            FanotifyEventFlags::FAN_OPEN_EXEC_PERM | FanotifyEventFlags::FAN_CLOSE_WRITE,
            None,
            Some(path),
        ).expect("mark failed");
    }
    // ... async event loop
}
```

### SHA-256 Baseline Integrity

On startup, compute and store SHA-256 hashes of:
- Nova EDR binary itself (`/proc/self/exe`)
- Nova EDR config files
- Critical system binaries (configurable list)
- AI agent binaries being monitored

Use the `sha2` or `blake3` crate (blake3 is ~3x faster for large files).

```rust
use blake3::Hasher;

pub fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path)?;
    Ok(*blake3::hash(&data).as_bytes())
}
```

---

## 7. Network Egress Monitoring

### Multi-layer approach

**Layer 1: eBPF TC (Traffic Control) egress filter**
- Attach to network interface in TC egress hook
- Inspect packet headers in-kernel before transmission
- Can drop packets (not just observe) — enforcement capability
- Per-process attribution via `bpf_get_current_pid_tgid()`

```rust
// nova-edr-ebpf/src/net.rs
#[classifier(name = "nova_tc_egress")]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let pid = bpf_get_current_pid_tgid() as u32;
    
    // Check if this PID is a monitored AI agent
    if let Some(agent) = unsafe { AI_AGENTS.get(&pid) } {
        let dst_ip = extract_dst_ip(&ctx)?;
        let dst_port = extract_dst_port(&ctx)?;
        let bytes = ctx.len() as u64;
        
        // Send flow event to ring buffer
        submit_net_event(pid, dst_ip, dst_port, bytes);
        
        // If killswitch active for this agent, drop packet
        if agent.egress_blocked {
            return Ok(TC_ACT_SHOT); // Drop
        }
    }
    Ok(TC_ACT_OK)
}
```

**Layer 2: Socket-level kprobes**
- `tcp_connect` / `udp_sendmsg` — get process context with connection details
- Higher-level than TC (post-routing), but easier to correlate with processes
- Use for DNS monitoring, exfiltration pattern detection

### Exfiltration Detection Heuristics

Track per-agent egress metrics in an eBPF HashMap:
```rust
#[repr(C)]
pub struct EgressStats {
    pub bytes_sent: u64,
    pub connection_count: u32,
    pub unique_destinations: u32,
    pub last_alert_ts: u64,
}

#[map(name = "EGRESS_STATS")]
static mut EGRESS_STATS: HashMap<u32, EgressStats> = HashMap::with_max_entries(1024, 0);
```

Alert when:
- Single agent sends > threshold bytes/minute (configurable, default 10MB)
- Connections to unusual external IPs (compare against allowlist)
- DNS queries for suspicious patterns (base64-encoded subdomains)
- Data volumes spike relative to baseline

---

## 8. Anti-Tamper & Watchdog Pattern

This is the most architecturally complex part. The Python EDR has basic SIGSTOP responses; we need something that survives `kill -9`.

### The Core Problem

`SIGKILL` (signal 9) cannot be blocked at the userspace level. Even LSM hooks cannot reliably prevent SIGKILL delivery (kernel enforces it). Therefore, **the process will die**. The strategy is:

1. **eBPF programs persist in the kernel** after the userspace daemon dies (if pinned to bpffs)
2. **Watchdog process** detects death and respawns
3. **systemd** handles respawn as the last line of defense
4. **LSM hooks** raise alerts when kill attempts are made (even if they can't always block them)

### Strategy 1: eBPF Program Pinning (Kernel Persistence)

Pin eBPF programs to the BPF filesystem so they outlive the loader process:

```rust
// In ebpf_loader.rs
pub fn pin_programs(bpf: &mut Ebpf) -> Result<()> {
    // Pin to /sys/fs/bpf/nova-edr/
    let pin_dir = Path::new("/sys/fs/bpf/nova-edr");
    fs::create_dir_all(pin_dir)?;
    
    for prog_name in &["nova_process_exec", "nova_tc_egress", "nova_lsm_kill"] {
        let prog = bpf.program_mut(prog_name).unwrap();
        prog.pin(pin_dir.join(prog_name))?;
    }
    
    // Pin maps too
    bpf.map_mut("PROCESS_EVENTS").unwrap()
        .pin(pin_dir.join("process_events"))?;
    Ok(())
}
```

On restart, the new process reattaches to existing pinned programs:
```rust
pub fn load_or_reattach(bpf: &mut Ebpf) -> Result<()> {
    let pin_dir = Path::new("/sys/fs/bpf/nova-edr");
    if pin_dir.exists() {
        // Reattach to already-running pinned programs
        // (they kept monitoring even while we were dead)
    } else {
        // Fresh load
        pin_programs(bpf)?;
    }
}
```

### Strategy 2: Two-Process Mutual Watchdog

Run two processes that monitor each other. If either dies, the other respawns it.

```
[nova-edr-daemon]  ←→  [nova-edr-watchdog]
         ↑                      ↑
         └── monitors PID ──────┘
         └── mutual heartbeat ──┘
```

```rust
// watchdog.rs
pub struct Watchdog {
    daemon_pid: Arc<AtomicU32>,
    watchdog_pid: u32,
    heartbeat_socket: UnixDatagram,
}

impl Watchdog {
    pub async fn run(&self) -> Result<()> {
        loop {
            // Check heartbeat from daemon
            let deadline = Instant::now() + Duration::from_secs(5);
            match timeout_at(deadline, self.recv_heartbeat()).await {
                Ok(_) => {} // Alive
                Err(_) => {
                    // Daemon died or hung
                    self.alert_tamper_attempt().await;
                    self.respawn_daemon().await?;
                }
            }
            
            // Send our own heartbeat
            self.send_heartbeat().await?;
            
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    
    async fn respawn_daemon(&self) -> Result<()> {
        let exe = std::env::current_exe()?;
        let child = Command::new(&exe)
            .arg("--daemon")
            .spawn()?;
        self.daemon_pid.store(child.id(), Ordering::SeqCst);
        Ok(())
    }
}
```

### Strategy 3: LSM Kill Alert (Best-Effort Block)

Even though SIGKILL can't be blocked, we can log and alert immediately:

```rust
// nova-edr-ebpf/src/lsm.rs
#[lsm(hook = "task_kill")]
pub fn nova_lsm_task_kill(ctx: LsmContext) -> i32 {
    let target_pid: u32 = unsafe { ctx.arg(0) };  
    let sig: i32 = unsafe { ctx.arg(2) };
    
    let edr_pid = NOVA_EDR_PID.load(Ordering::Relaxed);
    let watchdog_pid = NOVA_WATCHDOG_PID.load(Ordering::Relaxed);
    
    if target_pid == edr_pid || target_pid == watchdog_pid {
        // Submit tamper alert (synchronous, before kill happens)
        let _ = submit_tamper_alert(&ctx, TamperKind::KillAttempt, target_pid, sig);
        
        // For non-SIGKILL signals, we can block
        if sig != 9 {
            return -1; // EPERM
        }
        // SIGKILL: alert but can't block; watchdog will respawn
    }
    0
}
```

### Strategy 4: systemd Hardened Service

```ini
[Service]
Restart=always
RestartSec=1
# Watchdog protocol (systemd native)
WatchdogSec=10
NotifyAccess=main
Type=notify

# Make the service hard to stop without explicit systemctl stop
KillMode=mixed
SendSIGKILL=no
TimeoutStopSec=infinity
```

The process calls `sd_notify(0, "WATCHDOG=1")` every 5 seconds. If systemd doesn't receive this within `WatchdogSec`, it restarts the service.

### Strategy 5: Binary Self-Integrity Check

On startup, verify the EDR binary hasn't been tampered with:

```rust
pub fn verify_self_integrity(expected_hash: &[u8; 32]) -> Result<()> {
    let exe_path = std::fs::read_link("/proc/self/exe")?;
    let actual_hash = hash_file(&exe_path)?;
    
    if actual_hash != *expected_hash {
        panic!("TAMPER ALERT: EDR binary has been modified!");
    }
    Ok(())
}
```

Store the expected hash in a separate file protected by permissions (`root:root 600`) and verified via LSM on access.

---

## 9. MITRE ATLAS Mapping (AI-Specific)

**Use MITRE ATLAS**, not ATT&CK. ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's dedicated AI security framework. As of October 2025, it has 15 tactics, 66 techniques, 46 sub-techniques, including 14 new agentic AI techniques.

### AI-Agent-Specific Detection Signatures

| ATLAS Technique | Nova EDR Detection | eBPF Hook |
|---|---|---|
| Credentials from AI Agent Config | Read of `~/.claude/`, `~/.codex/`, `secrets/` by non-agent processes | LSM `file_open` + path filter |
| RAG Credential Harvesting | Unusual DB/vector store queries from agent process | kprobe on socket send, DNS |
| Modify AI Agent Configuration | Write to agent config files | eBPF FIM on config paths |
| Prompt Injection → Shell Exec | Unexpected `execve` of `bash`/`sh` by AI agent | Tracepoint `sched_process_exec` |
| Agent spawning child agents | Fork/exec chains exceeding depth threshold | Process tree tracking |
| Data Exfiltration via Agent | High egress volume from agent PID | TC egress bytes counter |
| Vault/Secrets Access | Agent reading `/proc/*/environ`, secret stores | kprobe `vfs_open` |
| Privilege Escalation | `commit_creds` with UID 0 from agent process | kprobe `commit_creds` |
| Tool misuse: curl/wget | AI agent exec'ing network tools unexpectedly | Process allowlist check |
| Persistence via cron | AI agent writing to `crontab`, `/etc/cron*` | FIM on cron paths |

### AI Tool Behavioral Allowlist

```yaml
# config.yaml
ai_agents:
  - name: claude-code
    binary_patterns:
      - "node"
      - "claude"
    allowed_exec:
      - "git"
      - "cargo"
      - "python3"
    denied_exec:
      - "curl"
      - "wget"
      - "nc"
      - "bash"  # unless explicitly allowed per-session
    egress_limit_mbps: 10
    protected_paths:
      - "/home/ryan/.ssh"
      - "/home/ryan/.aws"
      - "/home/ryan/clawd/secrets"
```

---

## 10. Real-Time Alerting

### Alert Channels

1. **Local Unix socket** — primary; OpenClaw daemon listens on `/run/nova-edr/alerts.sock`
2. **Webhook (HTTP/S)** — Telegram, Slack, PagerDuty
3. **Journald** — structured logging via `sd_journal_send` for systemd integration
4. **Forensic JSON log** — append-only, rotated, signed

```rust
// alert.rs
pub enum AlertChannel {
    UnixSocket(UnixListener),
    Webhook(reqwest::Client, Url),
    Journald,
    AuditLog(BufWriter<File>),
}

#[derive(Serialize)]
pub struct Alert {
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub mitre_atlas_id: Option<String>,
    pub pid: u32,
    pub agent_name: String,
    pub description: String,
    pub raw_event: EdrEvent,
}
```

### OpenClaw Integration

The main agent (OpenClaw) already receives Telegram messages and can act on alerts. Nova EDR should emit alerts to:
1. `/run/nova-edr/alerts.sock` — OpenClaw reads this socket
2. Or call OpenClaw's HTTP API if it exposes one

Alert format should include `mitre_atlas_id` and `severity` so the main agent can decide response level.

---

## 11. systemd Integration & Hardening

### Service File (`/etc/systemd/system/nova-edr.service`)

```ini
[Unit]
Description=Nova EDR - AI Agent Security Monitor
Documentation=https://github.com/meridianhouse/nova-edr
After=network.target
StartLimitIntervalSec=0

[Service]
Type=notify
ExecStart=/usr/local/bin/nova-edr --config /etc/nova-edr/config.yaml
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy (resilient)
Restart=always
RestartSec=1
StartLimitBurst=0

# systemd watchdog
WatchdogSec=15
NotifyAccess=main

# User/Group (EDR needs root or specific caps)
User=root
Group=root

# Capability hardening (only what we actually need)
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_KILL CAP_BPF CAP_PERFMON
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_PERFMON

# Filesystem protection
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/nova-edr /run/nova-edr /sys/fs/bpf/nova-edr

# Process isolation
NoNewPrivileges=yes  # Must be no if we need to spawn privileged children
PrivateTmp=yes
PrivateDevices=no  # Needs /dev/null etc.
ProtectKernelTunables=no  # Needs kernel access
ProtectKernelModules=yes
ProtectControlGroups=yes

# Network
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

# Seccomp (aggressive filtering)
SystemCallFilter=@system-service @network-io @file-system bpf perf_event_open

[Install]
WantedBy=multi-user.target
```

**Note:** `NoNewPrivileges=yes` conflicts with needing `CAP_SYS_ADMIN` for eBPF loading. Use `AmbientCapabilities` instead, and keep `NoNewPrivileges=no` if the process needs to exec privileged children. Alternatively, pre-load eBPF programs in a short-lived privileged launcher that then drops to a less-privileged daemon.

### Hardening Score

Use `systemd-analyze security nova-edr.service` to assess. Target score < 4.0 (exposed). With the above config, expect ~2.5-3.5.

---

## 12. Performance Considerations

### eBPF vs. /proc Polling

| Method | Latency | CPU Overhead | Event Fidelity |
|---|---|---|---|
| /proc polling (Python, 1s) | ~1000ms | ~5-15% | Misses short-lived processes |
| eBPF tracepoint | <1ms | <0.5% | 100% — every exec captured |
| eBPF LSM hook | <0.1ms | <0.1% | 100% — synchronous |

Real-world benchmarks: Wiz Defend's eBPF sensor achieves 11ms alert latency with <2% CPU overhead across production fleets.

### Ring Buffer Sizing

```rust
// 4MB ring buffer for process events
// At 1000 events/sec × ~500 bytes/event = 500KB/sec
// 4MB gives ~8 seconds of burst buffer before backpressure
const PROCESS_RINGBUF_SIZE: u32 = 4 * 1024 * 1024;
const NET_RINGBUF_SIZE: u32 = 8 * 1024 * 1024; // Network is higher volume
```

If events are dropped (lagged subscriber), log a warning. In high-throughput scenarios, use `BPF_RB_NO_WAKEUP` with periodic forced wakeup.

### In-Kernel Filtering (Critical)

Do NOT send every event to userspace. Filter aggressively in eBPF:

```rust
// eBPF: only forward exec events for monitored agent PIDs
fn try_exec(ctx: TracePointContext) -> Result<(), i64> {
    let pid = bpf_get_current_pid_tgid() as u32;
    
    // Check if this PID (or its parent) is in our watchlist
    // If not, return early without allocating ring buffer entry
    if unsafe { AI_AGENTS.get(&pid).is_none() } {
        // Check parent PID
        let ppid = get_ppid();
        if unsafe { AI_AGENTS.get(&ppid).is_none() } {
            return Ok(()); // Skip — not a monitored agent
        }
    }
    
    // Only reach here for monitored processes
    submit_process_event(ctx)?;
    Ok(())
}
```

Datadog's eBPF FIM implementation filters 94% of events in-kernel, processing only ~1M relevant events/minute across large infrastructure.

### Userspace Event Processing

- Use `tokio::sync::broadcast` with backpressure: if a subscriber is > 1000 events behind, drop oldest and log
- Response engine runs on dedicated threads (not shared Tokio thread pool) to avoid head-of-line blocking
- Alert dispatch is async/non-blocking; failures go to a retry queue

---

## 13. Packaging & Distribution

### Single Static Binary (Target)

```bash
# Add musl target
rustup target add x86_64-unknown-linux-musl

# .cargo/config.toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"

# Build
cargo build --release --target x86_64-unknown-linux-musl
```

Result: `target/x86_64-unknown-linux-musl/release/nova-edr` — statically linked, ~15-30MB typically.

**Caveat:** eBPF programs require nightly Rust compiler for the eBPF target (`bpfel-unknown-none`). The userspace binary itself can be stable. Use a split build:

```makefile
# Build eBPF with nightly
build-ebpf:
    cargo +nightly build -Z build-std=core \
        --target bpfel-unknown-none \
        --release \
        -p nova-edr-ebpf

# Build userspace with stable (embeds eBPF via include_bytes!)
build:
    cargo build --release --target x86_64-unknown-linux-musl
```

### Installation Script

```bash
#!/bin/bash
# install.sh
install -m 755 nova-edr /usr/local/bin/
install -m 755 nova-edr-watchdog /usr/local/bin/  # if separate binary
install -d /etc/nova-edr /var/log/nova-edr /run/nova-edr
install -m 640 config.yaml /etc/nova-edr/
install -m 644 nova-edr.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nova-edr
```

### Version Compatibility Matrix

| Feature | Min Kernel | Notes |
|---|---|---|
| kprobes | 2.6.9 | Very old |
| Tracepoints | 2.6.27 | Standard |
| eBPF programs | 3.18 | Basic |
| BTF/CO-RE | 5.4 | Needed for aya |
| LSM hooks | 5.7 | Critical for enforcement |
| Ring buffer | 5.8 | Preferred; fall back to perf_event_array |

Minimum recommended: **kernel 5.15** (LTS). Ubuntu 22.04+ ships 5.15, Fedora 38+ ships 6.x.

---

## 14. Cargo Workspace Layout

### `Cargo.toml` (workspace root)

```toml
[workspace]
members = [
    "nova-edr",          # Main userspace binary
    "nova-edr-ebpf",     # eBPF kernel programs
    "nova-edr-common",   # Shared types (no_std)
]
resolver = "2"

[workspace.dependencies]
# Userspace
tokio = { version = "1", features = ["full"] }
aya = { version = "0.13", features = ["async_tokio"] }
aya-log = "0.2"
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
blake3 = "1"
nix = { version = "0.29", features = ["signal", "process", "fs"] }
sd-notify = "0.4"
chrono = { version = "0.4", features = ["serde"] }
toml = "0.8"

# eBPF
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"

# Build
aya-build = "0.1"
```

### `nova-edr-common/Cargo.toml`

```toml
[package]
name = "nova-edr-common"
version = "0.1.0"
edition = "2021"

# Must be no_std for use in eBPF kernel programs
[features]
default = ["userspace"]
userspace = ["dep:serde"]

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```

---

## 15. Crate Dependency Matrix

| Crate | Purpose | Notes |
|---|---|---|
| `aya` | eBPF program loading, map access, async ring buffer | Core |
| `aya-ebpf` | eBPF kernel-side macros/types | no_std |
| `aya-log` / `aya-log-ebpf` | Structured logging from eBPF | |
| `tokio` | Async runtime, channels, timers | full features |
| `anyhow` | Error handling | |
| `serde` + `serde_json` + `serde_yaml` | Serialization | |
| `reqwest` | Webhook HTTP client | rustls, no OpenSSL |
| `tracing` + `tracing-subscriber` | Structured logging | json format |
| `blake3` | Fast file hashing for FIM | 3x faster than SHA-256 |
| `nix` | fanotify, Unix signals, low-level Linux | |
| `sd-notify` | systemd watchdog protocol | |
| `chrono` | Timestamps | |
| `ring` or `rustls` | TLS for webhook alerts | |
| `tokio-unix-listener` | Unix socket server for OpenClaw | in tokio |

Deliberately **excluded**:
- `openssl` — use `rustls` instead (avoids C dep, better for static linking)
- `libbpf-rs` — using aya instead
- `procfs` — we're replacing /proc polling with eBPF

---

## 16. Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- [ ] Set up Cargo workspace with aya template
- [ ] Basic process exec/exit tracepoints working
- [ ] ProcessEvent shared type in nova-edr-common
- [ ] Ring buffer → Tokio event bus pipeline
- [ ] YAML config loading, structured JSON logging

### Phase 2: Core Monitoring (Week 3-4)
- [ ] Process tree tracking (fork events + PID→agent mapping)
- [ ] AI agent detection (binary name matching, parent chain)
- [ ] argv capture from execve
- [ ] Credential file access detection (vfs_open kprobe)
- [ ] Basic MITRE ATLAS mapping module

### Phase 3: Response & LSM (Week 5-6)
- [ ] LSM hooks (task_kill alert, signal blocking for non-SIGKILL)
- [ ] SIGSTOP/SIGCONT response (equivalent to killswitch.py)
- [ ] TC egress filter for basic network monitoring
- [ ] Webhook/socket alerting

### Phase 4: Anti-Tamper (Week 7)
- [ ] eBPF program pinning to bpffs
- [ ] Watchdog process mutual monitoring
- [ ] systemd watchdog protocol
- [ ] Binary self-integrity check on startup

### Phase 5: File Integrity & Network (Week 8-9)
- [ ] fanotify-based FIM with configurable paths
- [ ] Per-agent egress byte tracking
- [ ] Exfiltration heuristics (threshold alerting)
- [ ] DNS monitoring for suspicious patterns

### Phase 6: Polish (Week 10)
- [ ] Static musl binary build
- [ ] systemd service file with full hardening
- [ ] Install script
- [ ] Multi-node relay (replaces node_monitor.py)
- [ ] Migration guide from Python EDR

---

## Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Kernel version < 5.7 (no LSM) | Detect at startup; degrade gracefully (no enforcement, monitoring only) |
| BPF LSM not enabled | Print instructions; provide kernel param to add |
| SIGKILL bypasses all protection | Pin eBPF to bpffs; systemd Restart=always; watchdog respawn |
| eBPF verifier rejects program | Keep programs simple; test against min kernel version |
| High event volume causing drops | Aggressive in-kernel filtering; tune ring buffer sizes |
| musl + eBPF nightly toolchain complexity | CI/CD builds in Docker; pin toolchain versions |

---

## References

- [aya-rs book](https://aya-rs.dev/book/) — Definitive aya reference
- [lsm_hook_defs.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h) — All available LSM hooks
- [aya-rs/aya-template](https://github.com/aya-rs/aya-template) — Project scaffolding
- [MITRE ATLAS](https://atlas.mitre.org) — AI threat framework (14 agentic techniques added Oct 2025)
- [Datadog eBPF FIM blog](https://www.datadoghq.com/blog/engineering/workload-protection-ebpf-fim/) — Production lessons
- [Wiz Defend eBPF sensor](https://softwareanalyst.substack.com/p/runtime-security-in-2025-how-wiz) — 11ms latency, <2% overhead benchmarks
- [Trail of Bits: eBPF pitfalls](https://blog.trailofbits.com/2023/09/25/pitfalls-of-relying-on-ebpf-for-security-monitoring-and-some-solutions/) — Known limitations
- [tetragon-mini](https://yuki-nakamura.com/2024/12/28/tetragon-mini-by-rust-ebpf-based-process-monitoring/) — Rust eBPF process monitoring reference impl
- [systemd hardening](https://www.opensourcerers.org/2022/04/25/optimizing-a-systemd-service-for-security/) — Service hardening guide
