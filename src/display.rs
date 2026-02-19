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
            println!("   tree: {}", format_process_tree(process));
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

fn format_process_tree(process: &ProcessInfo) -> String {
    if process.parent_chain.is_empty() {
        return format!("{}({})", process.name, process.pid);
    }

    let mut parts = process.parent_chain.clone();
    parts.reverse();
    parts.push(format!("{}({})", process.name, process.pid));
    parts.join(" -> ")
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
