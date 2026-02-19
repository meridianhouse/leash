use crate::mitre::infer_and_tag;
use crate::models::{EventType, FileEvent, NetConnection, ProcessInfo, SecurityEvent, ThreatLevel};

pub fn build_test_events() -> Vec<SecurityEvent> {
    let green_proc = ProcessInfo {
        pid: 4242,
        ppid: 2211,
        name: "codex".to_string(),
        cmdline: "codex --task review".to_string(),
        exe: "/usr/local/bin/codex".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec![],
        parent_chain: vec!["bash(2211)".to_string(), "tmux(1111)".to_string()],
    };

    let yellow_proc = ProcessInfo {
        pid: 4343,
        ppid: 4242,
        name: "bash".to_string(),
        cmdline: "bash -lc curl https://example.com/bootstrap.sh".to_string(),
        exe: "/usr/bin/bash".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec!["/tmp/bootstrap.sh".to_string()],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let orange_proc = ProcessInfo {
        pid: 4444,
        ppid: 4242,
        name: "python3".to_string(),
        cmdline: "python3 -c \"import socket\"".to_string(),
        exe: "/usr/bin/python3".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec![],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let red_proc = ProcessInfo {
        pid: 4545,
        ppid: 4242,
        name: "cat".to_string(),
        cmdline: "cat ~/.ssh/id_rsa".to_string(),
        exe: "/usr/bin/cat".to_string(),
        cwd: "/home/user".to_string(),
        username: "user".to_string(),
        open_files: vec!["/home/user/.ssh/id_rsa".to_string()],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let mut green = SecurityEvent::new(
        EventType::ProcessNew,
        ThreatLevel::Green,
        "TEST EVENT: baseline monitored process detected".to_string(),
    );
    green.process = Some(green_proc);

    let mut yellow = SecurityEvent::new(
        EventType::ProcessShellSpawn,
        ThreatLevel::Yellow,
        "TEST EVENT: shell spawn under monitored AI process".to_string(),
    );
    yellow.process = Some(yellow_proc);

    let mut orange = SecurityEvent::new(
        EventType::NetworkSuspicious,
        ThreatLevel::Orange,
        "TEST EVENT: suspicious outbound network activity".to_string(),
    );
    orange.process = Some(orange_proc);
    orange.connection = Some(NetConnection {
        local_addr: "10.0.0.10".to_string(),
        local_port: 54622,
        remote_addr: "198.51.100.25".to_string(),
        remote_port: 4444,
        state: "ESTABLISHED".to_string(),
        pid: 4444,
        process_name: "python3".to_string(),
    });

    let mut red = SecurityEvent::new(
        EventType::CredentialAccess,
        ThreatLevel::Red,
        "TEST EVENT: access to sensitive credential path".to_string(),
    );
    red.process = Some(red_proc);
    red.file_event = Some(FileEvent {
        path: "/home/user/.ssh/id_rsa".to_string(),
        event_type: "read".to_string(),
        old_hash: None,
        new_hash: None,
        old_perms: None,
        new_perms: None,
    });

    vec![
        infer_and_tag(green),
        infer_and_tag(yellow),
        infer_and_tag(orange),
        infer_and_tag(red),
    ]
}
