use crate::models::{EventType, MitreMapping, SecurityEvent};

pub fn infer_and_tag(mut event: SecurityEvent) -> SecurityEvent {
    match event.event_type {
        EventType::ProcessShellSpawn => add_technique(&mut event, "T1059.004"),
        EventType::CredentialAccess => add_technique(&mut event, "T1552.001"),
        EventType::NetworkSuspicious => add_technique(&mut event, "T1071.001"),
        EventType::NetworkNewConnection => add_technique(&mut event, "T1071.001"),
        EventType::FileModified | EventType::FileCreated | EventType::FilePermissionChange => {
            add_technique(&mut event, "T1005");
        }
        EventType::SelfTamper => add_technique(&mut event, "T1562.001"),
        EventType::ContainerEscape => add_technique(&mut event, "T1611"),
        _ => add_technique(&mut event, "T1204"),
    }

    let process_cmd = event
        .process
        .as_ref()
        .map(|p| p.cmdline.to_ascii_lowercase())
        .unwrap_or_default();
    let narrative = event.narrative.to_ascii_lowercase();
    let combined = format!("{process_cmd} {narrative}");

    if looks_like_prompt_injection(&combined) {
        add_technique(&mut event, "AML.T0054");
    }

    if looks_like_model_evasion(&combined) {
        add_technique(&mut event, "AML.T0051");
    }

    if combined.contains("python -c")
        || combined.contains("python3 -c")
        || combined.contains("python ")
        || combined.contains("python3 ")
    {
        add_technique(&mut event, "T1059.006");
    }

    if combined.contains("http://")
        || combined.contains("https://")
        || combined.contains("curl ")
        || combined.contains("wget ")
    {
        add_technique(&mut event, "T1071.001");
    }

    if combined.contains(" nc ")
        || combined.contains(" ncat ")
        || combined.starts_with("nc ")
        || combined.starts_with("ncat ")
    {
        add_technique(&mut event, "T1048");
    }

    if combined.contains("download_pipe_shell")
        || combined.contains("wget_pipe_shell")
        || (combined.contains("curl ") && combined.contains("| bash"))
        || (combined.contains("wget ") && combined.contains("| sh"))
    {
        add_technique(&mut event, "T1105");
    }

    if combined.contains("base64 -d")
        || combined.contains("base64 --decode")
        || combined.contains("base64_decode")
        || combined.contains("encoded_python")
    {
        add_technique(&mut event, "T1027");
    }

    if combined.contains("ssh_unusual_host")
        || combined.starts_with("ssh ")
        || combined.contains(" ssh ")
    {
        add_technique(&mut event, "T1021.004");
    }

    if combined.contains("known_exfil_service")
        || combined.contains("pastebin")
        || combined.contains("transfer.sh")
        || combined.contains("file.io")
    {
        add_technique(&mut event, "T1567");
    }

    if combined.contains("tor_port") || combined.contains("9050") || combined.contains("9051") {
        add_technique(&mut event, "T1090");
    }

    if combined.contains("chmod +x")
        || combined.contains("download_exec")
        || combined.contains("download_exec_tmpdir")
        || combined.contains("write_sensitive_path")
    {
        add_technique(&mut event, "T1222.001");
    }

    if combined.contains("gatekeeper_bypass")
        || combined.contains("xattr -c")
        || combined.contains("xattr -d com.apple.quarantine")
        || combined.contains("xattr -rd com.apple.quarantine")
    {
        add_technique(&mut event, "T1553.001");
    }

    if combined.contains("osascript_tmp_exec")
        || combined.contains("osascript_inline_sensitive")
        || combined.contains("osacompile_with_curl")
        || combined.contains("osascript -e")
        || combined.contains("osacompile")
    {
        add_technique(&mut event, "T1059.002");
    }

    if combined.contains("fileless_pipeline_decode")
        || combined.contains("fileless_pipeline_python")
        || combined.contains("exec_tmpdir")
        || ((combined.contains("curl ")
            || combined.contains("http://")
            || combined.contains("https://"))
            && (combined.contains("| python") || combined.contains("| python3")))
    {
        add_technique(&mut event, "T1059.004");
    }

    if combined.contains("launchd_persistence")
        || combined.contains("/library/launchdaemons/")
        || combined.contains("/library/launchagents/")
    {
        add_technique(&mut event, "T1543.001");
    }

    if combined.contains("kube_config_access") || combined.contains(".kube/config") {
        add_technique(&mut event, "T1552.001");
    }

    let persistence_path = event
        .file_event
        .as_ref()
        .map(|f| f.path.to_ascii_lowercase())
        .unwrap_or_default();
    if persistence_path.contains("systemd")
        || persistence_path.contains("/etc/cron")
        || persistence_path.contains("/var/spool/cron")
        || combined.contains("crontab ")
    {
        add_technique(&mut event, "T1547.001");
    }

    event
}

fn add_technique(event: &mut SecurityEvent, technique_id: &str) {
    if event
        .mitre
        .iter()
        .any(|existing| existing.technique_id == technique_id)
    {
        return;
    }
    if let Some(mapping) = lookup(technique_id) {
        event.mitre.push(mapping);
    }
}

fn looks_like_prompt_injection(text: &str) -> bool {
    let needles = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard earlier instructions",
        "system prompt",
        "developer message",
        "jailbreak",
        "prompt injection",
    ];
    needles.iter().any(|needle| text.contains(needle))
}

fn looks_like_model_evasion(text: &str) -> bool {
    let needles = [
        "bypass safety",
        "evade detection",
        "avoid guardrails",
        "obfuscate payload",
        "stealth prompt",
        "jailbreak",
    ];
    needles.iter().any(|needle| text.contains(needle))
}

fn lookup(technique_id: &str) -> Option<MitreMapping> {
    let (tactic, name) = match technique_id {
        "AML.T0054" => ("ATLAS", "LLM Prompt Injection"),
        "AML.T0051" => ("ATLAS", "Model Evasion"),
        "T1059.004" => ("Execution", "Command and Scripting Interpreter: Unix Shell"),
        "T1059.002" => (
            "Execution",
            "Command and Scripting Interpreter: AppleScript",
        ),
        "T1059.006" => ("Execution", "Command and Scripting Interpreter: Python"),
        "T1552.001" => (
            "Credential Access",
            "Unsecured Credentials: Credentials In Files",
        ),
        "T1553.001" => (
            "Defense Evasion",
            "Subvert Trust Controls: Gatekeeper Bypass",
        ),
        "T1071.001" => (
            "Command and Control",
            "Application Layer Protocol: Web Protocols",
        ),
        "T1071" => ("Command and Control", "Application Layer Protocol"),
        "T1048" => ("Exfiltration", "Exfiltration Over Alternative Protocol"),
        "T1547.001" => (
            "Persistence",
            "Boot/Logon Autostart: systemd or cron modification",
        ),
        "T1543.001" => (
            "Persistence",
            "Create or Modify System Process: Launch Agent",
        ),
        "T1105" => ("Command and Control", "Ingress Tool Transfer"),
        "T1027" => (
            "Defense Evasion",
            "Obfuscated/Compressed Files and Information",
        ),
        "T1021.004" => ("Lateral Movement", "Remote Services: SSH"),
        "T1567" => ("Exfiltration", "Exfiltration Over Web Service"),
        "T1090" => ("Command and Control", "Proxy"),
        "T1222.001" => (
            "Defense Evasion",
            "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
        ),
        "T1005" => ("Collection", "Data from Local System"),
        "T1562.001" => (
            "Defense Evasion",
            "Impair Defenses: Disable or Modify Tools",
        ),
        "T1611" => ("Privilege Escalation", "Escape to Host"),
        "T1204" => ("Execution", "User Execution"),
        _ => return None,
    };

    Some(MitreMapping {
        technique_id: technique_id.to_string(),
        tactic: tactic.to_string(),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventType, SecurityEvent, ThreatLevel};

    fn has_technique_prefix(event: &SecurityEvent, technique_id_prefix: &str) -> bool {
        event
            .mitre
            .iter()
            .any(|mapping| mapping.technique_id.starts_with(technique_id_prefix))
    }

    #[test]
    fn process_spawn_gets_t1059_mapping() {
        let shell_event = infer_and_tag(SecurityEvent::new(
            EventType::ProcessShellSpawn,
            ThreatLevel::Yellow,
            "shell".into(),
        ));
        assert!(has_technique_prefix(&shell_event, "T1059"));
    }

    #[test]
    fn credential_access_gets_t1552_mapping() {
        let credential_event = infer_and_tag(SecurityEvent::new(
            EventType::CredentialAccess,
            ThreatLevel::Red,
            "credential".into(),
        ));
        assert!(has_technique_prefix(&credential_event, "T1552"));
    }

    #[test]
    fn network_events_get_t1071_mapping() {
        let network_event = infer_and_tag(SecurityEvent::new(
            EventType::NetworkSuspicious,
            ThreatLevel::Orange,
            "network".into(),
        ));
        assert!(has_technique_prefix(&network_event, "T1071"));
    }

    #[test]
    fn gatekeeper_bypass_gets_t1553_mapping() {
        let event = infer_and_tag(SecurityEvent::new(
            EventType::NetworkSuspicious,
            ThreatLevel::Orange,
            "Dangerous command pattern(s) [gatekeeper_bypass]".into(),
        ));
        assert!(has_technique_prefix(&event, "T1553.001"));
    }

    #[test]
    fn applescript_abuse_gets_t1059_002_mapping() {
        let event = infer_and_tag(SecurityEvent::new(
            EventType::NetworkSuspicious,
            ThreatLevel::Orange,
            "Dangerous command pattern(s) [osascript_inline_sensitive]".into(),
        ));
        assert!(has_technique_prefix(&event, "T1059.002"));
    }

    #[test]
    fn launchd_persistence_gets_t1543_001_mapping() {
        let event = infer_and_tag(SecurityEvent::new(
            EventType::NetworkSuspicious,
            ThreatLevel::Red,
            "Dangerous command pattern(s) [launchd_persistence]".into(),
        ));
        assert!(has_technique_prefix(&event, "T1543.001"));
    }
}
