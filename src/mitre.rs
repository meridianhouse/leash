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
        "T1059.006" => ("Execution", "Command and Scripting Interpreter: Python"),
        "T1552.001" => (
            "Credential Access",
            "Unsecured Credentials: Credentials In Files",
        ),
        "T1071.001" => ("Command and Control", "Application Layer Protocol: Web Protocols"),
        "T1071" => ("Command and Control", "Application Layer Protocol"),
        "T1048" => ("Exfiltration", "Exfiltration Over Alternative Protocol"),
        "T1547.001" => (
            "Persistence",
            "Boot/Logon Autostart: systemd or cron modification",
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
