use crate::models::{EventType, MitreMapping, SecurityEvent};

pub fn tag_event(mut event: SecurityEvent, technique_id: &str) -> SecurityEvent {
    event.mitre = lookup(technique_id);
    event
}

pub fn infer_and_tag(mut event: SecurityEvent) -> SecurityEvent {
    let technique = match event.event_type {
        EventType::ProcessShellSpawn => Some("T1059.004"),
        EventType::CredentialAccess => Some("T1552.001"),
        EventType::NetworkSuspicious => Some("T1071"),
        EventType::NetworkNewConnection => Some("T1071"),
        EventType::FileModified | EventType::FileCreated | EventType::FilePermissionChange => {
            Some("T1005")
        }
        EventType::SelfTamper => Some("T1562.001"),
        EventType::ContainerEscape => Some("T1611"),
        _ => Some("T1204"),
    };

    if let Some(tech) = technique {
        event.mitre = lookup(tech);
    }

    event
}

fn lookup(technique_id: &str) -> Option<MitreMapping> {
    let (tactic, name) = match technique_id {
        "T1059.004" => ("Execution", "Command and Scripting Interpreter: Unix Shell"),
        "T1552.001" => (
            "Credential Access",
            "Unsecured Credentials: Credentials In Files",
        ),
        "T1071" => ("Command and Control", "Application Layer Protocol"),
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
