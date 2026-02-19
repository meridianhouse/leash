use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    Green,
    Yellow,
    Orange,
    Red,
    Nuclear,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessNew,
    ProcessExit,
    ProcessShellSpawn,
    NetworkNewConnection,
    NetworkSuspicious,
    FileModified,
    FileCreated,
    FilePermissionChange,
    CredentialAccess,
    SelfTamper,
    Persistence,
    ContainerEscape,
    VaultAccess,
    PromptInjection,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            EventType::ProcessNew => "process_new",
            EventType::ProcessExit => "process_exit",
            EventType::ProcessShellSpawn => "process_shell_spawn",
            EventType::NetworkNewConnection => "network_new_connection",
            EventType::NetworkSuspicious => "network_suspicious",
            EventType::FileModified => "file_modified",
            EventType::FileCreated => "file_created",
            EventType::FilePermissionChange => "file_permission_change",
            EventType::CredentialAccess => "credential_access",
            EventType::SelfTamper => "self_tamper",
            EventType::Persistence => "persistence",
            EventType::ContainerEscape => "container_escape",
            EventType::VaultAccess => "vault_access",
            EventType::PromptInjection => "prompt_injection",
        };
        write!(f, "{text}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub cmdline: String,
    pub exe: String,
    pub cwd: String,
    pub username: String,
    pub open_files: Vec<String>,
    pub parent_chain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: i32,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub event_type: String,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub old_perms: Option<u32>,
    pub new_perms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub tactic: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEnrichment {
    pub full_cmdline: String,
    pub working_dir: String,
    pub env: HashMap<String, String>,
    pub open_fds: Vec<String>,
    pub memory_rss_kb: Option<u64>,
    pub memory_vmsize_kb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: EventType,
    pub threat_level: ThreatLevel,
    pub timestamp: DateTime<Utc>,
    pub narrative: String,
    pub process: Option<ProcessInfo>,
    pub connection: Option<NetConnection>,
    pub file_event: Option<FileEvent>,
    #[serde(default)]
    pub mitre: Vec<MitreMapping>,
    pub enrichment: Option<ProcessEnrichment>,
    pub response_taken: Option<String>,
    #[serde(default)]
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_reason: Option<String>,
}

impl SecurityEvent {
    pub fn new(event_type: EventType, threat_level: ThreatLevel, narrative: String) -> Self {
        Self {
            event_type,
            threat_level,
            timestamp: Utc::now(),
            narrative,
            process: None,
            connection: None,
            file_event: None,
            mitre: Vec::new(),
            enrichment: None,
            response_taken: None,
            allowed: false,
            allowed_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventType, SecurityEvent, ThreatLevel};

    #[test]
    fn threat_level_ordering() {
        assert!(ThreatLevel::Green < ThreatLevel::Yellow);
        assert!(ThreatLevel::Yellow < ThreatLevel::Orange);
        assert!(ThreatLevel::Orange < ThreatLevel::Red);
        assert!(ThreatLevel::Red < ThreatLevel::Nuclear);
    }

    #[test]
    fn security_event_serializes_to_json() {
        let event = SecurityEvent::new(
            EventType::CredentialAccess,
            ThreatLevel::Red,
            "credential file read".to_string(),
        );

        let value = serde_json::to_value(event).expect("security event should serialize");
        assert_eq!(value["event_type"], "credential_access");
        assert_eq!(value["threat_level"], "red");
        assert_eq!(value["narrative"], "credential file read");
        assert!(value.get("timestamp").is_some());
    }
}
