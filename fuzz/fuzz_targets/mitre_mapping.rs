#![no_main]

use leash::mitre;
use leash::models::{EventType, SecurityEvent, ThreatLevel};
use leash::fuzzing::fuzz_write_into_corpus;
use libfuzzer_sys::fuzz_target;

fn event_type_from_byte(byte: u8) -> EventType {
    match byte % 14 {
        0 => EventType::ProcessNew,
        1 => EventType::ProcessExit,
        2 => EventType::ProcessShellSpawn,
        3 => EventType::NetworkNewConnection,
        4 => EventType::NetworkSuspicious,
        5 => EventType::FileModified,
        6 => EventType::FileCreated,
        7 => EventType::FilePermissionChange,
        8 => EventType::CredentialAccess,
        9 => EventType::SelfTamper,
        10 => EventType::Persistence,
        11 => EventType::ContainerEscape,
        12 => EventType::VaultAccess,
        _ => EventType::PromptInjection,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let event_type = event_type_from_byte(data[0]);
    let narrative = String::from_utf8_lossy(&data[1..]).to_string();
    let event = SecurityEvent::new(event_type, ThreatLevel::Green, narrative);
    let tagged = mitre::infer_and_tag(event);
    if !tagged.mitre.is_empty() {
        let _ = fuzz_write_into_corpus("mitre_mapping", data);
    }
});
