use crate::models::{SecurityEvent, ThreatLevel};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use tokio::sync::broadcast;
use tracing::warn;

const STATS_FILE: &str = "/tmp/leash-stats.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub events_per_minute: f64,
    pub total_events: u64,
    pub events_by_severity: BTreeMap<String, u64>,
    pub events_by_type: BTreeMap<String, u64>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn track_events(mut rx: broadcast::Receiver<SecurityEvent>) -> anyhow::Result<()> {
    let mut state = StatsState::default();
    write_snapshot(&state.snapshot())?;

    loop {
        match rx.recv().await {
            Ok(event) => {
                state.record(&event);
                if let Err(err) = write_snapshot(&state.snapshot()) {
                    warn!(?err, "failed to write stats snapshot");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(lagged = n, "stats subscriber lagged");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

pub fn load_snapshot() -> anyhow::Result<Option<StatsSnapshot>> {
    if !Path::new(STATS_FILE).exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(STATS_FILE)?;
    let snapshot = serde_json::from_str::<StatsSnapshot>(&content)?;
    Ok(Some(snapshot))
}

fn write_snapshot(snapshot: &StatsSnapshot) -> anyhow::Result<()> {
    std::fs::write(STATS_FILE, serde_json::to_string_pretty(snapshot)?)?;
    Ok(())
}

#[derive(Default)]
struct StatsState {
    total_events: u64,
    events_by_severity: BTreeMap<String, u64>,
    events_by_type: BTreeMap<String, u64>,
    events_last_minute: VecDeque<chrono::DateTime<chrono::Utc>>,
}

impl StatsState {
    fn record(&mut self, event: &SecurityEvent) {
        self.total_events += 1;

        let severity = threat_level_as_str(event.threat_level).to_string();
        *self.events_by_severity.entry(severity).or_default() += 1;
        *self
            .events_by_type
            .entry(event.event_type.to_string())
            .or_default() += 1;

        let now = chrono::Utc::now();
        self.events_last_minute.push_back(now);
        self.trim_last_minute(now);
    }

    fn snapshot(&mut self) -> StatsSnapshot {
        let now = chrono::Utc::now();
        self.trim_last_minute(now);
        StatsSnapshot {
            events_per_minute: self.events_last_minute.len() as f64,
            total_events: self.total_events,
            events_by_severity: self.events_by_severity.clone(),
            events_by_type: self.events_by_type.clone(),
            updated_at: now,
        }
    }

    fn trim_last_minute(&mut self, now: chrono::DateTime<chrono::Utc>) {
        while let Some(front) = self.events_last_minute.front() {
            if *front < now - chrono::Duration::minutes(1) {
                let _ = self.events_last_minute.pop_front();
            } else {
                break;
            }
        }
    }
}

fn threat_level_as_str(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Green => "green",
        ThreatLevel::Yellow => "yellow",
        ThreatLevel::Orange => "orange",
        ThreatLevel::Red => "red",
        ThreatLevel::Nuclear => "nuclear",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventType, SecurityEvent, ThreatLevel};

    fn sample_event(level: ThreatLevel, event_type: EventType) -> SecurityEvent {
        SecurityEvent::new(event_type, level, "test event".to_string())
    }

    #[test]
    fn event_counting_updates_totals_and_buckets() {
        let mut state = StatsState::default();

        state.record(&sample_event(ThreatLevel::Yellow, EventType::ProcessNew));
        state.record(&sample_event(ThreatLevel::Red, EventType::CredentialAccess));
        state.record(&sample_event(ThreatLevel::Yellow, EventType::ProcessNew));

        let snapshot = state.snapshot();
        assert_eq!(snapshot.total_events, 3);
        assert_eq!(snapshot.events_by_severity.get("yellow"), Some(&2));
        assert_eq!(snapshot.events_by_severity.get("red"), Some(&1));
        assert_eq!(snapshot.events_by_type.get("process_new"), Some(&2));
        assert_eq!(snapshot.events_by_type.get("credential_access"), Some(&1));
    }

    #[test]
    fn events_per_minute_only_counts_recent_window() {
        let mut state = StatsState::default();
        let now = chrono::Utc::now();

        state.events_last_minute.push_back(now - chrono::Duration::seconds(61));
        state.events_last_minute.push_back(now - chrono::Duration::seconds(40));
        state.events_last_minute.push_back(now - chrono::Duration::seconds(5));

        let snapshot = state.snapshot();
        assert_eq!(snapshot.events_per_minute, 2.0);
    }
}
