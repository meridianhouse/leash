use crate::models::{SecurityEvent, ThreatLevel};
use rusqlite::{Connection, params};
use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::warn;

#[derive(serde::Serialize)]
struct HistoryRecord {
    timestamp: chrono::DateTime<chrono::Utc>,
    severity: String,
    event_type: String,
    narrative: String,
}

pub async fn record_events(mut rx: broadcast::Receiver<SecurityEvent>) -> anyhow::Result<()> {
    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Err(err) = store_event(&event) {
                    warn!(?err, "failed to write event history");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(lagged = n, "history subscriber lagged");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

pub fn print_history(
    last: Option<&str>,
    severity: Option<&str>,
    json_output: bool,
) -> anyhow::Result<()> {
    let conn = open_db()?;
    let mut query =
        String::from("SELECT timestamp, severity, event_type, narrative FROM events WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(duration) = parse_last_filter(last)? {
        let threshold = chrono::Utc::now() - duration;
        query.push_str(" AND timestamp >= ?");
        args.push(threshold.to_rfc3339());
    }

    if let Some(sev) = parse_severity_filter(severity)? {
        query.push_str(" AND severity = ?");
        args.push(sev);
    }

    query.push_str(" ORDER BY timestamp DESC LIMIT 200");

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
        Ok(HistoryRecord {
            timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(0)?)
                .map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?
                .with_timezone(&chrono::Utc),
            severity: row.get(1)?,
            event_type: row.get(2)?,
            narrative: row.get(3)?,
        })
    })?;

    let mut records = Vec::new();
    for item in rows {
        records.push(item?);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No history events found");
    } else {
        for record in records {
            println!(
                "{} [{}] {} {}",
                record
                    .timestamp
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S"),
                record.severity.to_uppercase(),
                record.event_type,
                record.narrative
            );
        }
    }

    Ok(())
}

pub fn open_db() -> anyhow::Result<Connection> {
    let path = db_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            narrative TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);",
    )?;

    Ok(conn)
}

pub fn db_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share/leash/events.db"))
}

pub fn store_event(event: &SecurityEvent) -> anyhow::Result<()> {
    let conn = open_db()?;
    conn.execute(
        "INSERT INTO events (timestamp, severity, event_type, narrative, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event.timestamp.to_rfc3339(),
            threat_level_as_str(event.threat_level),
            event.event_type.to_string(),
            event.narrative,
            serde_json::to_string(event)?,
        ],
    )?;
    Ok(())
}

fn parse_last_filter(last: Option<&str>) -> anyhow::Result<Option<chrono::Duration>> {
    let Some(value) = last else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1h" => Ok(Some(chrono::Duration::hours(1))),
        "24h" => Ok(Some(chrono::Duration::hours(24))),
        _ => Err(anyhow::anyhow!(
            "invalid --last value: {value} (use 1h or 24h)"
        )),
    }
}

fn parse_severity_filter(severity: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = severity else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "green" | "yellow" | "orange" | "red" | "nuclear" => Ok(Some(normalized)),
        _ => Err(anyhow::anyhow!(
            "invalid --severity value: {value} (use green|yellow|orange|red|nuclear)"
        )),
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
