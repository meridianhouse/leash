use crate::models::{SecurityEvent, ThreatLevel};
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;
use tracing::warn;

#[derive(Debug, Clone, serde::Serialize)]
struct HistoryRecord {
    timestamp: chrono::DateTime<chrono::Utc>,
    severity: String,
    event_type: String,
    narrative: String,
    allowed: bool,
}

#[derive(Debug)]
struct StoredEvent {
    timestamp: String,
    severity: String,
    event_type: String,
    narrative: String,
    payload_json: String,
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
    let records = query_records(&conn, last, severity, Some(200))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No history events found");
    } else {
        for record in records {
            println!(
                "{} [{}]{} {} {}",
                record
                    .timestamp
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S"),
                record.severity.to_uppercase(),
                if record.allowed { " [ALLOWED]" } else { "" },
                record.event_type,
                record.narrative
            );
        }
    }

    Ok(())
}

pub fn load_security_events(
    last: Option<&str>,
    severity: Option<&str>,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let conn = open_db()?;
    query_security_events(&conn, last, severity, None)
}

pub fn open_db() -> anyhow::Result<Connection> {
    let path = db_path()?;
    open_db_at(&path)
}

fn open_db_at(path: &Path) -> anyhow::Result<Connection> {
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
    insert_event(&conn, event)
}

fn insert_event(conn: &Connection, event: &SecurityEvent) -> anyhow::Result<()> {
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

fn query_records(
    conn: &Connection,
    last: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
) -> anyhow::Result<Vec<HistoryRecord>> {
    let rows = query_stored_events(conn, last, severity, limit)?;
    let mut records = Vec::with_capacity(rows.len());

    for row in rows {
        let event = serde_json::from_str::<SecurityEvent>(&row.payload_json)?;
        let timestamp =
            chrono::DateTime::parse_from_rfc3339(&row.timestamp)?.with_timezone(&chrono::Utc);
        records.push(HistoryRecord {
            timestamp,
            severity: row.severity,
            event_type: row.event_type,
            narrative: row.narrative,
            allowed: event.allowed,
        });
    }

    Ok(records)
}

fn query_security_events(
    conn: &Connection,
    last: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let rows = query_stored_events(conn, last, severity, limit)?;
    let mut events = Vec::with_capacity(rows.len());

    for row in rows {
        events.push(serde_json::from_str::<SecurityEvent>(&row.payload_json)?);
    }

    Ok(events)
}

fn query_stored_events(
    conn: &Connection,
    last: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
) -> anyhow::Result<Vec<StoredEvent>> {
    let mut query = String::from(
        "SELECT timestamp, severity, event_type, narrative, payload_json FROM events WHERE 1=1",
    );
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

    query.push_str(" ORDER BY timestamp DESC");
    if let Some(value) = limit {
        query.push_str(&format!(" LIMIT {value}"));
    }

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
        Ok(StoredEvent {
            timestamp: row.get(0)?,
            severity: row.get(1)?,
            event_type: row.get(2)?,
            narrative: row.get(3)?,
            payload_json: row.get(4)?,
        })
    })?;

    let mut records = Vec::new();
    for item in rows {
        records.push(item?);
    }

    Ok(records)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventType, SecurityEvent, ThreatLevel};

    fn temp_db_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "leash-history-{label}-{}-{nanos}.db",
            std::process::id()
        ))
    }

    fn sample_event(
        timestamp: chrono::DateTime<chrono::Utc>,
        level: ThreatLevel,
        narrative: &str,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ProcessNew, level, narrative.to_string());
        event.timestamp = timestamp;
        event
    }

    #[test]
    fn sqlite_db_creation_creates_schema() {
        let db_path = temp_db_path("create");
        let conn = open_db_at(&db_path).expect("open db");

        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='events'",
                [],
                |row| row.get(0),
            )
            .expect("table query");
        assert_eq!(table_exists, 1);

        let idx_exists: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name='idx_events_timestamp'",
                [],
                |row| row.get(0),
            )
            .expect("index query");
        assert_eq!(idx_exists, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn event_insertion_persists_row() {
        let db_path = temp_db_path("insert");
        let conn = open_db_at(&db_path).expect("open db");

        let event = sample_event(chrono::Utc::now(), ThreatLevel::Yellow, "insert me");
        insert_event(&conn, &event).expect("insert event");

        let count: i64 = conn
            .query_row("SELECT COUNT(1) FROM events", [], |row| row.get(0))
            .expect("count rows");
        assert_eq!(count, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn query_by_time_range_filters_older_events() {
        let db_path = temp_db_path("time-range");
        let conn = open_db_at(&db_path).expect("open db");

        let old_event = sample_event(
            chrono::Utc::now() - chrono::Duration::hours(30),
            ThreatLevel::Green,
            "old event",
        );
        let recent_event = sample_event(
            chrono::Utc::now() - chrono::Duration::minutes(10),
            ThreatLevel::Yellow,
            "recent event",
        );

        insert_event(&conn, &old_event).expect("insert old");
        insert_event(&conn, &recent_event).expect("insert recent");

        let rows = query_records(&conn, Some("24h"), None, None).expect("query records");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].narrative, "recent event");

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn query_by_severity_filters_results() {
        let db_path = temp_db_path("severity");
        let conn = open_db_at(&db_path).expect("open db");

        let yellow_event = sample_event(chrono::Utc::now(), ThreatLevel::Yellow, "yellow event");
        let red_event = sample_event(chrono::Utc::now(), ThreatLevel::Red, "red event");
        insert_event(&conn, &yellow_event).expect("insert yellow");
        insert_event(&conn, &red_event).expect("insert red");

        let rows = query_records(&conn, None, Some("yellow"), None).expect("query severity");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].severity, "yellow");
        assert_eq!(rows[0].narrative, "yellow event");

        let _ = std::fs::remove_file(db_path);
    }
}
