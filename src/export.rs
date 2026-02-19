use crate::history;
use crate::models::ThreatLevel;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExportFormat {
    Json,
    Csv,
}

impl ExportFormat {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            _ => Err(anyhow::anyhow!(
                "invalid --format value: {raw} (use json or csv)"
            )),
        }
    }
}

pub fn export_events(
    format: ExportFormat,
    last: Option<&str>,
    severity: Option<&str>,
) -> anyhow::Result<()> {
    let severity_filter = parse_export_severity(severity)?;
    let events = history::load_security_events(last, severity_filter.as_deref())?;

    match format {
        ExportFormat::Json => {
            for event in events {
                println!("{}", serde_json::to_string(&event)?);
            }
        }
        ExportFormat::Csv => {
            println!(
                "timestamp,event_type,threat_level,narrative,pid,process_name,allowed,allowed_reason"
            );
            for event in events {
                let pid = event
                    .process
                    .as_ref()
                    .map(|process| process.pid.to_string())
                    .unwrap_or_default();
                let process_name = event
                    .process
                    .as_ref()
                    .map(|process| process.name.clone())
                    .unwrap_or_default();
                println!(
                    "{},{},{},{},{},{},{},{}",
                    csv_cell(&event.timestamp.to_rfc3339()),
                    csv_cell(&event.event_type.to_string()),
                    csv_cell(threat_level_as_str(event.threat_level)),
                    csv_cell(&event.narrative),
                    csv_cell(&pid),
                    csv_cell(&process_name),
                    csv_cell(if event.allowed { "true" } else { "false" }),
                    csv_cell(event.allowed_reason.as_deref().unwrap_or_default()),
                );
            }
        }
    }

    Ok(())
}

fn parse_export_severity(severity: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = severity else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "green" | "yellow" | "orange" | "red" => Ok(Some(normalized)),
        _ => Err(anyhow::anyhow!(
            "invalid --severity value: {value} (use green|yellow|orange|red)"
        )),
    }
}

fn csv_cell(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
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
    use super::{csv_cell, parse_export_severity};

    #[test]
    fn csv_cell_escapes_commas_quotes_and_newlines() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn export_severity_accepts_expected_values() {
        assert_eq!(
            parse_export_severity(Some("red")).expect("red should parse"),
            Some("red".to_string())
        );
        assert!(parse_export_severity(Some("nuclear")).is_err());
        assert!(parse_export_severity(Some("wat")).is_err());
    }
}
