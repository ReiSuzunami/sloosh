//! Human and NDJSON audit-log rendering.

use super::args::LogArgs;
use crate::daemon::audit;

pub(super) async fn cmd_log(args: LogArgs) -> anyhow::Result<()> {
    let path = audit::audit_log_path();
    let raw_lines = audit::read_raw_lines(&path).map_err(|error| {
        anyhow::anyhow!("could not read audit log at {}: {error}", path.display())
    })?;

    let mut parsed: Vec<(String, serde_json::Value)> = Vec::new();
    for line in raw_lines {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            parsed.push((line, value));
        }
    }

    let filtered: Vec<(String, serde_json::Value)> = parsed
        .into_iter()
        .filter(|(_, value)| {
            args.host
                .as_deref()
                .is_none_or(|host| value.get("host").and_then(|field| field.as_str()) == Some(host))
        })
        .collect();

    let start = filtered.len().saturating_sub(args.count);
    let tail = &filtered[start..];

    if tail.is_empty() {
        match &args.host {
            Some(host) => println!("no audit log entries for host '{host}'"),
            None => println!("no audit log entries yet (~/.sloosh/audit.jsonl)"),
        }
        return Ok(());
    }

    if args.json {
        for (raw, _) in tail {
            println!("{raw}");
        }
    } else {
        for (_, value) in tail {
            print_audit_event_human(value);
        }
    }
    Ok(())
}

fn print_audit_event_human(value: &serde_json::Value) {
    let timestamp = value
        .get("ts")
        .and_then(|field| field.as_str())
        .unwrap_or("?");
    let event = value
        .get("event")
        .and_then(|field| field.as_str())
        .unwrap_or("?");
    let mut fields = String::new();
    if let Some(object) = value.as_object() {
        let mut keys: Vec<&String> = object
            .keys()
            .filter(|key| *key != "ts" && *key != "event")
            .collect();
        keys.sort();
        for key in keys {
            fields.push_str(&format!(" {key}={}", render_field_value(&object[key])));
        }
    }
    println!("{timestamp}  {event}{fields}");
}

pub(super) fn render_field_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(string) => format!("{string:?}"),
        other => other.to_string(),
    }
}
