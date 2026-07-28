//! Human and NDJSON audit-log rendering.

use super::args::LogArgs;
use crate::daemon::audit;

pub(super) async fn cmd_log(args: LogArgs) -> anyhow::Result<()> {
    let path = audit::audit_log_path();
    let raw_events = audit::read_validated_raw_events(&path).map_err(|error| {
        anyhow::anyhow!("could not read audit log at {}: {error}", path.display())
    })?;

    let filtered: Vec<(String, serde_json::Value)> = raw_events
        .into_iter()
        .filter(|event| {
            args.host.as_deref().is_none_or(|host| {
                event.value.get("host").and_then(|field| field.as_str()) == Some(host)
            })
        })
        .map(|event| (event.raw, event.value))
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
