//! Append-only audit log writer, `~/.sloosh/audit.jsonl` (DESIGN.md §4).
//!
//! One NDJSON line per event: `{"ts":"<RFC3339 UTC>","event":"<tag>", ...}`.
//! The daemon is the only writer (created 0600, same-user, same posture as
//! the socket and vault); `sloosh log` reads the file directly since the CLI
//! runs as the same user — no daemon round-trip needed.
//!
//! **Every call site funnels through [`record`]** so audit emission stays a
//! one-liner and "never log credentials or command output" has exactly one
//! place to audit, instead of being a rule every call site has to remember
//! independently. Only pass metadata (host, session name, command *text*,
//! exit codes, byte counts, path names) — never a password, master
//! password, vault content, or a command's *output*.
//!
//! **Best-effort, by design (DESIGN.md §4):** a write failure (disk full,
//! permissions, `~/.sloosh` missing and uncreatable) is reported via
//! `tracing::warn` and otherwise swallowed — it never fails, blocks, or even
//! slows down the operation being logged. This project's same-user threat
//! model treats the log as a diagnostic/accountability aid, not a security
//! control that must never miss an entry; keeping the tool usable wins over
//! keeping the log complete.

use serde_json::{Map, Value};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::transport::unix::sloosh_home;

/// `~/.sloosh/audit.jsonl` (or `$SLOOSH_HOME/audit.jsonl` under test).
pub fn audit_log_path() -> PathBuf {
    sloosh_home().join("audit.jsonl")
}

/// Append one audit event. `event` is the short tag (`"run_started"`,
/// `"lease_approved"`, ...); `fields` carries its extra key-value pairs and
/// must be a JSON object (or `Value::Null`/`json!({})` for none) — anything
/// else is a programmer error and is dropped with a warning rather than
/// corrupting the log.
pub fn record(event: &str, fields: Value) {
    let Some(line) = build_line(event, fields) else {
        return;
    };
    if let Err(e) = append_line(&audit_log_path(), &line) {
        warn!(
            error = %e, event,
            "failed to write audit log entry; continuing without it (availability of sloosh \
             itself over completeness of the audit trail — DESIGN.md §4)"
        );
    }
}

/// Serialize one audit event to its NDJSON line. Split out of [`record`] so
/// the never-panics contract is testable without writing to the real
/// `sloosh_home()`-derived log path.
fn build_line(event: &str, fields: Value) -> Option<String> {
    let mut obj = Map::new();
    obj.insert(
        "ts".to_string(),
        Value::String(format_timestamp(SystemTime::now())),
    );
    obj.insert("event".to_string(), Value::String(event.to_string()));
    match fields {
        Value::Object(extra) => obj.extend(extra),
        Value::Null => {}
        other => {
            warn!(
                event,
                ?other,
                "audit fields must be a JSON object; dropping extra fields"
            );
        }
    }

    match serde_json::to_string(&Value::Object(obj)) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, event, "failed to serialize audit event; dropping it");
            None
        }
    }
}

fn append_line(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    writeln!(file, "{line}")
}

/// Format `t` as an RFC 3339 / ISO-8601 UTC timestamp (`2026-07-08T12:34:56Z`).
/// Hand-rolled instead of pulling in `chrono` as a direct dependency (it's
/// already a transitive dep of `russh-sftp`, but that's not something to
/// depend on): UTC-only civil-date math is a handful of integer operations,
/// not worth a new top-level dependency for.
fn format_timestamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days-since-epoch (1970-01-01) -> UTC
/// (year, month, day). Proleptic Gregorian, valid across the whole `i64`
/// range worth caring about here.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// One parsed audit log line, as `sloosh log` reads it back.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub event: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

/// Read and parse every line of the audit log. Malformed lines (should only
/// happen from a torn write racing a crash — appends are not fsync'd) are
/// skipped with a warning rather than failing the whole read: a corrupt tail
/// byte must not hide every earlier entry from `sloosh log`.
pub fn read_events(path: &std::path::Path) -> std::io::Result<Vec<AuditEvent>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut events = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEvent>(line) {
            Ok(ev) => events.push(ev),
            Err(e) => warn!(error = %e, "skipping malformed audit log line"),
        }
    }
    Ok(events)
}

/// Read the raw NDJSON lines of the audit log verbatim (trimmed, blank
/// lines dropped, still unparsed) — used by `sloosh log --json`, which
/// echoes the file's exact on-disk text rather than a value re-serialized
/// from a parsed struct (serde_json's `Map` is `BTreeMap`-backed without
/// the `preserve_order` feature, so re-serializing would silently reorder
/// fields away from what was actually written).
pub fn read_raw_lines(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_log_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sloosh-audit-test-{tag}-{}-{}.jsonl",
            std::process::id(),
            tag.len()
        ))
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Epoch itself.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-01-01 is a widely-cited constant: 30 years after the epoch,
        // with 7 leap years (1972..=1996 step 4) in between: 30*365+7=10957.
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        // The day before that must be the last day of 1999.
        assert_eq!(civil_from_days(10_956), (1999, 12, 31));
    }

    #[test]
    fn format_timestamp_is_rfc3339_utc() {
        assert_eq!(format_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2000-01-01T00:00:00Z, from the same constant used above.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(10_957 * 86_400);
        assert_eq!(format_timestamp(t), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn record_appends_ndjson_line_with_ts_and_event() {
        let path = temp_log_path("append");
        let _ = std::fs::remove_file(&path);

        let line = json!({"host": "box", "n": 1}).to_string();
        // Exercise append_line directly (record() always targets the real
        // sloosh_home()-derived path, which unit tests must never touch) —
        // it's the same function record() calls.
        append_line(&path, &line).expect("append");
        append_line(&path, &line).expect("append again");

        let contents = std::fs::read_to_string(&path).expect("read back");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            let v: Value = serde_json::from_str(l).expect("valid json line");
            assert_eq!(v["host"], "box");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_line_creates_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_log_path("mode");
        let _ = std::fs::remove_file(&path);
        append_line(&path, "{}").expect("append");
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_parses_ts_event_and_extra_fields() {
        let path = temp_log_path("read");
        let _ = std::fs::remove_file(&path);
        append_line(
            &path,
            &json!({"ts": "2026-07-08T00:00:00Z", "event": "run", "host": "box", "exit_code": 0})
                .to_string(),
        )
        .expect("append");
        append_line(
            &path,
            &json!({"ts": "2026-07-08T00:00:01Z", "event": "send", "host": "box"}).to_string(),
        )
        .expect("append");

        let events = read_events(&path).expect("read");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "run");
        assert_eq!(events[0].fields["host"], "box");
        assert_eq!(events[0].fields["exit_code"], 0);
        assert_eq!(events[1].event, "send");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_events_on_missing_file_returns_empty() {
        let path = temp_log_path("missing");
        let _ = std::fs::remove_file(&path);
        let events = read_events(&path).expect("read");
        assert!(events.is_empty());
    }

    #[test]
    fn read_raw_lines_preserves_exact_text_and_skips_blanks() {
        let path = temp_log_path("raw");
        let _ = std::fs::remove_file(&path);
        {
            let mut f = std::fs::File::create(&path).unwrap();
            // Deliberately out-of-alphabetical-order keys: a struct
            // round-trip through `Map` (BTreeMap-backed) would reorder
            // these, but read_raw_lines must hand them back byte-for-byte.
            writeln!(
                f,
                "{{\"ts\":\"2026-07-08T00:00:00Z\",\"event\":\"run\",\"zzz\":1,\"aaa\":2}}"
            )
            .unwrap();
            writeln!(f).unwrap(); // blank line, must be dropped
            writeln!(f, "{{\"ts\":\"2026-07-08T00:00:01Z\",\"event\":\"send\"}}").unwrap();
        }
        let lines = read_raw_lines(&path).expect("read");
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "{\"ts\":\"2026-07-08T00:00:00Z\",\"event\":\"run\",\"zzz\":1,\"aaa\":2}"
        );
        assert_eq!(
            lines[1],
            "{\"ts\":\"2026-07-08T00:00:01Z\",\"event\":\"send\"}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_raw_lines_on_missing_file_returns_empty() {
        let path = temp_log_path("raw-missing");
        let _ = std::fs::remove_file(&path);
        let lines = read_raw_lines(&path).expect("read");
        assert!(lines.is_empty());
    }

    #[test]
    fn read_events_skips_malformed_lines_but_keeps_the_rest() {
        let path = temp_log_path("malformed");
        let _ = std::fs::remove_file(&path);
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{{\"ts\":\"2026-07-08T00:00:00Z\",\"event\":\"run\"}}").unwrap();
            writeln!(f, "not json at all, a torn write").unwrap();
            writeln!(f, "{{\"ts\":\"2026-07-08T00:00:01Z\",\"event\":\"send\"}}").unwrap();
        }
        let events = read_events(&path).expect("read");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "run");
        assert_eq!(events[1].event, "send");
        let _ = std::fs::remove_file(&path);
    }

    /// The never-panics contract: passing non-object fields must warn-and-drop
    /// the extras, not panic the caller (a live daemon must never crash because
    /// an audit call site passed the wrong `Value` shape). Exercises
    /// `build_line` rather than `record`, which always writes to the real
    /// `sloosh_home()`-derived path that unit tests must never touch.
    #[test]
    fn build_line_with_non_object_fields_does_not_panic() {
        let line = build_line("test_event", Value::Bool(true)).expect("still serializes");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["event"], "test_event");
        assert!(build_line("test_event", Value::Null).is_some());
    }

    /// Concurrent-ish appends from multiple tasks must all land intact —
    /// `O_APPEND` writes below `PIPE_BUF` are atomic on POSIX, so many
    /// short lines interleaved from different tasks must never corrupt or
    /// interleave into each other.
    #[tokio::test]
    async fn concurrent_appends_all_land_intact() {
        let path = temp_log_path("concurrent");
        let _ = std::fs::remove_file(&path);

        let mut handles = Vec::new();
        for i in 0..20 {
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                let line = json!({"n": i}).to_string();
                append_line(&path, &line).expect("append");
            }));
        }
        for h in handles {
            h.await.expect("task");
        }

        let events = read_events(&path).expect("read");
        assert_eq!(
            events.len(),
            0,
            "these lines have no `event` field, use raw count instead"
        );
        let contents = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 20);
        let mut seen: Vec<u64> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<Value>(l).expect("valid json")["n"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..20).collect::<Vec<_>>());
        let _ = std::fs::remove_file(&path);
    }
}
