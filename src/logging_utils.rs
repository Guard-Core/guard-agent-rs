//! The agent's log-record formatters, ported from the reference
//! `logging_utils.py` (`JsonFormatter` + the text layout).
//!
//! The reference's `setup_agent_logging` wires Python's logging registry
//! (console + file handlers, the yield-to-host-root filter, the
//! reconfigure dance). Rust's `log` facade has no registry for this crate
//! to own - the host subscriber formats through its own machinery - so
//! the portable half is the record rendering: [`json_record`] (the
//! `JsonFormatter` four-field shape in reference key order) and
//! [`text_record`] (the `[%(name)s] %(asctime)s - %(levelname)s -
//! %(message)s` layout), plus [`asctime`] (the python-logging
//! `formatTime` shape both formatters emit).
//!
//! # Example
//!
//! ```
//! use guard_agent_rs::logging_utils::{asctime, json_record, text_record};
//!
//! let stamp = asctime(1_700_000_000, 250);
//! assert_eq!(stamp, "2023-11-14 22:13:20,250");
//! assert_eq!(
//!     json_record("INFO", "guard_agent", "started", &stamp),
//!     r#"{"timestamp": "2023-11-14 22:13:20,250", "level": "INFO", "logger": "guard_agent", "message": "started"}"#
//! );
//! assert_eq!(
//!     text_record("INFO", "guard_agent", "started", &stamp),
//!     "[guard_agent] 2023-11-14 22:13:20,250 - INFO - started"
//! );
//! ```

/// The python-logging `formatTime` shape: `YYYY-MM-DD HH:MM:SS,mmm` in
/// UTC (the reference's default `time.time()`-derived stamp).
#[must_use]
pub fn asctime(unix_seconds: i64, millis: u32) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02},{millis:03}",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: the proleptic Gregorian date for
/// days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        (if m <= 2 { y + 1 } else { y }),
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// The `JsonFormatter.format` shape: exactly four fields in reference key
/// order (`timestamp`, `level`, `logger`, `message`), JSON-encoded.
#[must_use]
pub fn json_record(level: &str, logger: &str, message: &str, timestamp: &str) -> String {
    // The reference `json.dumps` separator shapes (`, ` between fields, `: `
    // after keys), the fields emitted in reference key order.
    format!(
        "{{\"timestamp\": {}, \"level\": {}, \"logger\": {}, \"message\": {}}}",
        json_string(timestamp),
        json_string(level),
        json_string(logger),
        json_string(message)
    )
}

/// `json.dumps`' string encoding for the four record fields (the two
/// mandatory controls, backslash, and the quote).
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The text layout: `[%(name)s] %(asctime)s - %(levelname)s -
/// %(message)s`.
#[must_use]
pub fn text_record(level: &str, logger: &str, message: &str, timestamp: &str) -> String {
    format!("[{logger}] {timestamp} - {level} - {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asctime_renders_the_python_shape() {
        assert_eq!(asctime(1_700_000_000, 250), "2023-11-14 22:13:20,250");
        assert_eq!(asctime(0, 0), "1970-01-01 00:00:00,000");
        // A leap-year date exercises the civil conversion.
        assert_eq!(asctime(1_709_164_800, 1), "2024-02-29 00:00:00,001");
    }

    #[test]
    fn json_record_carries_the_four_reference_fields_in_order() {
        let record = json_record(
            "ERROR",
            "guard_agent",
            "flush failed: backend down",
            "2026-10-08 12:00:00,123",
        );
        assert!(
            record.starts_with(r#"{"timestamp": "2026-10-08 12:00:00,123""#),
            "{record}"
        );
        assert!(record.contains(r#""level": "ERROR""#), "{record}");
        assert!(record.contains(r#""logger": "guard_agent""#), "{record}");
        assert!(
            record.ends_with(r#""message": "flush failed: backend down"}"#),
            "{record}"
        );
    }

    #[test]
    fn json_string_escapes_the_control_family() {
        // The escaping arms: quote, backslash, newline, carriage return,
        // tab, and a raw control character.
        assert_eq!(
            json_string("a\"b\\c\nd\r\te\u{1}"),
            "\"a\\\"b\\\\c\\nd\\r\\te\\u0001\""
        );
        assert_eq!(json_string("plain"), "\"plain\"");
    }

    #[test]
    fn text_record_renders_the_reference_layout() {
        assert_eq!(
            text_record(
                "INFO",
                "guard_agent",
                "flushed 3 events",
                "2026-10-08 12:00:00,123"
            ),
            "[guard_agent] 2026-10-08 12:00:00,123 - INFO - flushed 3 events"
        );
    }
}
