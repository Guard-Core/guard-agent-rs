//! Redaction parity with the Python agent's `sanitize_headers`.
//!
//! The expected values in `fixtures/sanitize_vectors.json` were produced by
//! running `guard_agent.utils.sanitize_headers` (guard-agent master) on the
//! same inputs with the same sensitive-key list, so every case is a
//! cross-language pin: depth-bounded recursion with wholesale redaction past
//! the bound, JSON-looking string values parsed, sanitized and re-dumped with
//! Python's `json.dumps` defaults, and oversized JSON-looking strings
//! redacted wholesale.

use std::collections::BTreeMap;

use guard_agent_rs::utils::Redactor;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("fixtures/sanitize_vectors.json");

fn load() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("vector fixtures parse")
}

fn redactor(vectors: &Value) -> Redactor {
    let keys: Vec<String> = vectors["sensitive"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    Redactor::new(&keys)
}

#[test]
fn every_case_matches_the_python_reference() {
    let vectors = load();
    let redactor = redactor(&vectors);
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let mut value = case["input"].clone();
        redactor.redact_value(&mut value);
        assert_eq!(value, case["expected"], "case {}", case["name"]);
        // The embedded JSON strings must match byte for byte too, which Value
        // equality already guarantees for strings.
    }
}

#[test]
fn tags_match_the_python_reference() {
    let vectors = load();
    let redactor = redactor(&vectors);
    let case = &vectors["tags"];
    let mut tags: BTreeMap<String, String> = case["input"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
        .collect();
    redactor.redact_tags(&mut tags);
    let actual = serde_json::to_value(&tags).unwrap();
    assert_eq!(actual, case["expected"]);
}

#[test]
fn nothing_deeper_than_the_bound_survives() {
    let vectors = load();
    let redactor = redactor(&vectors);
    let mut value = serde_json::json!({"password": "top"});
    for _ in 0..40 {
        value = serde_json::json!({"wrap": value, "side": "visible"});
    }
    redactor.redact_value(&mut value);
    let dumped = value.to_string();
    assert!(!dumped.contains("top"));
}

#[test]
fn json_strings_the_parser_cannot_digest_never_leak_a_secret() {
    let vectors = load();
    let redactor = redactor(&vectors);
    // A lone surrogate escape parses in Python (which then redacts the
    // password) but not in serde_json: the string must be redacted wholesale
    // instead of passing through with the password intact.
    let mut value = serde_json::json!({
        "lone_surrogate": r#"{"a": "\ud800", "password": "hunter2"}"#,
        "too_deep": format!("{}{}", "[".repeat(300), "]".repeat(300)),
    });
    redactor.redact_value(&mut value);
    assert_eq!(value["lone_surrogate"], "[REDACTED]");
    assert_eq!(value["too_deep"], "[REDACTED]");
}
