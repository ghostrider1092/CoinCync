//! End-to-end DAP test: script a client conversation through the Session over
//! in-memory buffers and assert the adapter behaves like a real debugger —
//! advertises its capabilities, hits the difficulty-floor breakpoint, and
//! exposes the decoded consensus state. No process spawn, no IDE needed.

use coincync_dbg::engine::ReplayEngine;
use coincync_dbg::protocol::{read_message, write_message};
use coincync_dbg::session::Session;
use serde_json::{json, Value};
use std::io::Cursor;

/// Frame a request into the input stream.
fn req(buf: &mut Vec<u8>, seq: i64, command: &str, arguments: Value) {
    let msg = json!({
        "seq": seq, "type": "request", "command": command, "arguments": arguments
    });
    write_message(buf, &msg).unwrap();
}

/// Parse every DAP message the adapter wrote.
fn drain(output: Vec<u8>) -> Vec<Value> {
    let mut cur = Cursor::new(output);
    let mut out = Vec::new();
    while let Some(m) = read_message(&mut cur).unwrap() {
        out.push(m);
    }
    out
}

fn find_response<'a>(msgs: &'a [Value], command: &str) -> Option<&'a Value> {
    msgs.iter().find(|m| {
        m.get("type").and_then(Value::as_str) == Some("response")
            && m.get("command").and_then(Value::as_str) == Some(command)
    })
}

fn events<'a>(msgs: &'a [Value], event: &str) -> Vec<&'a Value> {
    msgs.iter()
        .filter(|m| {
            m.get("type").and_then(Value::as_str) == Some("event")
                && m.get("event").and_then(Value::as_str) == Some(event)
        })
        .collect()
}

#[test]
fn full_session_hits_difficulty_floor_and_exposes_state() {
    // ── Script the client side ────────────────────────────────────────────
    let mut input = Vec::new();
    req(&mut input, 1, "initialize", json!({ "adapterID": "coincync-dbg" }));
    req(&mut input, 2, "setExceptionBreakpoints", json!({ "filters": ["difficulty-floor"] }));
    req(&mut input, 3, "configurationDone", json!({}));
    req(&mut input, 4, "launch", json!({}));
    req(&mut input, 5, "threads", json!({}));
    req(&mut input, 6, "stackTrace", json!({ "threadId": 1 }));
    req(&mut input, 7, "scopes", json!({ "frameId": 1 }));
    req(&mut input, 8, "variables", json!({ "variablesReference": 1000 }));
    req(&mut input, 9, "disconnect", json!({}));

    // ── Run the adapter ───────────────────────────────────────────────────
    let mut reader = Cursor::new(input);
    let mut output: Vec<u8> = Vec::new();
    let engine = ReplayEngine::demo_floor_scenario();
    Session::new(engine, "scenario.ccscenario")
        .run(&mut reader, &mut output)
        .unwrap();
    let msgs = drain(output);

    // ── initialize advertises the difficulty-floor exception filter ───────
    let init = find_response(&msgs, "initialize").expect("initialize response");
    assert_eq!(
        init.pointer("/body/supportsConfigurationDoneRequest"),
        Some(&json!(true))
    );
    let filters = init
        .pointer("/body/exceptionBreakpointFilters")
        .and_then(Value::as_array)
        .expect("exception filters");
    assert!(
        filters.iter().any(|f| f.get("filter").and_then(Value::as_str) == Some("difficulty-floor")),
        "must advertise the difficulty-floor breakpoint filter"
    );
    // The client is told it can configure after initialize.
    assert_eq!(events(&msgs, "initialized").len(), 1);

    // ── launch replays and the floor breakpoint fires ────────────────────
    let stops = events(&msgs, "stopped");
    assert!(
        stops.iter().any(|e| e.pointer("/body/reason") == Some(&json!("exception"))),
        "a difficulty-floor exception stop must fire; got: {stops:?}"
    );

    // ── threads / stackTrace shape ───────────────────────────────────────
    let threads = find_response(&msgs, "threads").expect("threads response");
    assert_eq!(threads.pointer("/body/threads/0/id"), Some(&json!(1)));
    let st = find_response(&msgs, "stackTrace").expect("stackTrace response");
    assert!(st.pointer("/body/stackFrames/0/line").and_then(Value::as_i64).unwrap() >= 2);

    // ── variables decode the REAL consensus state at the floor ───────────
    let vars = find_response(&msgs, "variables").expect("variables response");
    let arr = vars.pointer("/body/variables").and_then(Value::as_array).expect("variables");
    let get = |name: &str| -> String {
        arr.iter()
            .find(|v| v.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|v| v.get("value").and_then(Value::as_str))
            .unwrap_or("")
            .to_string()
    };
    assert_eq!(get("at_floor"), "true", "the stop must be AT the floor");
    let difficulty: u128 = get("difficulty").parse().expect("difficulty is a number");
    let floor: u128 = get("floor_threshold").parse().expect("floor is a number");
    assert!(
        difficulty <= floor,
        "difficulty {difficulty} must be <= floor_threshold {floor} at the breakpoint"
    );
    assert!(get("target").starts_with("0x"), "target decoded as hex");
    assert!(!get("height").is_empty(), "height present");
}

#[test]
fn line_breakpoint_pauses_at_that_block() {
    // Set a line breakpoint on block[2] (source line 4) and confirm the adapter
    // pauses there with reason "breakpoint", before the floor.
    let mut input = Vec::new();
    req(&mut input, 1, "initialize", json!({}));
    // Disable the floor filter so the line breakpoint is what stops us.
    req(&mut input, 2, "setExceptionBreakpoints", json!({ "filters": [] }));
    req(&mut input, 3, "setBreakpoints",
        json!({ "source": { "path": "scenario.ccscenario" }, "breakpoints": [{ "line": 4 }] }));
    req(&mut input, 4, "configurationDone", json!({}));
    req(&mut input, 5, "launch", json!({}));
    req(&mut input, 6, "stackTrace", json!({ "threadId": 1 }));
    req(&mut input, 7, "disconnect", json!({}));

    let mut reader = Cursor::new(input);
    let mut output: Vec<u8> = Vec::new();
    Session::new(ReplayEngine::demo_floor_scenario(), "scenario.ccscenario")
        .run(&mut reader, &mut output)
        .unwrap();
    let msgs = drain(output);

    let stops = events(&msgs, "stopped");
    assert!(
        stops.iter().any(|e| e.pointer("/body/reason") == Some(&json!("breakpoint"))),
        "line breakpoint must produce a breakpoint stop; got {stops:?}"
    );
    let st = find_response(&msgs, "stackTrace").expect("stackTrace");
    assert_eq!(st.pointer("/body/stackFrames/0/line"), Some(&json!(4)),
        "must pause on the line the breakpoint was set");
}
