//! The DAP session: dispatch Debug Adapter Protocol requests against the
//! difficulty [`ReplayEngine`]. Minimal but real — enough that any DAP client
//! (VS Code, Neovim, JetBrains) drives it as a native debugger.
//!
//! Supported: initialize, launch, setBreakpoints (lines on the scenario
//! "source"), setExceptionBreakpoints (the `difficulty-floor` filter),
//! configurationDone, threads, stackTrace, scopes, variables, continue,
//! next/stepIn/stepOut, disconnect/terminate.
//!
//! Not yet: stepBack/reverseContinue (needs the replay-from-start plumbing — a
//! deliberate next increment), multiple threads, data breakpoints.

use crate::engine::{ReplayEngine, StepState};
use crate::protocol::{read_message, write_message};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// The single logical thread the replay runs on.
const THREAD_ID: i64 = 1;
/// variablesReference for the one "Block State" scope.
const BLOCK_SCOPE_REF: i64 = 1000;
/// Line 1 of the generated source is the scenario header; block `i` is line i+2.
fn block_line(index: usize) -> i64 {
    index as i64 + 2
}

pub struct Session {
    engine: ReplayEngine,
    source_path: String,
    seq: i64,
    line_breakpoints: Vec<i64>,
    floor_filter_enabled: bool,
}

impl Session {
    pub fn new(engine: ReplayEngine, source_path: impl Into<String>) -> Self {
        Session {
            engine,
            source_path: source_path.into(),
            seq: 1,
            line_breakpoints: Vec::new(),
            // On by default — the headline semantic breakpoint.
            floor_filter_enabled: true,
        }
    }

    fn next_seq(&mut self) -> i64 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    fn send_response<W: Write>(
        &mut self,
        w: &mut W,
        request: &Value,
        body: Value,
    ) -> std::io::Result<()> {
        let seq = self.next_seq();
        let msg = json!({
            "seq": seq,
            "type": "response",
            "request_seq": request.get("seq").cloned().unwrap_or(Value::Null),
            "success": true,
            "command": request.get("command").cloned().unwrap_or(Value::Null),
            "body": body,
        });
        write_message(w, &msg)
    }

    fn send_event<W: Write>(&mut self, w: &mut W, event: &str, body: Value) -> std::io::Result<()> {
        let seq = self.next_seq();
        let msg = json!({ "seq": seq, "type": "event", "event": event, "body": body });
        write_message(w, &msg)
    }

    /// Main loop. Reads requests until EOF or a disconnect/terminate.
    pub fn run<R: BufRead, W: Write>(&mut self, r: &mut R, w: &mut W) -> std::io::Result<()> {
        while let Some(msg) = read_message(r)? {
            if msg.get("type").and_then(Value::as_str) != Some("request") {
                continue;
            }
            let command = msg.get("command").and_then(Value::as_str).unwrap_or("");
            match command {
                "initialize" => {
                    self.send_response(w, &msg, self.capabilities())?;
                    // Tell the client it may now send configuration (breakpoints).
                    self.send_event(w, "initialized", json!({}))?;
                }
                "setBreakpoints" => {
                    let body = self.handle_set_breakpoints(&msg);
                    self.send_response(w, &msg, body)?;
                }
                "setExceptionBreakpoints" => {
                    let filters = msg
                        .pointer("/arguments/filters")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    self.floor_filter_enabled = filters
                        .iter()
                        .any(|f| f.as_str() == Some("difficulty-floor"));
                    self.send_response(w, &msg, json!({}))?;
                }
                "configurationDone" => self.send_response(w, &msg, json!({}))?,
                "launch" => {
                    self.apply_launch_args(&msg);
                    self.send_response(w, &msg, json!({}))?;
                    self.send_event(
                        w,
                        "thread",
                        json!({ "reason": "started", "threadId": THREAD_ID }),
                    )?;
                    self.send_event(
                        w,
                        "output",
                        json!({ "category": "console",
                                "output": format!("Replaying {} ({} blocks)\n",
                                    self.engine_name(), self.engine.program_len()) }),
                    )?;
                    self.run_until_stop(w, false)?;
                }
                "threads" => {
                    self.send_response(
                        w,
                        &msg,
                        json!({ "threads": [{ "id": THREAD_ID, "name": "difficulty-replay" }] }),
                    )?;
                }
                "stackTrace" => {
                    let body = self.stack_trace();
                    self.send_response(w, &msg, body)?;
                }
                "scopes" => {
                    self.send_response(
                        w,
                        &msg,
                        json!({ "scopes": [{
                            "name": "Block State",
                            "variablesReference": BLOCK_SCOPE_REF,
                            "expensive": false
                        }]}),
                    )?;
                }
                "variables" => {
                    let body = self.variables(&msg);
                    self.send_response(w, &msg, body)?;
                }
                "continue" => {
                    self.send_response(w, &msg, json!({ "allThreadsContinued": true }))?;
                    self.run_until_stop(w, false)?;
                }
                "next" | "stepIn" | "stepOut" => {
                    self.send_response(w, &msg, json!({}))?;
                    self.run_until_stop(w, true)?;
                }
                "disconnect" | "terminate" => {
                    self.send_response(w, &msg, json!({}))?;
                    break;
                }
                // Be lenient with anything else a client probes for.
                _ => self.send_response(w, &msg, json!({}))?,
            }
        }
        Ok(())
    }

    fn capabilities(&self) -> Value {
        json!({
            "supportsConfigurationDoneRequest": true,
            "supportsExceptionFilterOptions": true,
            "supportsTerminateRequest": true,
            // Reverse debugging is a planned increment; advertise it off for now.
            "supportsStepBack": false,
            "exceptionBreakpointFilters": [{
                "filter": "difficulty-floor",
                "label": "Difficulty reaches the consensus floor",
                "default": true,
                "description": "Pause when ASERT drives difficulty to MIN_DIFFICULTY (the #191 collapse symptom)."
            }]
        })
    }

    fn engine_name(&self) -> String {
        self.engine_scenario_name()
    }
    fn engine_scenario_name(&self) -> String {
        // Reach into the engine's public scenario name.
        self.engine.scenario_name.clone()
    }

    fn apply_launch_args(&mut self, msg: &Value) {
        // Optional: raise the floor threshold to catch a sharp drop before the
        // absolute floor, e.g. "floorMultiple": 8.
        if let Some(mult) = msg.pointer("/arguments/floorMultiple").and_then(Value::as_u64) {
            self.engine.floor_threshold =
                coincync::consensus::difficulty::MIN_DIFFICULTY.saturating_mul(mult as u128);
        }
    }

    fn handle_set_breakpoints(&mut self, msg: &Value) -> Value {
        let bps = msg
            .pointer("/arguments/breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.line_breakpoints = bps
            .iter()
            .filter_map(|b| b.get("line").and_then(Value::as_i64))
            .collect();
        let verified: Vec<Value> = self
            .line_breakpoints
            .iter()
            .map(|line| json!({ "verified": true, "line": line }))
            .collect();
        json!({ "breakpoints": verified })
    }

    /// Step the engine, emitting `stopped`/`terminated` as appropriate.
    /// `single` = one step then stop (next/stepIn/stepOut); otherwise run to the
    /// next breakpoint (launch/continue).
    fn run_until_stop<W: Write>(&mut self, w: &mut W, single: bool) -> std::io::Result<()> {
        loop {
            match self.engine.step() {
                Some(state) => {
                    let hit_floor = self.floor_filter_enabled && state.at_floor;
                    let hit_line = self.line_breakpoints.contains(&block_line(state.index));
                    if single {
                        let reason = if hit_floor {
                            "exception"
                        } else if hit_line {
                            "breakpoint"
                        } else {
                            "step"
                        };
                        return self.emit_stopped(w, reason, &state);
                    }
                    if hit_floor {
                        return self.emit_stopped(w, "exception", &state);
                    }
                    if hit_line {
                        return self.emit_stopped(w, "breakpoint", &state);
                    }
                    // keep running
                }
                None => {
                    self.send_event(w, "output", json!({
                        "category": "console",
                        "output": "Replay finished — difficulty never reached the floor.\n"
                    }))?;
                    self.send_event(w, "terminated", json!({}))?;
                    self.send_event(w, "exited", json!({ "exitCode": 0 }))?;
                    return Ok(());
                }
            }
        }
    }

    fn emit_stopped<W: Write>(
        &mut self,
        w: &mut W,
        reason: &str,
        state: &StepState,
    ) -> std::io::Result<()> {
        if reason == "exception" {
            self.send_event(w, "output", json!({
                "category": "important",
                "output": format!(
                    "⚠ difficulty floor hit at block[{}] height={}: difficulty={} (gap was {}s)\n",
                    state.index, state.height, state.difficulty, state.gap_secs)
            }))?;
        }
        let body = json!({
            "reason": reason,
            "threadId": THREAD_ID,
            "allThreadsStopped": true,
            "description": if reason == "exception" {
                "Difficulty reached the consensus floor"
            } else { "paused" },
            "text": format!("difficulty={} floor_threshold={}",
                state.difficulty, self.engine.floor_threshold),
        });
        self.send_event(w, "stopped", body)
    }

    fn stack_trace(&self) -> Value {
        let (line, name) = match &self.engine.last {
            Some(s) => (
                block_line(s.index),
                format!("block[{}] height={}", s.index, s.height),
            ),
            None => (1, "scenario start".to_string()),
        };
        json!({
            "stackFrames": [{
                "id": 1,
                "name": name,
                "line": line,
                "column": 1,
                "source": { "name": "scenario", "path": self.source_path }
            }],
            "totalFrames": 1
        })
    }

    fn variables(&self, msg: &Value) -> Value {
        let want = msg.pointer("/arguments/variablesReference").and_then(Value::as_i64);
        if want != Some(BLOCK_SCOPE_REF) {
            return json!({ "variables": [] });
        }
        let Some(s) = &self.engine.last else {
            return json!({ "variables": [] });
        };
        let var = |name: &str, value: String| {
            json!({ "name": name, "value": value, "variablesReference": 0 })
        };
        json!({ "variables": [
            var("height", s.height.to_string()),
            var("block_index", s.index.to_string()),
            var("timestamp", s.timestamp.to_string()),
            var("gap_secs", format!("{} ({} min)", s.gap_secs, s.gap_secs / 60)),
            var("difficulty", s.difficulty.to_string()),
            var("target", s.target_hex.clone()),
            var("floor_threshold", self.engine.floor_threshold.to_string()),
            var("at_floor", s.at_floor.to_string()),
        ]})
    }
}
