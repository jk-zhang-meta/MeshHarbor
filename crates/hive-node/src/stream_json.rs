// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The adapter from Claude Code's `--output-format stream-json` to
//! [`TranscriptEvent`]s.
//!
//! Headless stream-json is Hive's primary harness wire because it is a
//! documented output format; the on-disk transcript JSONL is "internal to
//! Claude Code and changes between versions". Even so, this parser is
//! deliberately tolerant: an unknown line type, block type or field is skipped
//! and reported, never an error — a harness upgrade must degrade a session's
//! rendering, not stop the session. The only error is a line that is not JSON.
//!
//! ⚠️ The shapes below follow the documented stream-json messages (`system`
//! `init` / `compact_boundary`, `assistant`, `user`, `result`, `stream_event`).
//! P0's field cell captures real output from a pinned Claude Code version and
//! adds it to the tests as fixtures; until then these tests pin the documented
//! shapes, not a recording.

use serde_json::Value;

use crate::event::{TranscriptEvent, Usage};

/// What one stream-json line amounts to.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// Events to record: appended to the chain and replicated.
    pub record: Vec<TranscriptEvent>,
    /// Live-only assistant text deltas (`--include-partial-messages`): shown to
    /// viewers while the turn runs and never recorded, because the complete
    /// block arrives in the following `assistant` message.
    pub live_text: Vec<String>,
    /// What was skipped, as `type` or `type/subtype` (or `block:<type>` for a
    /// content block), so a harness change shows up in the logs instead of
    /// silently thinning the transcript.
    pub skipped: Vec<String>,
}

/// Limits the adapter applies to what it records.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The most bytes of one tool output kept; the head and the tail are kept
    /// in equal parts, and the event is marked `truncated`.
    pub max_tool_output: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tool_output: 64 * 1024,
        }
    }
}

/// Parse one stream-json line.
pub fn parse_line(line: &str, limits: &Limits) -> Result<Parsed, serde_json::Error> {
    let v: Value = serde_json::from_str(line)?;
    let mut out = Parsed::default();
    let ty = v.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        "system" => system(&v, &mut out),
        "assistant" => assistant(&v, &mut out),
        "user" => user(&v, limits, &mut out),
        "result" => result(&v, &mut out),
        "stream_event" => stream_event(&v, &mut out),
        "" => out.skipped.push("<no type>".into()),
        other => out.skipped.push(other.to_string()),
    }
    Ok(out)
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn system(v: &Value, out: &mut Parsed) {
    match str_at(v, "subtype").unwrap_or("") {
        "init" => out.record.push(TranscriptEvent::SessionInit {
            harness_session_id: str_at(v, "session_id").unwrap_or_default().to_string(),
            model: str_at(v, "model").map(str::to_string),
            cwd: str_at(v, "cwd").map(str::to_string),
            tools: v
                .get("tools")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }),
        "compact_boundary" => {
            // The stream spells it `compact_metadata`; the on-disk JSONL
            // `compactMetadata`. Accept either.
            let meta = v
                .get("compact_metadata")
                .or_else(|| v.get("compactMetadata"));
            let field = |a: &str, b: &str| meta.and_then(|m| m.get(a).or_else(|| m.get(b)));
            out.record.push(TranscriptEvent::Compaction {
                trigger: field("trigger", "trigger")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                pre_tokens: field("pre_tokens", "preTokens").and_then(Value::as_u64),
            });
        }
        other => out.skipped.push(format!("system/{other}")),
    }
}

fn content_blocks(v: &Value) -> Option<&Vec<Value>> {
    v.get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
}

fn assistant(v: &Value, out: &mut Parsed) {
    let Some(blocks) = content_blocks(v) else {
        out.skipped.push("assistant/<no content>".into());
        return;
    };
    for b in blocks {
        match str_at(b, "type").unwrap_or("") {
            "text" => {
                let text = str_at(b, "text").unwrap_or_default();
                if !text.is_empty() {
                    out.record.push(TranscriptEvent::AssistantText {
                        text: text.to_string(),
                    });
                }
            }
            "thinking" => {
                // Current models return an empty `thinking` unless a summary was
                // asked for; an empty block records nothing.
                let summary = str_at(b, "thinking").unwrap_or_default();
                if !summary.trim().is_empty() {
                    out.record.push(TranscriptEvent::Thinking {
                        summary: summary.to_string(),
                    });
                }
            }
            "redacted_thinking" => {}
            "tool_use" | "server_tool_use" => out.record.push(TranscriptEvent::ToolUse {
                id: str_at(b, "id").unwrap_or_default().to_string(),
                name: str_at(b, "name").unwrap_or_default().to_string(),
                input: b.get("input").cloned().unwrap_or(Value::Null),
            }),
            other => out.skipped.push(format!("block:{other}")),
        }
    }
}

fn user(v: &Value, limits: &Limits, out: &mut Parsed) {
    let content = v.get("message").and_then(|m| m.get("content"));
    match content {
        // A prompt echoed as a plain string (`--replay-user-messages`).
        Some(Value::String(text)) if !text.is_empty() => {
            out.record.push(TranscriptEvent::UserMessage {
                author: None,
                text: text.clone(),
            })
        }
        Some(Value::Array(blocks)) => {
            for b in blocks {
                match str_at(b, "type").unwrap_or("") {
                    "tool_result" => {
                        let (output, truncated) =
                            clip(&tool_output(b.get("content")), limits.max_tool_output);
                        out.record.push(TranscriptEvent::ToolResult {
                            tool_use_id: str_at(b, "tool_use_id").unwrap_or_default().to_string(),
                            ok: !b.get("is_error").and_then(Value::as_bool).unwrap_or(false),
                            output,
                            truncated,
                        });
                    }
                    "text" => {
                        let text = str_at(b, "text").unwrap_or_default();
                        if !text.is_empty() {
                            out.record.push(TranscriptEvent::UserMessage {
                                author: None,
                                text: text.to_string(),
                            });
                        }
                    }
                    other => out.skipped.push(format!("block:{other}")),
                }
            }
        }
        _ => out.skipped.push("user/<no content>".into()),
    }
}

/// A tool result's content as text: a string as is; an array of blocks as its
/// text blocks joined, with a placeholder for anything else.
fn tool_output(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|p| match str_at(p, "type").unwrap_or("") {
                "text" => str_at(p, "text").unwrap_or_default().to_string(),
                other => format!("[{other}]"),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Keep at most `max` bytes: the head and the tail, cut on char boundaries,
/// with a marker saying how much was dropped.
fn clip(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_string(), false);
    }
    let half = max / 2;
    let mut head_end = half;
    while !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len() - half;
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let dropped = tail_start - head_end;
    (
        format!(
            "{}\n… [{dropped} bytes omitted] …\n{}",
            &text[..head_end],
            &text[tail_start..]
        ),
        true,
    )
}

fn result(v: &Value, out: &mut Parsed) {
    let subtype = str_at(v, "subtype").map(str::to_string);
    let is_error = v.get("is_error").and_then(Value::as_bool).unwrap_or(false);
    out.record.push(TranscriptEvent::Turn {
        ok: !is_error && subtype.as_deref().is_none_or(|s| s == "success"),
        subtype,
        num_turns: v
            .get("num_turns")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        duration_ms: v.get("duration_ms").and_then(Value::as_u64),
        // `total_cost_usd` is current; `cost_usd` is the deprecated spelling.
        cost_usd: v
            .get("total_cost_usd")
            .or_else(|| v.get("cost_usd"))
            .and_then(Value::as_f64),
        usage: v
            .get("usage")
            .and_then(|u| serde_json::from_value::<Usage>(u.clone()).ok()),
    });
}

fn stream_event(v: &Value, out: &mut Parsed) {
    let Some(ev) = v.get("event") else {
        out.skipped.push("stream_event/<no event>".into());
        return;
    };
    if str_at(ev, "type") == Some("content_block_delta")
        && let Some(delta) = ev.get("delta")
        && str_at(delta, "type") == Some("text_delta")
        && let Some(text) = str_at(delta, "text")
    {
        out.live_text.push(text.to_string());
    }
    // Every other stream event (message_start, content_block_start/stop,
    // input_json_delta, …) is expected and carries nothing to record: the
    // complete message follows. Not reported as skipped, so the skip log
    // stays a signal.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Parsed {
        parse_line(line, &Limits::default()).unwrap()
    }

    #[test]
    fn init_records_the_harness_session() {
        let p = parse(
            r#"{"type":"system","subtype":"init","session_id":"0b3c","model":"claude-opus-5-5","cwd":"/home/alice/meshharbor","tools":["Bash","Read"],"mcp_servers":[]}"#,
        );
        assert_eq!(
            p.record,
            vec![TranscriptEvent::SessionInit {
                harness_session_id: "0b3c".into(),
                model: Some("claude-opus-5-5".into()),
                cwd: Some("/home/alice/meshharbor".into()),
                tools: vec!["Bash".into(), "Read".into()],
            }]
        );
    }

    #[test]
    fn an_assistant_message_yields_one_event_per_block_in_order() {
        let p = parse(
            r#"{"type":"assistant","message":{"role":"assistant","content":[
                {"type":"thinking","thinking":"","signature":"x"},
                {"type":"text","text":"Running the tests."},
                {"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"cargo test"}}
            ]},"session_id":"0b3c","parent_tool_use_id":null}"#,
        );
        assert_eq!(
            p.record,
            vec![
                TranscriptEvent::AssistantText {
                    text: "Running the tests.".into()
                },
                TranscriptEvent::ToolUse {
                    id: "toolu_1".into(),
                    name: "Bash".into(),
                    input: serde_json::json!({"command": "cargo test"}),
                },
            ],
            "an empty thinking block records nothing"
        );
        assert!(p.skipped.is_empty());
    }

    #[test]
    fn a_thinking_summary_is_kept_when_present() {
        let p = parse(
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"Check the lockfile first."}]}}"#,
        );
        assert_eq!(
            p.record,
            vec![TranscriptEvent::Thinking {
                summary: "Check the lockfile first.".into()
            }]
        );
    }

    #[test]
    fn tool_results_record_ok_and_error_and_flatten_block_content() {
        let p = parse(
            r#"{"type":"user","message":{"role":"user","content":[
                {"type":"tool_result","tool_use_id":"toolu_1","content":"ok\n","is_error":false},
                {"type":"tool_result","tool_use_id":"toolu_2","content":[{"type":"text","text":"line 1"},{"type":"image","source":{}}],"is_error":true}
            ]}}"#,
        );
        assert_eq!(
            p.record,
            vec![
                TranscriptEvent::ToolResult {
                    tool_use_id: "toolu_1".into(),
                    ok: true,
                    output: "ok\n".into(),
                    truncated: false,
                },
                TranscriptEvent::ToolResult {
                    tool_use_id: "toolu_2".into(),
                    ok: false,
                    output: "line 1\n[image]".into(),
                    truncated: false,
                },
            ]
        );
    }

    #[test]
    fn a_long_tool_output_keeps_head_and_tail_on_char_boundaries() {
        let big = format!("{}é{}", "a".repeat(100), "z".repeat(100));
        let line = serde_json::json!({
            "type": "user",
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t", "content": big}]}
        })
        .to_string();
        let p = parse_line(
            &line,
            &Limits {
                max_tool_output: 101,
            },
        )
        .unwrap();
        let TranscriptEvent::ToolResult {
            output, truncated, ..
        } = &p.record[0]
        else {
            panic!("not a tool result: {:?}", p.record)
        };
        assert!(truncated);
        assert!(output.starts_with(&"a".repeat(50)), "{output}");
        assert!(output.ends_with(&"z".repeat(50)), "{output}");
        assert!(output.contains("bytes omitted"), "{output}");
    }

    #[test]
    fn result_records_the_turn_with_cost_and_usage() {
        let p = parse(
            r#"{"type":"result","subtype":"success","is_error":false,"duration_ms":4200,"num_turns":3,"total_cost_usd":0.0123,"usage":{"input_tokens":10,"output_tokens":20,"cache_creation_input_tokens":30,"cache_read_input_tokens":40},"session_id":"0b3c"}"#,
        );
        assert_eq!(
            p.record,
            vec![TranscriptEvent::Turn {
                ok: true,
                subtype: Some("success".into()),
                num_turns: Some(3),
                duration_ms: Some(4200),
                cost_usd: Some(0.0123),
                usage: Some(Usage {
                    input_tokens: 10,
                    output_tokens: 20,
                    cache_creation_input_tokens: 30,
                    cache_read_input_tokens: 40,
                }),
            }]
        );
    }

    #[test]
    fn an_error_result_is_not_ok_and_the_old_cost_spelling_is_read() {
        let p = parse(
            r#"{"type":"result","subtype":"error_max_turns","is_error":true,"cost_usd":0.5}"#,
        );
        let TranscriptEvent::Turn { ok, cost_usd, .. } = &p.record[0] else {
            panic!()
        };
        assert!(!ok);
        assert_eq!(*cost_usd, Some(0.5));
    }

    #[test]
    fn text_deltas_are_live_only_and_never_recorded() {
        let p = parse(
            r#"{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Run"}},"session_id":"0b3c"}"#,
        );
        assert_eq!(p.live_text, vec!["Run".to_string()]);
        assert!(p.record.is_empty());
        // Expected stream events that carry nothing are not reported as skipped.
        let p = parse(r#"{"type":"stream_event","event":{"type":"message_start"}}"#);
        assert_eq!(p, Parsed::default());
    }

    #[test]
    fn compaction_reads_either_spelling() {
        for line in [
            r#"{"type":"system","subtype":"compact_boundary","compact_metadata":{"trigger":"auto","pre_tokens":180000}}"#,
            r#"{"type":"system","subtype":"compact_boundary","compactMetadata":{"trigger":"auto","preTokens":180000}}"#,
        ] {
            assert_eq!(
                parse(line).record,
                vec![TranscriptEvent::Compaction {
                    trigger: Some("auto".into()),
                    pre_tokens: Some(180_000),
                }],
                "{line}"
            );
        }
    }

    #[test]
    fn unknown_types_and_blocks_are_skipped_and_named_never_errors() {
        let p = parse(r#"{"type":"rate_limit_event","info":{}}"#);
        assert_eq!(p.skipped, vec!["rate_limit_event".to_string()]);
        let p = parse(r#"{"type":"system","subtype":"hook_response"}"#);
        assert_eq!(p.skipped, vec!["system/hook_response".to_string()]);
        let p = parse(r#"{"type":"assistant","message":{"content":[{"type":"citations_v9"}]}}"#);
        assert_eq!(p.skipped, vec!["block:citations_v9".to_string()]);
        assert!(parse_line("not json", &Limits::default()).is_err());
    }
}
