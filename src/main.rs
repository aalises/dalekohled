mod estate;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) const REPORT_VERSION: u8 = 2;
const THINKING_THRESHOLD: usize = 2_000;
const OUTPUT_THRESHOLD: usize = 2_500;
pub(crate) const DEFAULT_SEMANTIC_MODEL: &str = "moonshotai/kimi-k3";
const SEMANTIC_DIGEST_CAP: usize = 60_000;

pub(crate) fn semantic_model() -> String {
    std::env::var("CXWATCH_SEMANTIC_MODEL").unwrap_or_else(|_| DEFAULT_SEMANTIC_MODEL.into())
}

#[derive(Parser)]
#[command(
    name = "cxwatch",
    about = "Context hygiene for agent sessions (pi, Claude Code, Codex)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a session (default: most recent session across all harnesses)
    Report {
        session: Option<PathBuf>,
        /// Emit JSON
        #[arg(long)]
        json: bool,
        /// Also run LLM semantic analysis
        #[arg(long)]
        semantic: bool,
    },
    /// Write a Markdown report (includes semantic pass)
    Explain {
        session: Option<PathBuf>,
        /// Output file (default: cxwatch-demo.md)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// List available sessions
    Sessions,
    /// Interactive session picker
    Pick {
        /// Start with the LLM semantic pass enabled
        #[arg(long)]
        semantic: bool,
    },
    /// Audit static context (skills, commands, MCP, memory) against observed usage
    Estate {
        /// Emit JSON
        #[arg(long)]
        json: bool,
        /// Also run LLM contradiction/duplication analysis
        #[arg(long)]
        semantic: bool,
        /// Write an agent-ready Markdown pruning plan to this file
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        None => tui::pick(false),
        Some(Cmd::Report {
            session,
            json,
            semantic,
        }) => report_cmd(session, json, semantic),
        Some(Cmd::Explain { session, output }) => explain_cmd(session, output),
        Some(Cmd::Sessions) => sessions_cmd(),
        Some(Cmd::Pick { semantic }) => tui::pick(semantic),
        Some(Cmd::Estate {
            json,
            semantic,
            output,
        }) => estate::estate_cmd(json, semantic, output),
    }
}

// ---------- session discovery ----------

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Source {
    Pi,
    Claude,
    Codex,
    OpenCode,
}

impl Source {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Source::Pi => "pi",
            Source::Claude => "claude",
            Source::Codex => "codex",
            Source::OpenCode => "opencode",
        }
    }
}

fn roots() -> Vec<(Source, PathBuf)> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    vec![
        (Source::Pi, home.join(".pi/agent/sessions")),
        (Source::Claude, home.join(".claude/projects")),
        (Source::Codex, home.join(".codex/sessions")),
        (Source::Codex, home.join(".codex/archived_sessions")),
    ]
}

pub(crate) fn walk_jsonl(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk_jsonl(&p, out);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out.push(p);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct SessionMeta {
    pub source: Source,
    pub path: PathBuf,
    pub title: String,
    pub modified: SystemTime,
    pub size: u64,
    /// First real user prompt, filled lazily by the TUI.
    pub preview: Option<String>,
}

pub(crate) fn sessions() -> Vec<SessionMeta> {
    let mut out = Vec::new();
    for (source, root) in roots() {
        let mut files = Vec::new();
        walk_jsonl(&root, &mut files);
        for path in files {
            let md = path.metadata().ok();
            let modified = md
                .as_ref()
                .and_then(|m| m.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let size = md.map(|m| m.len()).unwrap_or(0);
            let title = title_for(source, &path);
            out.push(SessionMeta {
                source,
                path,
                title,
                modified,
                size,
                preview: None,
            });
        }
    }
    opencode_sessions(&mut out);
    out.sort_by_key(|session| Reverse(session.modified));
    out
}

// ---------- opencode (sqlite-backed sessions, addressed as "opencode:<id>") ----------

fn opencode_db() -> PathBuf {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    home.join(".local/share/opencode/opencode.db")
}

fn sqlite_json(db: &Path, query: &str) -> Vec<Value> {
    let Ok(out) = std::process::Command::new("sqlite3")
        .arg("-readonly")
        .arg("-json")
        .arg(db)
        .arg(query)
        .output()
    else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<Value>>(&out.stdout).unwrap_or_default()
}

fn opencode_sessions(out: &mut Vec<SessionMeta>) {
    let db = opencode_db();
    if !db.is_file() {
        return;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let rows = sqlite_json(
        &db,
        "select s.id as id, s.directory as dir, s.title as title, s.time_updated as up, \
         coalesce(sum(length(p.data)),0) as bytes \
         from session s left join part p on p.session_id = s.id group by s.id",
    );
    for r in rows {
        let Some(id) = r["id"].as_str() else { continue };
        let dir = r["dir"].as_str().unwrap_or("?");
        let title = dir
            .strip_prefix(&home)
            .unwrap_or(dir)
            .trim_start_matches('/')
            .to_string();
        out.push(SessionMeta {
            source: Source::OpenCode,
            path: PathBuf::from(format!("opencode:{id}")),
            title: if title.is_empty() { "~".into() } else { title },
            modified: SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(r["up"].as_u64().unwrap_or(0)),
            size: r["bytes"].as_u64().unwrap_or(0),
            // the db already stores an LLM-generated session title — use it as the preview
            preview: Some(r["title"].as_str().unwrap_or("").to_string()),
        });
    }
}

fn parse_opencode(id: &str) -> Result<Vec<Event>> {
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("invalid opencode session id");
    }
    let rows = sqlite_json(
        &opencode_db(),
        &format!(
            "select m.id as mid, json_extract(m.data,'$.role') as role, p.data as data \
             from part p join message m on m.id = p.message_id \
             where p.session_id = '{id}' order by m.time_created, m.id, p.id"
        ),
    );
    if rows.is_empty() {
        anyhow::bail!("no opencode session {id} (or sqlite3 unavailable)");
    }
    let mut events: Vec<Event> = Vec::new();
    for r in &rows {
        let mid = r["mid"].as_str().unwrap_or("");
        let role = r["role"].as_str().unwrap_or("unknown");
        let part: Value = r["data"]
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(Value::Null);
        let items = opencode_items(&part);
        if items.is_empty() {
            continue;
        }
        match events.last_mut() {
            Some(ev) if ev.id == mid => ev.items.extend(items),
            _ => events.push(Event {
                id: mid.to_string(),
                role: role.to_string(),
                items,
            }),
        }
    }
    Ok(events)
}

/// An opencode `tool` part carries the call and its result merged in one object.
fn opencode_items(part: &Value) -> Vec<Item> {
    match part["type"].as_str().unwrap_or("") {
        "text" => vec![Item::Text(part["text"].as_str().unwrap_or("").into())],
        "reasoning" => vec![Item::Thinking(part["text"].as_str().unwrap_or("").into())],
        "tool" => {
            let call_id = part["callID"].as_str().unwrap_or("").to_string();
            let name = part["tool"].as_str().unwrap_or("");
            vec![
                tool_call_item(call_id.clone(), name, &part["state"]["input"]),
                Item::ToolResult {
                    call_id,
                    tokens: estimate_tokens(part["state"]["output"].as_str().unwrap_or("")),
                },
            ]
        }
        _ => vec![],
    }
}

fn title_for(source: Source, path: &Path) -> String {
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match source {
        // dir name encodes the cwd, e.g. "--Users-me-dev-cxwatch--" / "-Users-me-dev-cxwatch"
        Source::Pi | Source::Claude => decode_slug(parent),
        // listed straight from the db, never via file walk
        Source::OpenCode => String::new(),
        // filename: rollout-<date>T<time>-<uuid>.jsonl
        Source::Codex => {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("session");
            let s = stem.strip_prefix("rollout-").unwrap_or(stem);
            if s.len() > 37 {
                format!("{} {}", &s[..s.len() - 37], &s[s.len() - 36..s.len() - 28])
            } else {
                s.into()
            }
        }
    }
}

pub(crate) fn decode_slug(slug: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default().replace('/', "-");
    let t = slug.trim_matches('-');
    let t = t
        .strip_prefix(home.trim_matches('-'))
        .unwrap_or(t)
        .trim_matches('-');
    if t.is_empty() {
        "~".into()
    } else {
        t.replace('-', "/")
    }
}

fn latest_session() -> Result<PathBuf> {
    sessions()
        .into_iter()
        .next()
        .map(|s| s.path)
        .ok_or_else(|| anyhow::anyhow!("no sessions found under ~/.pi, ~/.claude or ~/.codex"))
}

/// First real user prompt of a session, for the picker. Scans only the head of the file.
pub(crate) fn preview(source: Source, path: &Path) -> String {
    use std::io::{BufRead, BufReader, Read};
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let reader = BufReader::new(f.take(512 * 1024));
    for line in reader.lines().map_while(Result::ok).take(120) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let text = match source {
            Source::Pi => (v["type"] == "message" && v["message"]["role"] == "user")
                .then(|| first_text(&v["message"]["content"]))
                .flatten(),
            Source::Claude => (v["type"] == "user" && v["isMeta"] != true)
                .then(|| first_text(&v["message"]["content"]))
                .flatten(),
            Source::Codex => (v["type"] == "response_item"
                && v["payload"]["type"] == "message"
                && v["payload"]["role"] == "user")
                .then(|| first_text(&v["payload"]["content"]))
                .flatten(),
            // preview comes from the db title, set at listing time
            Source::OpenCode => return String::new(),
        };
        if let Some(t) = text {
            let t = t.trim();
            // skip injected context: tags, caveats, AGENTS.md preambles
            if t.is_empty() || t.starts_with('<') || t.starts_with('#') || t.starts_with("Caveat:")
            {
                continue;
            }
            return clip(&t.split_whitespace().collect::<Vec<_>>().join(" "), 100);
        }
    }
    String::new()
}

fn first_text(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => items.iter().find_map(|i| {
            matches!(i["type"].as_str(), Some("text" | "input_text"))
                .then(|| i["text"].as_str().map(String::from))
                .flatten()
        }),
        _ => None,
    }
}

// ---------- unified event model ----------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Action {
    Read,
    Mutate,
}

#[derive(Clone)]
pub(crate) enum Item {
    Text(String),
    Thinking(String),
    ToolCall {
        call_id: String,
        desc: String,
        targets: Vec<(Action, String)>,
    },
    ToolResult {
        call_id: String,
        tokens: usize,
    },
}

#[derive(Clone)]
pub(crate) struct Event {
    pub id: String,
    pub role: String,
    pub items: Vec<Item>,
}

pub(crate) fn parse(path: &Path) -> Result<Vec<Event>> {
    if let Some(id) = path.to_str().and_then(|s| s.strip_prefix("opencode:")) {
        return parse_opencode(id);
    }
    let s = std::fs::read_to_string(path)?;
    Ok(s.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| parse_line(&v))
        .collect())
}

fn parse_line(v: &Value) -> Option<Event> {
    match v["type"].as_str()? {
        // pi: {"type":"message","id":..,"message":{"role":..,"content":[..]}}
        "message" => {
            let m = &v["message"];
            let id = v["id"].as_str().unwrap_or("").to_string();
            let role = m["role"].as_str()?.to_string();
            if role == "toolResult" {
                return Some(Event {
                    id,
                    role,
                    items: vec![Item::ToolResult {
                        call_id: m["toolCallId"].as_str().unwrap_or("").into(),
                        tokens: estimate_tokens(&text_of(&m["content"])),
                    }],
                });
            }
            Some(Event {
                id,
                role,
                items: body_items(&m["content"]),
            })
        }
        // Claude Code: {"type":"user"|"assistant","uuid":..,"message":{"role":..,"content":str|[..]}}
        "user" | "assistant" => {
            let m = &v["message"];
            let id = v["uuid"].as_str().unwrap_or("").to_string();
            let role = m["role"]
                .as_str()
                .or(v["type"].as_str())
                .unwrap_or("unknown")
                .to_string();
            Some(Event {
                id,
                role,
                items: body_items(&m["content"]),
            })
        }
        // Codex: {"type":"response_item","payload":{"type":"message"|"function_call"|..}}
        "response_item" => {
            let p = &v["payload"];
            match p["type"].as_str()? {
                "message" => Some(Event {
                    id: p["id"].as_str().unwrap_or("").to_string(),
                    role: p["role"].as_str().unwrap_or("unknown").to_string(),
                    items: p["content"]
                        .as_array()?
                        .iter()
                        .filter(|i| {
                            matches!(
                                i["type"].as_str(),
                                Some("input_text" | "output_text" | "text")
                            )
                        })
                        .map(|i| Item::Text(i["text"].as_str().unwrap_or("").into()))
                        .collect(),
                }),
                "function_call" => {
                    let call_id = p["call_id"].as_str().unwrap_or("").to_string();
                    // arguments arrive as a JSON-encoded string
                    let args: Value = p["arguments"]
                        .as_str()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or_else(|| p["arguments"].clone());
                    let name = p["name"].as_str().unwrap_or("");
                    Some(Event {
                        id: call_id.clone(),
                        role: "assistant".into(),
                        items: vec![tool_call_item(call_id, name, &args)],
                    })
                }
                "custom_tool_call" => {
                    let call_id = p["call_id"].as_str().unwrap_or("").to_string();
                    Some(Event {
                        id: call_id.clone(),
                        role: "assistant".into(),
                        items: vec![custom_tool_call_item(
                            call_id,
                            p["name"].as_str().unwrap_or(""),
                            p["input"].as_str().unwrap_or(""),
                        )],
                    })
                }
                "function_call_output" | "custom_tool_call_output" => {
                    let call_id = p["call_id"].as_str().unwrap_or("").to_string();
                    Some(Event {
                        id: call_id.clone(),
                        role: "tool".into(),
                        items: vec![Item::ToolResult {
                            call_id,
                            tokens: estimate_tokens(&text_of(&p["output"])),
                        }],
                    })
                }
                "reasoning" => {
                    let t = p["summary"]
                        .as_array()?
                        .iter()
                        .filter_map(|s| s["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    (!t.is_empty()).then(|| Event {
                        id: p["id"].as_str().unwrap_or("").to_string(),
                        role: "assistant".into(),
                        items: vec![Item::Thinking(t)],
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn body_items(content: &Value) -> Vec<Item> {
    match content {
        Value::String(s) => vec![Item::Text(s.clone())],
        Value::Array(a) => a
            .iter()
            .filter_map(|i| match i["type"].as_str()? {
                "text" => Some(Item::Text(i["text"].as_str().unwrap_or("").into())),
                "thinking" => Some(Item::Thinking(i["thinking"].as_str().unwrap_or("").into())),
                // pi style
                "toolCall" => Some(tool_call_item(
                    i["id"].as_str().unwrap_or("").into(),
                    i["name"].as_str().unwrap_or(""),
                    &i["arguments"],
                )),
                // Claude Code style
                "tool_use" => Some(tool_call_item(
                    i["id"].as_str().unwrap_or("").into(),
                    i["name"].as_str().unwrap_or(""),
                    &i["input"],
                )),
                "tool_result" => Some(Item::ToolResult {
                    call_id: i["tool_use_id"].as_str().unwrap_or("").into(),
                    tokens: estimate_tokens(&text_of(&i["content"])),
                }),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn tool_call_item(call_id: String, name: &str, args: &Value) -> Item {
    let targets = tool_targets(name, args);
    let desc = if let Some((_, p)) = targets.first() {
        format!("{name} {p}")
    } else if let Some(c) = args["command"].as_str().or(args["cmd"].as_str()) {
        format!(
            "{name} `{}`",
            clip(&c.split_whitespace().collect::<Vec<_>>().join(" "), 48)
        )
    } else {
        name.to_string()
    };
    Item::ToolCall {
        call_id,
        desc,
        targets,
    }
}

fn custom_tool_call_item(call_id: String, name: &str, input: &str) -> Item {
    let targets = match name {
        "apply_patch" => patch_targets(input),
        "exec" => exec_script_targets(input),
        _ => Vec::new(),
    };
    let desc = targets
        .first()
        .map(|(_, path)| format!("{name} {path}"))
        .unwrap_or_else(|| name.to_string());
    Item::ToolCall {
        call_id,
        desc,
        targets,
    }
}

fn tool_targets(name: &str, args: &Value) -> Vec<(Action, String)> {
    let file = || {
        ["path", "file_path", "filePath", "notebook_path"]
            .iter()
            .find_map(|k| args[*k].as_str())
            .map(String::from)
    };
    match name.to_ascii_lowercase().as_str() {
        "read" => file().map(|p| (Action::Read, p)).into_iter().collect(),
        "write" | "edit" | "multiedit" | "notebookedit" => {
            file().map(|p| (Action::Mutate, p)).into_iter().collect()
        }
        "bash" | "exec_command" | "shell" | "local_shell" => {
            let cmd = args["command"]
                .as_str()
                .map(String::from)
                .or_else(|| {
                    args["command"].as_array().map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                })
                .or_else(|| args["cmd"].as_str().map(String::from));
            cmd.map(|c| shell_targets(&c)).unwrap_or_default()
        }
        "apply_patch" => patch_targets(args["input"].as_str().unwrap_or("")),
        _ => vec![],
    }
}

/// Detect common file reads and edits in shell commands.
fn shell_targets(cmd: &str) -> Vec<(Action, String)> {
    let mut out = Vec::new();
    for seg in cmd.replace("&&", ";").split(['|', ';', '\n']) {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let Some(&first) = toks.first() else { continue };
        let is_reader = matches!(first, "cat" | "head" | "tail" | "less" | "more" | "bat")
            || (first == "sed" && !toks.iter().any(|t| t.starts_with("-i")));
        if is_reader && let Some(path) = last_pathish(&toks[1..]) {
            out.push((Action::Read, path));
        }
        let mutates_last = (first == "sed" && toks.iter().any(|t| t.starts_with("-i")))
            || matches!(first, "tee" | "cp" | "install");
        if mutates_last {
            if let Some(path) = last_pathish(&toks[1..]) {
                out.push((Action::Mutate, path));
            }
        } else if matches!(first, "mv" | "rm" | "unlink" | "truncate") {
            out.extend(
                toks[1..]
                    .iter()
                    .filter_map(|t| pathish(t).map(|p| (Action::Mutate, p))),
            );
        }
        for (i, tok) in toks.iter().enumerate() {
            let path = match *tok {
                ">" | ">>" => toks.get(i + 1).and_then(|t| pathish(t)),
                _ => tok
                    .strip_prefix(">>")
                    .or_else(|| tok.strip_prefix('>'))
                    .and_then(pathish),
            };
            if let Some(path) = path {
                out.push((Action::Mutate, path));
            }
        }
    }
    dedup_targets(out)
}

fn last_pathish(toks: &[&str]) -> Option<String> {
    toks.iter().rev().find_map(|t| pathish(t))
}

fn pathish(token: &str) -> Option<String> {
    let token = token.trim_matches(|c| c == '\'' || c == '"');
    (!token.is_empty()
        && !token.starts_with('-')
        && !token.starts_with(|c: char| c.is_ascii_digit())
        && !token.contains(['$', '`', '*', '=']))
    .then(|| token.to_string())
}

fn exec_script_targets(script: &str) -> Vec<(Action, String)> {
    let mut targets = Vec::new();
    for (start, value) in js_string_literals(script) {
        let prefix = script[..start].trim_end();
        if ["cmd:", "\"cmd\":", "'cmd':", "command:", "\"command\":"]
            .iter()
            .any(|key| prefix.ends_with(key))
        {
            targets.extend(shell_targets(&value));
        }
        if value.contains("*** Begin Patch") {
            targets.extend(patch_targets(&value));
        }
    }
    dedup_targets(targets)
}

fn js_string_literals(script: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut chars = script.char_indices().peekable();
    while let Some((start, quote)) = chars.next() {
        if !matches!(quote, '\'' | '"' | '`') {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, ch) in chars.by_ref() {
            if escaped {
                value.push(match ch {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                out.push((start, value));
                break;
            } else {
                value.push(ch);
            }
        }
    }
    out
}

fn dedup_targets(targets: Vec<(Action, String)>) -> Vec<(Action, String)> {
    let mut seen = HashSet::new();
    targets
        .into_iter()
        .filter(|target| seen.insert(target.clone()))
        .collect()
}

fn patch_targets(patch: &str) -> Vec<(Action, String)> {
    patch
        .lines()
        .filter_map(|l| {
            l.strip_prefix("*** Update File: ")
                .or_else(|| l.strip_prefix("*** Add File: "))
                .or_else(|| l.strip_prefix("*** Delete File: "))
                .map(|p| (Action::Mutate, p.trim().to_string()))
        })
        .collect()
}

/// Real BPE token count (o200k). Falls back to len/4 only if the tokenizer fails to load.
pub(crate) fn estimate_tokens(text: &str) -> usize {
    static BPE: std::sync::OnceLock<Option<tiktoken_rs::CoreBPE>> = std::sync::OnceLock::new();
    match BPE.get_or_init(|| tiktoken_rs::o200k_base().ok()) {
        Some(bpe) => bpe.encode_ordinary(text).len(),
        None => text.len() / 4,
    }
}

fn text_of(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .filter_map(|i| i["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

// ---------- rules ----------

#[derive(Serialize, Clone)]
pub(crate) struct Finding {
    pub rule: &'static str,
    pub event_idx: usize,
    pub event_id: String,
    pub detail: String,
    pub tokens: usize,
}

struct Op {
    idx: usize,
    id: String,
    call_id: String,
    action: Action,
    path: String,
}

pub(crate) fn analyze(events: &[Event]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut ops: Vec<Op> = Vec::new();
    let mut result_tokens: HashMap<String, usize> = HashMap::new();
    let mut call_desc: HashMap<String, String> = HashMap::new();
    let mut results: Vec<(usize, String, String)> = Vec::new();

    for (idx, ev) in events.iter().enumerate() {
        for item in &ev.items {
            match item {
                Item::Thinking(t) => {
                    let tokens = estimate_tokens(t);
                    if tokens > THINKING_THRESHOLD {
                        findings.push(Finding {
                            rule: "huge-thinking",
                            event_idx: idx,
                            event_id: ev.id.clone(),
                            detail: format!("thinking block of ~{tokens} tok — condense or drop"),
                            tokens,
                        });
                    }
                }
                Item::ToolCall {
                    call_id,
                    desc,
                    targets,
                } => {
                    call_desc.insert(call_id.clone(), desc.clone());
                    for (action, path) in targets {
                        ops.push(Op {
                            idx,
                            id: ev.id.clone(),
                            call_id: call_id.clone(),
                            action: *action,
                            path: path.clone(),
                        });
                    }
                }
                Item::ToolResult { call_id, tokens } => {
                    result_tokens.insert(call_id.clone(), *tokens);
                    results.push((idx, ev.id.clone(), call_id.clone()));
                }
                Item::Text(_) => {}
            }
        }
    }

    // A read is dead weight if the same path is re-read later (superseded)
    // or edited later (stale). Reads after the last mutation are fresh.
    let read_counts: HashMap<&str, usize> =
        ops.iter()
            .filter(|op| op.action == Action::Read)
            .fold(HashMap::new(), |mut counts, op| {
                *counts.entry(op.call_id.as_str()).or_default() += 1;
                counts
            });
    let mut read_positions: HashMap<&str, usize> = HashMap::new();
    let mut flagged: HashSet<&str> = HashSet::new();
    for (i, op) in ops.iter().enumerate() {
        if op.action != Action::Read {
            continue;
        }
        let later_read = ops[i + 1..]
            .iter()
            .find(|o| o.path == op.path && o.action == Action::Read && o.call_id != op.call_id);
        let later_mutate = ops[i + 1..]
            .iter()
            .find(|o| o.path == op.path && o.action == Action::Mutate);
        let total = result_tokens.get(&op.call_id).copied().unwrap_or(0);
        let count = read_counts.get(op.call_id.as_str()).copied().unwrap_or(1);
        let position = read_positions.entry(op.call_id.as_str()).or_default();
        let tokens = total / count + usize::from(*position < total % count);
        *position += 1;
        if let Some(r) = later_read {
            findings.push(Finding {
                rule: "superseded-read",
                event_idx: op.idx,
                event_id: op.id.clone(),
                detail: format!(
                    "{} re-read at #{} — this earlier copy is dead weight",
                    op.path, r.idx
                ),
                tokens,
            });
            flagged.insert(&op.call_id);
        } else if let Some(m) = later_mutate {
            findings.push(Finding {
                rule: "stale-read",
                event_idx: op.idx,
                event_id: op.id.clone(),
                detail: format!(
                    "{} edited at #{} — this read no longer matches disk",
                    op.path, m.idx
                ),
                tokens,
            });
            flagged.insert(&op.call_id);
        }
    }

    for (idx, id, call_id) in &results {
        let tokens = result_tokens.get(call_id).copied().unwrap_or(0);
        if tokens > OUTPUT_THRESHOLD && !flagged.contains(call_id.as_str()) {
            let desc = call_desc
                .get(call_id)
                .cloned()
                .unwrap_or_else(|| "tool".into());
            findings.push(Finding {
                rule: "huge-output",
                event_idx: *idx,
                event_id: id.clone(),
                detail: format!("{desc} returned ~{tokens} tok — trim or summarize"),
                tokens,
            });
        }
    }

    findings.sort_by_key(|finding| Reverse(finding.tokens));
    findings
}

// ---------- report ----------

#[derive(Serialize, Clone)]
pub(crate) struct Semantic {
    pub contradiction: String,
    pub bloating: String,
    pub model_used: String,
}

#[derive(Serialize, Clone)]
pub(crate) struct Summary {
    pub total_events: usize,
    pub session_tokens: usize,
    pub findings: usize,
    pub reclaimable_tokens: usize,
    pub reclaimable_pct: usize,
}

#[derive(Serialize, Clone)]
pub(crate) struct Report {
    pub version: u8,
    pub session: String,
    pub findings: Vec<Finding>,
    pub semantic: Option<Semantic>,
    pub summary: Summary,
}

pub(crate) fn build_report(
    session: String,
    events: &[Event],
    semantic: Option<Semantic>,
) -> Report {
    let findings = analyze(events);
    let session_tokens: usize = events
        .iter()
        .flat_map(|e| &e.items)
        .map(|i| match i {
            Item::Text(t) | Item::Thinking(t) => estimate_tokens(t),
            Item::ToolResult { tokens, .. } => *tokens,
            Item::ToolCall { .. } => 0,
        })
        .sum();
    let reclaimable: usize = findings.iter().map(|f| f.tokens).sum();
    Report {
        version: REPORT_VERSION,
        session,
        summary: Summary {
            total_events: events.len(),
            session_tokens,
            findings: findings.len(),
            reclaimable_tokens: reclaimable,
            reclaimable_pct: reclaimable * 100 / session_tokens.max(1),
        },
        findings,
        semantic,
    }
}

pub(crate) fn semantic(events: &[Event]) -> Result<Semantic> {
    let mut digest = String::new();
    for ev in events {
        for item in &ev.items {
            match item {
                Item::Text(t) => digest.push_str(&format!("\n--- {} ---\n{}\n", ev.role, t)),
                Item::Thinking(t) => digest.push_str(&format!("\n--- thinking ---\n{}\n", t)),
                _ => {}
            }
        }
    }
    let digest = cap_middle(digest, SEMANTIC_DIGEST_CAP);
    let prompt = format!(
        "Analyze the conversation for context rot. Find CONTRADICTIONS and BLOATING. Be specific.\n\nCONTRADICTIONS:\n- <list>\n\nBLOATING:\n- <list>\n\nConversation:\n{digest}"
    );
    llm_sections(&prompt)
}

pub(crate) fn cap_middle(s: String, cap: usize) -> String {
    if s.len() <= cap {
        return s;
    }
    let cut = |at: usize| {
        let mut i = at.min(s.len());
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    format!(
        "{}\n[... middle truncated ...]\n{}",
        &s[..cut(cap / 2)],
        &s[cut(s.len() - cap / 2)..]
    )
}

pub(crate) fn llm_sections(prompt: &str) -> Result<Semantic> {
    let model = semantic_model();
    let sh = std::process::Command::new("pi")
        .args(["-p", prompt, "--model", &model])
        .output()?;
    if !sh.status.success() {
        let detail = clip(String::from_utf8_lossy(&sh.stderr).trim(), 300);
        anyhow::bail!(
            "pi failed with status {}{}",
            sh.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }
    let stdout = String::from_utf8_lossy(&sh.stdout);
    let (contradiction, bloating) = parse_semantic_sections(&stdout);
    Ok(Semantic {
        contradiction,
        bloating,
        model_used: model,
    })
}

fn parse_semantic_sections(output: &str) -> (String, String) {
    // A heading is a short non-bullet line naming the section; bullets under the
    // current heading are collected, blank lines and prose are skipped.
    let heading_of = |t: &str| -> Option<usize> {
        if t.len() >= 60 || t.starts_with("- ") || t.starts_with("* ") {
            return None;
        }
        let u = t.to_uppercase();
        if u.contains("CONTRADICTION") {
            Some(0)
        } else if ["BLOAT", "DUPLICATION", "REDUNDAN"]
            .iter()
            .any(|k| u.contains(k))
        {
            Some(1)
        } else {
            None
        }
    };
    let mut sections = [String::new(), String::new()];
    let mut cur: Option<usize> = None;
    for line in output.lines() {
        let t = line.trim();
        if let Some(i) = heading_of(t) {
            cur = Some(i);
            continue;
        }
        if let Some(i) = cur
            && (t.starts_with("- ") || t.starts_with("* "))
        {
            let body = t.trim_start_matches(['-', '*']).trim();
            sections[i].push_str(&format!("- {body}\n"));
        }
    }
    let done = |s: String| {
        if s.is_empty() {
            "(no findings)".to_string()
        } else {
            s.trim_end().to_string()
        }
    };
    let [c, b] = sections;
    (done(c), done(b))
}

// ---------- output ----------

pub(crate) fn tok_fmt(n: usize) -> String {
    if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

pub(crate) fn ago(t: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(t)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match secs {
        0..=59 => format!("{}s", secs.max(1)),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

pub(crate) fn size_fmt(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{}K", n / 1000)
    } else {
        format!("{n}B")
    }
}

pub(crate) fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        format!(
            "{}…",
            s.chars().take(n.saturating_sub(1)).collect::<String>()
        )
    }
}

fn human(r: &Report) {
    let s = &r.summary;
    println!("cxwatch — {}", r.session);
    println!(
        "  events {} · session ≈{} tok · {} findings · ≈{} tok reclaimable ({}%)",
        s.total_events,
        tok_fmt(s.session_tokens),
        s.findings,
        tok_fmt(s.reclaimable_tokens),
        s.reclaimable_pct
    );
    for f in &r.findings {
        println!(
            "  {:<16} {:>8}  #{:<5} {}",
            f.rule,
            format!("~{}", tok_fmt(f.tokens)),
            f.event_idx,
            f.detail
        );
    }
    if let Some(sem) = &r.semantic {
        println!("  semantic ({}):", sem.model_used);
        println!(
            "    contradictions:\n      {}",
            sem.contradiction.replace('\n', "\n      ")
        );
        println!(
            "    bloating:\n      {}",
            sem.bloating.replace('\n', "\n      ")
        );
    }
}

pub(crate) fn markdown(r: &Report) -> String {
    let s = &r.summary;
    let mut md = format!(
        "# cxwatch report\n\n- Session: `{}`\n- Events: {}\n- Session size: ~{} tok\n- Findings: {}\n- Reclaimable: ~{} tok ({}%)\n\n## Findings\n\n",
        r.session,
        s.total_events,
        tok_fmt(s.session_tokens),
        s.findings,
        tok_fmt(s.reclaimable_tokens),
        s.reclaimable_pct
    );
    if r.findings.is_empty() {
        md.push_str("No mechanical rot detected.\n");
    }
    for f in &r.findings {
        md.push_str(&format!(
            "- **{}** (#{}): {} — ~{} tok\n",
            f.rule,
            f.event_idx,
            f.detail,
            tok_fmt(f.tokens)
        ));
    }
    if let Some(sem) = &r.semantic {
        md.push_str(&format!(
            "\n## Semantic ({})\n\n### Contradictions\n{}\n\n### Bloating\n{}\n",
            sem.model_used, sem.contradiction, sem.bloating
        ));
    }
    md
}

// ---------- subcommands ----------

fn load(session: Option<PathBuf>, want_semantic: bool) -> Result<Report> {
    let path = match session {
        Some(p) => p,
        None => latest_session()?,
    };
    let events = parse(&path)?;
    let semantic = want_semantic.then(|| {
        semantic(&events).unwrap_or_else(|e| Semantic {
            contradiction: format!("semantic unavailable: {e}"),
            bloating: String::new(),
            model_used: semantic_model(),
        })
    });
    Ok(build_report(path.display().to_string(), &events, semantic))
}

fn report_cmd(session: Option<PathBuf>, json: bool, want_semantic: bool) -> Result<()> {
    let r = load(session, want_semantic)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        human(&r);
    }
    Ok(())
}

fn explain_cmd(session: Option<PathBuf>, output: Option<String>) -> Result<()> {
    let r = load(session, true)?;
    let out = output.unwrap_or_else(|| "cxwatch-demo.md".into());
    std::fs::write(&out, markdown(&r))?;
    println!("wrote {out}");
    Ok(())
}

fn sessions_cmd() -> Result<()> {
    for (i, s) in sessions().iter().enumerate() {
        println!(
            "[{:>4}] {:<7} {:>4} {:>7}  {:<40}  {}",
            i + 1,
            s.source.label(),
            ago(s.modified),
            size_fmt(s.size),
            clip(&s.title, 40),
            s.path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pi_call(id: &str, call_id: &str, name: &str, args: Value) -> Event {
        parse_line(
            &json!({"type":"message","id":id,"message":{"role":"assistant","content":[
            {"type":"toolCall","id":call_id,"name":name,"arguments":args}]}}),
        )
        .unwrap()
    }

    fn pi_result(call_id: &str, text: &str) -> Event {
        parse_line(
            &json!({"type":"message","id":"r","message":{"role":"toolResult",
            "toolCallId":call_id,"content":[{"type":"text","text":text}]}}),
        )
        .unwrap()
    }

    #[test]
    fn stale_read_flags_the_earlier_read() {
        let payload = "some file content that was read ".repeat(20);
        let events = vec![
            pi_call("a", "c1", "read", json!({"path":"/x"})),
            pi_result("c1", &payload),
            pi_call("b", "c2", "edit", json!({"path":"/x"})),
        ];
        let f = analyze(&events);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "stale-read");
        assert_eq!(f[0].event_idx, 0);
        assert_eq!(f[0].tokens, estimate_tokens(&payload)); // priced from the tool result, not the call
    }

    #[test]
    fn read_after_edit_is_fresh() {
        let events = vec![
            pi_call("a", "c1", "edit", json!({"path":"/x"})),
            pi_call("b", "c2", "read", json!({"path":"/x"})),
        ];
        assert!(analyze(&events).is_empty());
    }

    #[test]
    fn superseded_read_flags_the_earlier_copy() {
        let payload = "line of file content here ".repeat(10);
        let events = vec![
            pi_call("a", "c1", "read", json!({"path":"/f"})),
            pi_result("c1", &payload),
            pi_call("b", "c2", "read", json!({"path":"/f"})),
        ];
        let f = analyze(&events);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "superseded-read");
        assert_eq!(f[0].event_idx, 0);
        assert_eq!(f[0].tokens, estimate_tokens(&payload));
    }

    #[test]
    fn huge_thinking() {
        let thinking = "thinking about the problem in detail ".repeat(500);
        assert!(estimate_tokens(&thinking) > 2000);
        let ev = parse_line(
            &json!({"type":"message","id":"t","message":{"role":"assistant",
            "content":[{"type":"thinking","thinking":thinking}]}}),
        )
        .unwrap();
        let f = analyze(&[ev]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "huge-thinking");
    }

    #[test]
    fn huge_output() {
        let payload = "a long line of interesting command output ".repeat(400);
        assert!(estimate_tokens(&payload) > 2500);
        let events = vec![
            pi_call("a", "c1", "bash", json!({"command":"ls -la"})),
            pi_result("c1", &payload),
        ];
        let f = analyze(&events);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "huge-output");
        assert_eq!(f[0].tokens, estimate_tokens(&payload));
    }

    #[test]
    fn claude_format_parses_tool_use_and_result() {
        let call = parse_line(&json!({"type":"assistant","uuid":"u1","message":{"role":"assistant",
            "content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/a.rs"}}]}}))
        .unwrap();
        let payload = "fn main() { println!(\"hi\"); } ".repeat(15);
        let result = parse_line(&json!({"type":"user","uuid":"u2","message":{"role":"user",
            "content":[{"type":"tool_result","tool_use_id":"t1","content":payload}]}}))
        .unwrap();
        let edit = parse_line(&json!({"type":"assistant","uuid":"u3","message":{"role":"assistant",
            "content":[{"type":"tool_use","id":"t2","name":"Edit","input":{"file_path":"/a.rs"}}]}}))
        .unwrap();
        let f = analyze(&[call, result, edit]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "stale-read");
        assert_eq!(f[0].tokens, estimate_tokens(&payload));
    }

    #[test]
    fn opencode_tool_part_yields_call_and_result() {
        let part = json!({"type":"tool","tool":"read","callID":"c1",
            "state":{"status":"completed","input":{"filePath":"/a.rs"},"output":"file contents here"}});
        let items = opencode_items(&part);
        assert_eq!(items.len(), 2);
        let Item::ToolCall { targets, .. } = &items[0] else {
            panic!("expected call")
        };
        assert_eq!(targets, &vec![(Action::Read, "/a.rs".to_string())]);
        let Item::ToolResult { call_id, tokens } = &items[1] else {
            panic!("expected result")
        };
        assert_eq!(call_id, "c1");
        assert_eq!(*tokens, estimate_tokens("file contents here"));
        assert!(matches!(
            opencode_items(&json!({"type":"reasoning","text":"hmm"}))[0],
            Item::Thinking(_)
        ));
        assert!(opencode_items(&json!({"type":"step-start"})).is_empty());
    }

    #[test]
    fn codex_function_call_string_args() {
        let ev = parse_line(
            &json!({"type":"response_item","payload":{"type":"function_call",
            "name":"exec_command","call_id":"c9",
            "arguments":"{\"cmd\":\"ls && sed -n '1,240p' plan.md\"}"}}),
        )
        .unwrap();
        let Item::ToolCall { targets, .. } = &ev.items[0] else {
            panic!("expected tool call")
        };
        assert_eq!(targets, &[(Action::Read, "plan.md".to_string())]);
    }

    #[test]
    fn codex_custom_tool_call_and_output_parse() {
        let call = parse_line(&json!({"type":"response_item","payload":{
            "type":"custom_tool_call","name":"apply_patch","call_id":"c10",
            "input":"*** Begin Patch\n*** Update File: src/main.rs\n*** End Patch"}}))
        .expect("custom tool call");
        let Item::ToolCall { targets, .. } = &call.items[0] else {
            panic!("expected tool call")
        };
        assert_eq!(targets, &[(Action::Mutate, "src/main.rs".to_string())]);

        let result = parse_line(&json!({"type":"response_item","payload":{
            "type":"custom_tool_call_output","call_id":"c10",
            "output":[{"type":"input_text","text":"Done!"}]}}))
        .expect("custom tool output");
        let Item::ToolResult { call_id, tokens } = &result.items[0] else {
            panic!("expected tool result")
        };
        assert_eq!(call_id, "c10");
        assert_eq!(*tokens, estimate_tokens("Done!"));
    }

    #[test]
    fn codex_custom_exec_extracts_nested_file_operations() {
        let input = r#"const a = await tools.exec_command({cmd:"cat a.txt; sed -i 's/a/b/' b.txt"});
const patch = "*** Begin Patch\n*** Update File: c.txt\n*** End Patch";
await tools.apply_patch(patch);"#;
        let call = parse_line(&json!({"type":"response_item","payload":{
            "type":"custom_tool_call","name":"exec","call_id":"c11","input":input}}))
        .expect("custom exec call");
        let Item::ToolCall { targets, .. } = &call.items[0] else {
            panic!("expected tool call")
        };
        assert_eq!(
            targets,
            &[
                (Action::Read, "a.txt".into()),
                (Action::Mutate, "b.txt".into()),
                (Action::Mutate, "c.txt".into()),
            ]
        );
    }

    #[test]
    fn one_result_is_not_counted_once_per_file() {
        let payload = "contents from two files";
        let events = vec![
            pi_call("a", "c1", "bash", json!({"command":"cat a.txt; cat b.txt"})),
            pi_result("c1", payload),
            pi_call("b", "c2", "read", json!({"path":"a.txt"})),
            pi_call("c", "c3", "read", json!({"path":"b.txt"})),
        ];
        let report = build_report("test".into(), &events, None);
        assert_eq!(report.summary.reclaimable_tokens, estimate_tokens(payload));
        assert!(report.summary.reclaimable_pct <= 100);
    }

    #[test]
    fn shell_edits_are_mutations() {
        let targets = tool_targets(
            "exec_command",
            &json!({"cmd":"cat a.txt; sed -i 's/a/b/' b.txt; printf x > c.txt"}),
        );
        assert_eq!(
            targets,
            vec![
                (Action::Read, "a.txt".into()),
                (Action::Mutate, "b.txt".into()),
                (Action::Mutate, "c.txt".into()),
            ]
        );
    }

    #[test]
    fn semantic_sections_survive_llm_formatting() {
        let out = "Here is my analysis.\n\n### CONTRADICTIONS\n\n- A says tabs, B says spaces\n\nSome prose.\n\n**Duplication:**\n\n- C and D both say run tests\n- E repeats C\n";
        let (c, b) = parse_semantic_sections(out);
        assert_eq!(c, "- A says tabs, B says spaces");
        assert_eq!(b, "- C and D both say run tests\n- E repeats C");
        let (c2, b2) = parse_semantic_sections("nothing structured at all");
        assert_eq!(c2, "(no findings)");
        assert_eq!(b2, "(no findings)");
    }

    #[test]
    fn shell_reader_extraction() {
        assert_eq!(
            shell_targets("cat /tmp/foo"),
            vec![(Action::Read, "/tmp/foo".into())]
        );
        assert_eq!(
            shell_targets("ls | head -n 50 src/main.rs"),
            vec![(Action::Read, "src/main.rs".into())]
        );
        assert_eq!(
            shell_targets("sed -i 's/a/b/' f.txt"),
            vec![(Action::Mutate, "f.txt".into())]
        );
    }
}
