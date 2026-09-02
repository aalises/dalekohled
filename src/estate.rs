use crate::{Semantic, tok_fmt};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const GRACE_DAYS: u64 = 14;
const STALE_DAYS: u64 = 120;
const HOOK_TAX_MIN_TOKENS: usize = 500;
const HEAVY_BLOCK_TOKENS: usize = 400;
const LONG_SESSION_TOKENS: usize = 150_000;
const CMD_DENY_MIN: usize = 3;
const CMD_FAIL_MIN: usize = 3;
const DIRECTIVE_MIN_SESSIONS: usize = 3;
const DENIAL_MARKER: &str = "doesn't want to proceed";

#[derive(Serialize, Clone)]
pub(crate) struct EstateFinding {
    pub rule: &'static str,
    pub unit: String,
    /// Absolute path of the file to touch when acting on this finding.
    pub path: String,
    /// Concrete remediation: the command to run or edit to make.
    pub fix: String,
    /// Unit cost in tokens (0 = unknown, e.g. MCP servers whose schemas load remotely).
    pub tokens: usize,
    pub uses: usize,
    pub detail: String,
    pub action: &'static str,
}

#[derive(Serialize, Clone)]
pub(crate) struct EstateSummary {
    pub sessions_claude: usize,
    pub sessions_codex: usize,
    pub sessions_pi: usize,
    pub sessions_cursor: usize,
    pub units: usize,
    pub findings: usize,
    pub tokens_flagged: usize,
}

#[derive(Serialize, Clone)]
pub(crate) struct Block {
    pub file: String,
    pub heading: String,
    pub tokens: usize,
}

#[derive(Serialize, Clone)]
pub(crate) struct SessionStat {
    pub harness: &'static str,
    pub sessions: usize,
    pub median_tokens: usize,
    pub p90_tokens: usize,
    pub over_long: usize,
}

#[derive(Serialize, Clone)]
pub(crate) struct EstateReport {
    pub version: u8,
    pub findings: Vec<EstateFinding>,
    /// Always-loaded instruction files priced per heading block.
    pub blocks: Vec<Block>,
    /// Rough per-harness session size distribution; only harnesses with sessions.
    pub session_stats: Vec<SessionStat>,
    /// Positive usage counts, for JSON consumers and the semantic digest.
    pub usage: Vec<String>,
    /// Short user messages observed across sessions ("N× text"), for JSON
    /// consumers and the semantic paraphrase pass.
    pub directives: Vec<String>,
    pub semantic: Option<Semantic>,
    pub summary: EstateSummary,
}

// ---------- usage join: what the transcripts actually show ----------

#[derive(Default)]
struct HookStat {
    fires: usize,
    tokens: usize,
    sample: String,
}

#[derive(Clone, Copy)]
enum Harness {
    Claude,
    Codex,
    Pi,
    Cursor,
}

impl Harness {
    fn idx(self) -> usize {
        match self {
            Harness::Claude => 0,
            Harness::Codex => 1,
            Harness::Pi => 2,
            Harness::Cursor => 3,
        }
    }
}

#[derive(Default)]
struct CmdStat {
    runs: usize,
    fails: usize,   // is_error results that are not permission denials
    denials: usize, // permission-denied results
    fail_tokens: usize,
    sample: String, // one failing invocation, first line
}

#[derive(Default)]
struct DirectiveStat {
    sessions: usize, // distinct sessions the message was typed in
    sample: String,  // original casing
}

#[derive(Default)]
struct Usage {
    claude_sessions: usize,
    codex_sessions: usize,
    pi_sessions: usize,
    cursor_sessions: usize,
    skills: HashMap<String, usize>, // Skill tool invocations (claude)
    commands: HashMap<String, usize>, // slash commands (claude)
    mcp_claude: HashMap<String, usize>, // mcp__server__ calls per harness
    mcp_codex: HashMap<String, usize>,
    hooks: HashMap<String, HookStat>,
    skill_reads_claude: HashMap<String, usize>,
    skill_reads_codex: HashMap<String, usize>,
    skill_reads_pi: HashMap<String, usize>,
    skill_reads_cursor: HashMap<String, usize>,
    bash: HashMap<String, CmdStat>, // per command head, claude only
    directives: HashMap<String, DirectiveStat>, // normalized short user messages, claude only
    session_toks: [Vec<usize>; 4],  // rough tokens per session, indexed by Harness::idx
}

fn scan_usage(home: &Path) -> Usage {
    let mut u = Usage::default();
    let roots = [
        (home.join(".claude/projects"), Harness::Claude),
        (home.join(".codex/sessions"), Harness::Codex),
        (home.join(".codex/archived_sessions"), Harness::Codex),
        (home.join(".pi/agent/sessions"), Harness::Pi),
    ];
    for (root, harness) in roots {
        let mut files = Vec::new();
        crate::walk_jsonl(&root, &mut files);
        for f in files {
            let Ok(s) = std::fs::read_to_string(&f) else {
                continue;
            };
            count_transcript(&s, harness, &mut u);
        }
    }
    for bubbles in crate::cursor_bubbles() {
        count_cursor_session(&bubbles, &mut u);
    }
    u
}

fn count_transcript(hay: &str, harness: Harness, usage: &mut Usage) {
    usage.session_toks[harness.idx()].push(token_estimate(hay));
    match harness {
        Harness::Claude => {
            usage.claude_sessions += 1;
            count_skill_reads(hay, &mut usage.skill_reads_claude);
            count_captures(
                hay,
                "\"name\":\"Skill\",\"input\":{\"skill\":\"",
                |c| c == '"',
                &mut usage.skills,
            );
            count_captures(
                hay,
                "<command-name>/",
                |c| !(c.is_ascii_alphanumeric() || "-_:".contains(c)),
                &mut usage.commands,
            );
            count_mcp(hay, &mut usage.mcp_claude);
            count_hooks(hay, &mut usage.hooks);
            count_bash_outcomes(hay, &mut usage.bash);
            count_directives(hay, &mut usage.directives);
        }
        Harness::Codex => {
            usage.codex_sessions += 1;
            count_skill_reads(hay, &mut usage.skill_reads_codex);
            count_mcp(hay, &mut usage.mcp_codex);
        }
        Harness::Pi => {
            usage.pi_sessions += 1;
            count_skill_reads(hay, &mut usage.skill_reads_pi);
        }
        // cursor sessions arrive as parsed bubbles, see count_cursor_session
        Harness::Cursor => usage.cursor_sessions += 1,
    }
}

/// Cursor keeps tool arguments and results as JSON-encoded strings inside
/// each turn's bubble, so usage is read from parsed bubbles rather than raw
/// substrings. Size is content chars / 4: nothing is duplicated here, unlike
/// the JSONL transcripts; within ~10% of the o200k count on real chats.
fn count_cursor_session(bubbles: &[Value], usage: &mut Usage) {
    usage.cursor_sessions += 1;
    let mut chars = 0usize;
    for bubble in bubbles {
        chars += bubble["text"].as_str().map_or(0, str::len)
            + bubble["thinking"]["text"].as_str().map_or(0, str::len);
        let tool = &bubble["toolFormerData"];
        let Some(name) = tool["name"].as_str() else {
            continue;
        };
        chars += crate::cursor_result_text(tool).len();
        for (action, path) in crate::tool_targets(name, &crate::cursor_args(tool)) {
            if action == crate::Action::Read
                && let Some(skill) = skill_from_path(&path)
            {
                *usage.skill_reads_cursor.entry(skill).or_default() += 1;
            }
        }
    }
    usage.session_toks[Harness::Cursor.idx()].push(chars / 4);
}

/// `<anything>/skills/<name>/SKILL.md` -> `<name>`.
fn skill_from_path(path: &str) -> Option<String> {
    let (dir, name) = path.strip_suffix("/SKILL.md")?.rsplit_once('/')?;
    let valid = !name.is_empty()
        && name.len() < 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    (valid && dir.rsplit('/').next() == Some("skills")).then(|| name.to_string())
}

fn count_captures(
    hay: &str,
    pat: &str,
    stop: impl Fn(char) -> bool,
    map: &mut HashMap<String, usize>,
) {
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        let end = rest.find(&stop).unwrap_or(rest.len());
        if end > 0 && end < 64 {
            *map.entry(rest[..end].to_string()).or_default() += 1;
        }
    }
}

fn count_mcp(hay: &str, map: &mut HashMap<String, usize>) {
    for pat in ["\"name\":\"mcp__", "tools.mcp__"] {
        count_mcp_pattern(hay, pat, map);
    }
}

fn count_mcp_pattern(hay: &str, pat: &str, map: &mut HashMap<String, usize>) {
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        if let Some(end) = rest.find("__")
            && end > 0
            && end < 64
        {
            *map.entry(rest[..end].to_string()).or_default() += 1;
        }
    }
}

fn count_hooks(hay: &str, map: &mut HashMap<String, HookStat>) {
    let pat = "\"type\":\"hook_success\",\"hookName\":\"";
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        let Some(nend) = rest.find('"') else { continue };
        let name = rest[..nend].to_string();
        let mut window_end = rest.len().min(nend + 300);
        while !rest.is_char_boundary(window_end) {
            window_end -= 1;
        }
        let window = &rest[nend..window_end];
        let tokens = window
            .find("\"content\":\"")
            .map(|ci| {
                let body_start = nend + ci + 11;
                let len = escaped_len(&rest[body_start..]);
                let raw = &rest[body_start..body_start + len];
                let decoded = serde_json::from_str::<String>(&format!("\"{raw}\""))
                    .unwrap_or_else(|_| raw.to_string());
                let e = map.entry(name.clone()).or_default();
                if e.sample.is_empty() {
                    e.sample = crate::clip(&decoded, 2_000);
                }
                crate::estimate_tokens(&decoded)
            })
            .unwrap_or(0);
        let e = map.entry(name).or_default();
        e.fires += 1;
        e.tokens += tokens;
    }
}

/// Tool-call reads of `skills/<name>/SKILL.md` — how pi/codex load skills.
/// Requires a read marker near the match so prose mentions of skill paths
/// (e.g. in an embedded CLAUDE.md) don't count as usage.
fn count_skill_reads(hay: &str, map: &mut HashMap<String, usize>) {
    for (i, _) in hay.match_indices("/SKILL.md") {
        let mut start = i.saturating_sub(160);
        while !hay.is_char_boundary(start) {
            start += 1;
        }
        let back = &hay[start..i];
        let is_read = ["path\\\":", "path\":\"", "sed ", "cat ", "head "]
            .iter()
            .any(|m| back.contains(m));
        if !is_read {
            continue;
        }
        if let Some(j) = back.rfind("skills/") {
            let name = &back[j + 7..];
            if !name.is_empty()
                && name.len() < 64
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                *map.entry(name.to_string()).or_default() += 1;
            }
        }
    }
}

/// Rough per-session token estimate from the content-bearing JSON string
/// fields. Transcript formats duplicate result text (in-message plus a
/// line-level copy), so this divides by 8 instead of chars/4; calibrated
/// against the o200k-based session audit (within ~±20%).
fn token_estimate(hay: &str) -> usize {
    let mut chars = 0usize;
    for pat in [
        "\"text\":\"",
        "\"thinking\":\"",
        "\"content\":\"",
        "\"output\":\"",
    ] {
        for (i, _) in hay.match_indices(pat) {
            chars += escaped_len(&hay[i + pat.len()..]);
        }
    }
    chars / 8
}

/// Normalize a shell command to a stable head ("git push", "rg"), skipping a
/// leading `cd dir &&`.
fn command_head(cmd: &str) -> String {
    let cmd = cmd.trim_start();
    let cmd = if cmd.starts_with("cd ") {
        cmd.split_once("&&")
            .map(|(_, r)| r.trim_start())
            .unwrap_or(cmd)
    } else {
        cmd
    };
    let mut toks = cmd.split_whitespace();
    let first = toks.next().unwrap_or("?").to_string();
    const WITH_SUBCOMMAND: [&str; 12] = [
        "git", "cargo", "npm", "pnpm", "yarn", "docker", "kubectl", "gh", "go", "uv", "brew",
        "make",
    ];
    if WITH_SUBCOMMAND.contains(&first.as_str())
        && let Some(second) = toks.next()
        && !second.starts_with('-')
    {
        return format!("{first} {second}");
    }
    first
}

/// Pair Bash tool calls with their results and record failures and
/// permission denials per command head (claude transcripts only).
fn count_bash_outcomes(hay: &str, map: &mut HashMap<String, CmdStat>) {
    let mut pending: HashMap<String, (String, String)> = HashMap::new(); // call id -> (head, command)
    for line in hay.lines() {
        if !line.contains("\"name\":\"Bash\"") && !line.contains("\"tool_use_id\":") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(items) = v["message"]["content"].as_array() else {
            continue;
        };
        for item in items {
            match item["type"].as_str() {
                Some("tool_use") if item["name"] == "Bash" => {
                    if let (Some(id), Some(cmd)) =
                        (item["id"].as_str(), item["input"]["command"].as_str())
                    {
                        let head = command_head(cmd);
                        map.entry(head.clone()).or_default().runs += 1;
                        pending.insert(id.to_string(), (head, cmd.to_string()));
                    }
                }
                Some("tool_result") => {
                    let Some((head, cmd)) = item["tool_use_id"]
                        .as_str()
                        .and_then(|id| pending.remove(id))
                    else {
                        continue;
                    };
                    if item["is_error"].as_bool() != Some(true) {
                        continue;
                    }
                    let text = crate::text_of(&item["content"]);
                    let stat = map.entry(head).or_default();
                    if text.contains(DENIAL_MARKER) {
                        stat.denials += 1;
                    } else {
                        stat.fails += 1;
                        stat.fail_tokens += crate::estimate_tokens(&text);
                        if stat.sample.is_empty() {
                            stat.sample = crate::clip(cmd.lines().next().unwrap_or(&cmd), 80);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Short instructions the user typed themselves, counted once per session
/// (claude transcripts only). Excludes slash-command wrappers, pasted output,
/// sidechains, and bare acknowledgements.
fn count_directives(hay: &str, map: &mut HashMap<String, DirectiveStat>) {
    const ACK_WORDS: [&str; 18] = [
        "yes", "no", "ok", "okay", "sure", "thanks", "thank", "great", "perfect", "nice", "cool",
        "lgtm", "go", "continue", "proceed", "done", "stop", "wait",
    ];
    let mut seen = HashSet::new();
    for line in hay.lines() {
        if !line.contains("\"type\":\"user\"") || line.contains("tool_result") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v["isSidechain"].as_bool() == Some(true) || v["message"]["role"] != "user" {
            continue;
        }
        let Some(text) = v["message"]["content"].as_str() else {
            continue;
        };
        let text = text.trim();
        if text.len() < 12
            || text.len() > 240
            || text.contains('\n')
            || text.starts_with(['<', '['])
        {
            continue;
        }
        let norm = text
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { ' ' })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let words = norm.split(' ').count();
        if words < 3 || ACK_WORDS.contains(&norm.split(' ').next().unwrap_or("")) {
            continue;
        }
        if !seen.insert(norm.clone()) {
            continue;
        }
        let e = map.entry(norm).or_default();
        e.sessions += 1;
        if e.sample.is_empty() {
            e.sample = text.to_string();
        }
    }
}

fn percentile(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    sorted[(sorted.len() - 1) * pct / 100]
}

/// Length of a JSON string body starting right after its opening quote.
fn escaped_len(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i,
            _ => i += 1,
        }
    }
    i
}

/// Server names differ across harnesses only in separators (chrome-devtools vs chrome_devtools).
fn canon(s: &str) -> String {
    s.chars()
        .filter(|c| !"-_".contains(*c))
        .collect::<String>()
        .to_lowercase()
}

fn uses_of(map: &HashMap<String, usize>, name: &str) -> usize {
    let c = canon(name);
    map.iter()
        .filter(|(k, _)| canon(k) == c)
        .map(|(_, v)| v)
        .sum()
}

// ---------- inventory + rules ----------

pub(crate) fn audit() -> EstateReport {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let usage = scan_usage(&home);
    let now = SystemTime::now();
    let mut findings = Vec::new();
    let mut units = 0usize;

    // Claude skills: ~/.claude/skills/*/SKILL.md
    let mut skill_names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/skills")) {
        for e in rd.flatten() {
            let f = e.path().join("SKILL.md");
            let Ok(md) = f.metadata() else { continue };
            let name = e.file_name().to_string_lossy().to_string();
            units += 1;
            // claude skills are invoked via the Skill tool or a slash command;
            // file reads are not the harness mechanism here (unlike codex/pi)
            let uses = usage.skills.get(&name).copied().unwrap_or(0)
                + usage.commands.get(&name).copied().unwrap_or(0);
            if usage.claude_sessions > 0
                && uses == 0
                && age_days(now, md.modified().ok()) > GRACE_DAYS
            {
                let reads = usage.skill_reads_claude.get(&name).copied().unwrap_or(0);
                let reads_note = if reads > 0 {
                    format!(" ({reads} raw file reads observed, hooks or manual)")
                } else {
                    String::new()
                };
                findings.push(EstateFinding {
                    rule: "dead-skill",
                    unit: format!("skill {name}"),
                    path: f.display().to_string(),
                    fix: format!(
                        "confirm with the user, then `rm -r {}`; if the guidance is still wanted, move the key lines into a doc that is read on demand instead of an always-listed skill",
                        f.parent().unwrap_or(&f).display()
                    ),
                    tokens: crate::estimate_tokens(&std::fs::read_to_string(&f).unwrap_or_default()),
                    uses: 0,
                    detail: format!(
                        "never invoked across {} claude sessions; its description is loaded every session{reads_note}{}",
                        usage.claude_sessions,
                        git_note(&f)
                    ),
                    action: "delete or demote",
                });
            }
            skill_names.push(name);
        }
    }

    // Codex plugin skills and pi package skills, judged by SKILL.md reads in their own transcripts
    let mut seen = HashSet::new();
    let mut plugin_skills = Vec::new();
    find_skill_mds(&home.join(".codex/plugins"), &mut plugin_skills, 8);
    for f in plugin_skills {
        if f.to_string_lossy().contains("staging") {
            continue;
        }
        push_harness_skill(
            &f,
            "codex",
            usage.codex_sessions,
            &usage.skill_reads_codex,
            &mut seen,
            &mut units,
            &mut findings,
            now,
        );
    }
    for f in pi_skill_files(&home.join(".pi/agent/npm")) {
        push_harness_skill(
            &f,
            "pi",
            usage.pi_sessions,
            &usage.skill_reads_pi,
            &mut seen,
            &mut units,
            &mut findings,
            now,
        );
    }
    for f in cursor_skill_files(&home.join(".cursor/skills")) {
        push_harness_skill(
            &f,
            "cursor",
            usage.cursor_sessions,
            &usage.skill_reads_cursor,
            &mut seen,
            &mut units,
            &mut findings,
            now,
        );
    }

    // Claude commands: ~/.claude/commands/*.md
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/commands")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "md") {
                continue;
            }
            let Ok(md) = p.metadata() else { continue };
            let name = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            units += 1;
            if usage.claude_sessions > 0
                && usage.commands.get(&name).copied().unwrap_or(0) == 0
                && age_days(now, md.modified().ok()) > GRACE_DAYS
            {
                findings.push(EstateFinding {
                    rule: "dead-command",
                    unit: format!("command /{name}"),
                    path: p.display().to_string(),
                    fix: format!("confirm with the user, then `rm {}`", p.display()),
                    tokens: crate::estimate_tokens(
                        &std::fs::read_to_string(&p).unwrap_or_default(),
                    ),
                    uses: 0,
                    detail: format!(
                        "never invoked across {} claude sessions{}",
                        usage.claude_sessions,
                        git_note(&p)
                    ),
                    action: "delete",
                });
            }
        }
    }

    // MCP servers: ~/.claude.json (global + per-project) and ~/.codex/config.toml
    let mut servers: Vec<(String, &'static str, String)> = Vec::new(); // name, harness, scope
    if let Ok(s) = std::fs::read_to_string(home.join(".claude.json"))
        && let Ok(v) = serde_json::from_str::<Value>(&s)
    {
        if let Some(m) = v["mcpServers"].as_object() {
            for k in m.keys() {
                servers.push((k.clone(), "claude", "global".into()));
            }
        }
        if let Some(projs) = v["projects"].as_object() {
            for (proj, pv) in projs {
                if let Some(m) = pv["mcpServers"].as_object() {
                    for k in m.keys() {
                        if !servers.iter().any(|(n, h, _)| n == k && *h == "claude") {
                            servers.push((
                                k.clone(),
                                "claude",
                                format!("project {}", proj.rsplit('/').next().unwrap_or(proj)),
                            ));
                        }
                    }
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string(home.join(".codex/config.toml")) {
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("[mcp_servers.") {
                let name = rest.trim_end_matches(']').trim_matches('"').to_string();
                if !name.contains('.') {
                    servers.push((name, "codex", "config.toml".into()));
                }
            }
        }
    }
    for (name, harness, scope) in &servers {
        let (own, other, other_label, sessions) = if *harness == "claude" {
            (
                &usage.mcp_claude,
                &usage.mcp_codex,
                "codex",
                usage.claude_sessions,
            )
        } else {
            (
                &usage.mcp_codex,
                &usage.mcp_claude,
                "claude",
                usage.codex_sessions,
            )
        };
        // no sessions of the harness = no evidence; say nothing about it
        if sessions == 0 {
            continue;
        }
        units += 1;
        if uses_of(own, name) == 0 {
            let cross = uses_of(other, name);
            let cross_note = if cross > 0 {
                format!(" (used {cross}× in {other_label}, keep it there only)")
            } else {
                String::new()
            };
            let config = if *harness == "claude" {
                ".claude.json"
            } else {
                ".codex/config.toml"
            };
            let fix = if *harness == "claude" {
                format!(
                    "run `claude mcp remove {name}` (or delete the \"{name}\" entry under mcpServers in ~/.claude.json)"
                )
            } else {
                format!(
                    "delete the `[mcp_servers.{name}]` block (and any `[mcp_servers.{name}.*]` sub-tables) from ~/.codex/config.toml"
                )
            };
            findings.push(EstateFinding {
                rule: "dead-mcp",
                unit: format!("mcp {harness}:{name}"),
                path: home.join(config).display().to_string(),
                fix,
                tokens: 0,
                uses: 0,
                detail: format!(
                    "mounted ({scope}), 0 calls across {sessions} {harness} sessions; instructions + tool listing paid every session{cross_note}"
                ),
                action: "disable",
            });
        }
    }

    // memory: ~/.claude/projects/*/memory
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/projects")) {
        for e in rd.flatten() {
            let mem = e.path().join("memory");
            if !mem.is_dir() {
                continue;
            }
            let project = crate::decode_slug(&e.file_name().to_string_lossy());
            let index_text = std::fs::read_to_string(mem.join("MEMORY.md")).unwrap_or_default();
            let indexed: HashSet<String> = index_links(&index_text).into_iter().collect();
            let mut on_disk: HashSet<String> = HashSet::new();
            let mut stale = 0usize;
            if let Ok(files) = std::fs::read_dir(&mem) {
                for f in files.flatten() {
                    let p = f.path();
                    let fname = p
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    if p.extension().is_none_or(|x| x != "md") || fname == "MEMORY.md" {
                        continue;
                    }
                    units += 1;
                    on_disk.insert(fname.clone());
                    let md = p.metadata().ok();
                    if age_days(now, md.and_then(|m| m.modified().ok())) > STALE_DAYS {
                        stale += 1;
                    }
                    let body = std::fs::read_to_string(&p).unwrap_or_default();
                    if !indexed.contains(&fname) {
                        let desc = body
                            .lines()
                            .find_map(|l| l.strip_prefix("description:"))
                            .map(|d| d.trim().to_string())
                            .unwrap_or_else(|| "<one-line summary>".into());
                        findings.push(EstateFinding {
                            rule: "orphan-memory",
                            unit: format!("memory {project}/{fname}"),
                            path: mem.join("MEMORY.md").display().to_string(),
                            fix: format!(
                                "append to {}: `- [{}]({fname}) — {desc}`",
                                mem.join("MEMORY.md").display(),
                                fname.trim_end_matches(".md")
                            ),
                            tokens: crate::estimate_tokens(&body),
                            uses: 0,
                            detail: "on disk but missing from MEMORY.md index, never loaded".into(),
                            action: "repair index",
                        });
                    }
                    let missing = missing_paths(&body);
                    if !missing.is_empty() {
                        findings.push(EstateFinding {
                            rule: "stale-ref",
                            unit: format!("memory {project}/{fname}"),
                            path: p.display().to_string(),
                            fix: format!(
                                "edit {} and update or remove each reference to: {}",
                                p.display(),
                                missing.join(", ")
                            ),
                            tokens: crate::estimate_tokens(&body),
                            uses: 0,
                            detail: format!("references missing path(s): {}", missing.join(", ")),
                            action: "update memory",
                        });
                    }
                }
            }
            for fname in indexed.difference(&on_disk) {
                findings.push(EstateFinding {
                    rule: "dangling-index",
                    unit: format!("memory {project}/{fname}"),
                    path: mem.join("MEMORY.md").display().to_string(),
                    fix: format!(
                        "delete the line containing `({fname})` from {}",
                        mem.join("MEMORY.md").display()
                    ),
                    tokens: 0,
                    uses: 0,
                    detail: "indexed in MEMORY.md but the file does not exist".into(),
                    action: "repair index",
                });
            }
            if stale > 0 {
                findings.push(EstateFinding {
                    rule: "stale-memory",
                    unit: format!("memory {project}"),
                    path: mem.display().to_string(),
                    fix: format!(
                        "review each file in {} with the user: delete obsolete ones, refresh the rest",
                        mem.display()
                    ),
                    tokens: 0,
                    uses: 0,
                    detail: format!(
                        "{stale} memor{} unmodified for over {STALE_DAYS} days",
                        if stale == 1 { "y" } else { "ies" }
                    ),
                    action: "review",
                });
            }
        }
    }

    // instruction files: duplicate directives + dead references
    let claude_md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap_or_default();
    if !claude_md.is_empty() {
        units += 1;
        for name in &skill_names {
            let mentions = claude_md.matches(name.as_str()).count();
            if mentions >= 2 {
                findings.push(EstateFinding {
                    rule: "duplicate-directive",
                    unit: format!("CLAUDE.md × skill {name}"),
                    path: home.join(".claude/CLAUDE.md").display().to_string(),
                    fix: format!(
                        "edit ~/.claude/CLAUDE.md: keep at most one `{name}` trigger line and delete the other mentions; the skill's own description already announces it"
                    ),
                    tokens: 0,
                    uses: mentions,
                    detail: format!(
                        "mentioned {mentions}× in CLAUDE.md on top of its own always-loaded skill description"
                    ),
                    action: "merge",
                });
            }
        }
    }
    // always-loaded instruction files: stale refs + per-block pricing
    let mut blocks: Vec<Block> = Vec::new();
    for (label, rel, body) in [
        ("CLAUDE.md", ".claude/CLAUDE.md", claude_md),
        (
            "codex AGENTS.md",
            ".codex/AGENTS.md",
            std::fs::read_to_string(home.join(".codex/AGENTS.md")).unwrap_or_default(),
        ),
        (
            "opencode AGENTS.md",
            ".config/opencode/AGENTS.md",
            std::fs::read_to_string(home.join(".config/opencode/AGENTS.md")).unwrap_or_default(),
        ),
    ] {
        let missing = missing_paths(&body);
        if !missing.is_empty() {
            findings.push(EstateFinding {
                rule: "stale-ref",
                unit: label.into(),
                path: home.join(rel).display().to_string(),
                fix: format!(
                    "edit {} and update or remove each reference to: {}",
                    home.join(rel).display(),
                    missing.join(", ")
                ),
                tokens: crate::estimate_tokens(&body),
                uses: 0,
                detail: format!("references missing path(s): {}", missing.join(", ")),
                action: "update instructions",
            });
        }
        for b in price_blocks(label, &body) {
            if b.tokens > HEAVY_BLOCK_TOKENS {
                findings.push(EstateFinding {
                    rule: "heavy-block",
                    unit: format!("{} § {}", b.file, b.heading),
                    path: home.join(rel).display().to_string(),
                    fix: format!(
                        "tighten the `{}` block in {} or move it into an on-demand skill/doc",
                        b.heading,
                        home.join(rel).display()
                    ),
                    tokens: b.tokens,
                    uses: 0,
                    detail: format!(
                        "~{} tok paid on every request of every session",
                        tok_fmt(b.tokens)
                    ),
                    action: "tighten",
                });
            }
            blocks.push(b);
        }
    }
    blocks.sort_by_key(|block| Reverse(block.tokens));

    // hook tax: payloads observed injected into transcripts
    for (name, stat) in &usage.hooks {
        let tokens = stat.tokens / stat.fires.max(1);
        if tokens > HOOK_TAX_MIN_TOKENS {
            findings.push(EstateFinding {
                rule: "hook-tax",
                unit: format!("hook {name}"),
                path: home.join(".claude/settings.json").display().to_string(),
                fix: format!(
                    "with the user, decide if the `{name}` payload earns ~{} tok per session; if not, slim the injected text or narrow the hook matcher in ~/.claude/settings.json",
                    tok_fmt(tokens)
                ),
                tokens,
                uses: stat.fires,
                detail: format!(
                    "injects ~{} tok per firing, {} firings observed",
                    tok_fmt(tokens),
                    stat.fires
                ),
                action: "review necessity",
            });
        }
    }

    // interaction: shell commands that keep getting denied or keep failing
    for (head, stat) in &usage.bash {
        if stat.denials >= CMD_DENY_MIN {
            findings.push(EstateFinding {
                rule: "blocked-command",
                unit: format!("bash `{head}`"),
                path: home.join(".claude/settings.json").display().to_string(),
                fix: format!(
                    "if `{head}` should be allowed, add \"Bash({head}:*)\" to permissions.allow in ~/.claude/settings.json (or use /permissions); otherwise tell the agent not to reach for it"
                ),
                tokens: 0,
                uses: stat.denials,
                detail: format!(
                    "permission-denied {}× across {} claude sessions; every denial stalls the agent mid-task",
                    stat.denials, usage.claude_sessions
                ),
                action: "allow or steer away",
            });
        }
        if stat.fails >= CMD_FAIL_MIN && stat.fails * 2 >= stat.runs {
            findings.push(EstateFinding {
                rule: "failing-command",
                unit: format!("bash `{head}`"),
                path: home.join(".claude/CLAUDE.md").display().to_string(),
                fix: format!(
                    "find out why `{head}` keeps failing (e.g. `{}`); fix the environment or record the working invocation in ~/.claude/CLAUDE.md",
                    stat.sample
                ),
                tokens: stat.fail_tokens,
                uses: stat.runs,
                detail: format!(
                    "failed {} of {} runs across claude sessions; each failure pays for the error output plus a retry",
                    stat.fails, stat.runs
                ),
                action: "unbreak",
            });
        }
    }

    // interaction: instructions the user retypes session after session
    for stat in usage.directives.values() {
        if stat.sessions >= DIRECTIVE_MIN_SESSIONS {
            findings.push(EstateFinding {
                rule: "repeated-directive",
                unit: format!("directive \"{}\"", crate::clip(&stat.sample, 48)),
                path: home.join(".claude/CLAUDE.md").display().to_string(),
                fix: format!(
                    "add it to ~/.claude/CLAUDE.md so it is loaded every session: `{}`",
                    stat.sample.replace('`', "'")
                ),
                tokens: crate::estimate_tokens(&stat.sample) * stat.sessions,
                uses: stat.sessions,
                detail: format!(
                    "typed in {} of {} claude sessions; standing instructions belong in CLAUDE.md, not in every conversation",
                    stat.sessions, usage.claude_sessions
                ),
                action: "promote",
            });
        }
    }

    // interaction: session size distribution per harness
    let mut session_stats = Vec::new();
    for (i, (label, sessions_root)) in [
        ("claude", home.join(".claude/projects")),
        ("codex", home.join(".codex/sessions")),
        ("pi", home.join(".pi/agent/sessions")),
        ("cursor", crate::cursor_db()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut toks = usage.session_toks[i].clone();
        if toks.is_empty() {
            continue;
        }
        toks.sort_unstable();
        let over = toks.iter().filter(|t| **t > LONG_SESSION_TOKENS).count();
        let stat = SessionStat {
            harness: label,
            sessions: toks.len(),
            median_tokens: percentile(&toks, 50),
            p90_tokens: percentile(&toks, 90),
            over_long: over,
        };
        if over >= 2 && over * 4 >= stat.sessions {
            findings.push(EstateFinding {
                rule: "long-sessions",
                unit: format!("{label} sessions"),
                path: sessions_root.display().to_string(),
                fix: "start a fresh session per task and hand context over explicitly (a plan file or summary) instead of carrying the whole history".into(),
                tokens: 0,
                uses: over,
                detail: format!(
                    "{over} of {} sessions exceed ~{} tok (median ~{}, p90 ~{}); past a point, extra history dilutes attention and raises cost",
                    stat.sessions,
                    tok_fmt(LONG_SESSION_TOKENS),
                    tok_fmt(stat.median_tokens),
                    tok_fmt(stat.p90_tokens)
                ),
                action: "split work",
            });
        }
        session_stats.push(stat);
    }

    findings.sort_by(|a, b| {
        rank(a.rule)
            .cmp(&rank(b.rule))
            .then(b.tokens.cmp(&a.tokens))
    });

    let mut used: Vec<String> = Vec::new();
    let mut push_usage = |kind: &str, map: &HashMap<String, usize>| {
        let mut v: Vec<_> = map.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (name, n) in v {
            used.push(format!("{kind} {name}: {n} uses"));
        }
    };
    push_usage("skill", &usage.skills);
    push_usage("skill-read(claude)", &usage.skill_reads_claude);
    push_usage("skill-read(codex)", &usage.skill_reads_codex);
    push_usage("skill-read(pi)", &usage.skill_reads_pi);
    push_usage("skill-read(cursor)", &usage.skill_reads_cursor);
    push_usage("command", &usage.commands);
    push_usage("mcp(claude)", &usage.mcp_claude);
    push_usage("mcp(codex)", &usage.mcp_codex);
    let hook_samples: Vec<(String, String)> = usage
        .hooks
        .iter()
        .filter(|(_, s)| !s.sample.is_empty())
        .map(|(n, s)| (n.clone(), s.sample.clone()))
        .collect();

    // repeated-or-notable user messages, most-repeated first, for the
    // semantic paraphrase pass and JSON consumers
    let mut directives: Vec<(&usize, &String)> = usage
        .directives
        .values()
        .map(|d| (&d.sessions, &d.sample))
        .collect();
    directives.sort_by(|a, b| b.0.cmp(a.0).then(a.1.cmp(b.1)));
    let directives: Vec<String> = directives
        .into_iter()
        .take(120)
        .map(|(n, s)| format!("{n}× {s}"))
        .collect();

    let tokens_flagged = findings.iter().map(|f| f.tokens).sum();
    let mut report = EstateReport {
        version: crate::REPORT_VERSION,
        summary: EstateSummary {
            sessions_claude: usage.claude_sessions,
            sessions_codex: usage.codex_sessions,
            sessions_pi: usage.pi_sessions,
            sessions_cursor: usage.cursor_sessions,
            units,
            findings: findings.len(),
            tokens_flagged,
        },
        findings,
        blocks,
        session_stats,
        usage: used,
        directives,
        semantic: None,
    };
    report.usage.extend(
        hook_samples
            .into_iter()
            .map(|(n, s)| format!("hook-sample {n}: {s}")),
    );
    report
}

#[allow(clippy::too_many_arguments)]
fn push_harness_skill(
    skill_md: &Path,
    harness: &str,
    sessions: usize,
    reads: &HashMap<String, usize>,
    seen: &mut HashSet<String>,
    units: &mut usize,
    findings: &mut Vec<EstateFinding>,
    now: SystemTime,
) {
    // no sessions of the harness = no evidence; say nothing about it
    if sessions == 0 {
        return;
    }
    let name = skill_md
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() || !seen.insert(format!("{harness}:{name}")) {
        return;
    }
    let Ok(md) = skill_md.metadata() else { return };
    *units += 1;
    if reads.get(&name).copied().unwrap_or(0) == 0 && age_days(now, md.modified().ok()) > GRACE_DAYS
    {
        let fix = match harness {
            "codex" => format!(
                "disable or uninstall the Codex plugin providing `{name}` (deleting from the plugin cache gets re-synced)"
            ),
            "cursor" => format!(
                "confirm with the user, then `rm -r {}`",
                skill_md.parent().unwrap_or(skill_md).display()
            ),
            _ => format!("remove the pi package providing `{name}` from ~/.pi/agent/npm"),
        };
        findings.push(EstateFinding {
            rule: "dead-skill",
            unit: format!("skill {harness}:{name}"),
            path: skill_md.display().to_string(),
            fix,
            tokens: crate::estimate_tokens(&std::fs::read_to_string(skill_md).unwrap_or_default()),
            uses: 0,
            detail: format!("never read across {sessions} {harness} sessions"),
            action: "remove",
        });
    }
}

fn find_skill_mds(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth == 0 {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                find_skill_mds(&p, out, depth - 1);
            } else if p.file_name().is_some_and(|f| f == "SKILL.md") {
                out.push(p);
            }
        }
    }
}

/// Cursor user skills: ~/.cursor/skills/<name>/SKILL.md. A skill marked
/// `disable-model-invocation: true` loads only when the user types `/name`,
/// so it costs nothing per session and is not audited.
fn cursor_skill_files(skills: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(skills) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path().join("SKILL.md"))
        .filter(|f| f.is_file())
        .filter(|f| !model_invocation_disabled(&std::fs::read_to_string(f).unwrap_or_default()))
        .collect()
}

fn model_invocation_disabled(skill_md: &str) -> bool {
    let Some((front, _)) = skill_md
        .strip_prefix("---")
        .and_then(|rest| rest.split_once("\n---"))
    else {
        return false;
    };
    front.lines().any(|l| {
        l.split_once(':')
            .is_some_and(|(k, v)| k.trim() == "disable-model-invocation" && v.trim() == "true")
    })
}

/// pi skills live at node_modules/<pkg>/skills/<name>/SKILL.md (pkg may be scoped).
fn pi_skill_files(npm: &Path) -> Vec<PathBuf> {
    let mut pkgs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(npm.join("node_modules")) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            if e.file_name().to_string_lossy().starts_with('@') {
                if let Ok(rd2) = std::fs::read_dir(&p) {
                    pkgs.extend(rd2.flatten().map(|x| x.path()));
                }
            } else {
                pkgs.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for pkg in pkgs {
        if let Ok(rd) = std::fs::read_dir(pkg.join("skills")) {
            for e in rd.flatten() {
                let f = e.path().join("SKILL.md");
                if f.is_file() {
                    out.push(f);
                }
            }
        }
    }
    out
}

fn rank(rule: &str) -> usize {
    GROUPS.iter().position(|(r, _)| *r == rule).unwrap_or(99)
}

/// (days since last commit, commit count) for files tracked in a git repo.
fn git_stats(path: &Path) -> Option<(u64, usize)> {
    let dir = path.parent()?;
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["log", "--format=%ct", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let commits: Vec<u64> = stdout
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    let last = *commits.first()?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((now.saturating_sub(last) / 86_400, commits.len()))
}

fn git_note(path: &Path) -> String {
    match git_stats(path) {
        Some((age, commits)) => format!(
            "; git: {commits} commit{}, last change {age}d ago",
            if commits == 1 { "" } else { "s" }
        ),
        None => String::new(),
    }
}

/// Split an instruction file into heading-delimited blocks, priced in real tokens.
fn price_blocks(file: &str, text: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut heading = "(preamble)".to_string();
    let mut buf = String::new();
    let flush = |heading: &str, buf: &mut String, out: &mut Vec<Block>| {
        if !buf.trim().is_empty() {
            out.push(Block {
                file: file.to_string(),
                heading: heading.to_string(),
                tokens: crate::estimate_tokens(buf),
            });
        }
        buf.clear();
    };
    for line in text.lines() {
        if line.starts_with('#') {
            flush(&heading, &mut buf, &mut out);
            heading = line.trim_start_matches('#').trim().to_string();
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    flush(&heading, &mut buf, &mut out);
    out
}

fn age_days(now: SystemTime, modified: Option<SystemTime>) -> u64 {
    modified
        .and_then(|m| now.duration_since(m).ok())
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

/// Markdown link targets like `[Title](file.md)` in a MEMORY.md index.
fn index_links(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in text.match_indices("](") {
        let rest = &text[i + 2..];
        if let Some(end) = rest.find(')') {
            let t = &rest[..end];
            if t.ends_with(".md") && !t.contains('/') && !t.contains(' ') {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Filesystem paths mentioned in a body that no longer exist on disk.
/// Restricted to real filesystem roots so API endpoints like /rest/e2e/reset
/// or /runs/{id} don't false-positive.
fn missing_paths(body: &str) -> Vec<String> {
    const FS_ROOTS: [&str; 7] = [
        "/Users/",
        "/tmp/",
        "/private/",
        "/var/",
        "/etc/",
        "/opt/",
        "/home/",
    ];
    let home = std::env::var("HOME").unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for tok in body.split_whitespace() {
        let t = tok
            .trim_matches(|c: char| "()[]`'\",;:*.".contains(c))
            .trim_end_matches('/');
        let expanded = if let Some(rest) = t.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else {
            t.to_string()
        };
        if FS_ROOTS.iter().any(|r| expanded.starts_with(r))
            && expanded.matches('/').count() >= 2
            && !expanded.contains(['$', '*', '{', '}', '<', '>'])
            && !expanded.contains("//")
            && !Path::new(&expanded).exists()
            && !out.contains(&t.to_string())
        {
            out.push(t.to_string());
        }
    }
    out
}

// ---------- semantic pass ----------

pub(crate) fn semantic_pass(report: &EstateReport) -> Result<Semantic> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let mut digest = String::new();
    for (label, path) in [
        (
            "CLAUDE.md (global instructions)",
            home.join(".claude/CLAUDE.md"),
        ),
        ("codex AGENTS.md", home.join(".codex/AGENTS.md")),
    ] {
        if let Ok(s) = std::fs::read_to_string(path) {
            digest.push_str(&format!("\n--- {label} ---\n{s}\n"));
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/skills")) {
        for e in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(e.path().join("SKILL.md")) {
                digest.push_str(&format!(
                    "\n--- skill {} ---\n{}\n",
                    e.file_name().to_string_lossy(),
                    crate::clip(&s, 1500)
                ));
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/projects")) {
        for e in rd.flatten() {
            if let Ok(files) = std::fs::read_dir(e.path().join("memory")) {
                for f in files.flatten() {
                    if f.path().extension().is_some_and(|x| x == "md")
                        && let Ok(s) = std::fs::read_to_string(f.path())
                    {
                        digest.push_str(&format!(
                            "\n--- memory {}/{} ---\n{}\n",
                            crate::decode_slug(&e.file_name().to_string_lossy()),
                            f.file_name().to_string_lossy(),
                            crate::clip(&s, 800)
                        ));
                    }
                }
            }
        }
    }
    if !report.directives.is_empty() {
        digest.push_str("\n--- short user messages across sessions (count× text) ---\n");
        digest.push_str(&report.directives.join("\n"));
        digest.push('\n');
    }
    let digest = crate::cap_middle(digest, 50_000);
    let prompt = format!(
        "You are auditing an AI coding agent's static context (global instructions, skills, memory files, hook payloads) for waste.\n\
         Find CONTRADICTIONS (directives that conflict with each other, with themselves, or with the observed usage stats) \
         and DUPLICATION (the same guidance stated in multiple places; also instructions the user keeps typing in sessions, \
         verbatim or paraphrased, that belong in CLAUDE.md — propose the exact line to add). Cite source names. Be specific.\n\n\
         CONTRADICTIONS:\n- <list>\n\nDUPLICATION:\n- <list>\n\n\
         Observed usage ({}):\n{}\n\nContext sources:\n{}",
        harness_counts(&report.summary),
        report.usage.join("\n"),
        digest
    );
    crate::llm_sections(&prompt)
}

// ---------- output ----------

pub(crate) fn tok_or_unknown(tokens: usize) -> String {
    if tokens == 0 {
        "?".into()
    } else {
        format!("~{}", tok_fmt(tokens))
    }
}

/// "42 claude · 7 pi sessions" — harnesses with no sessions are not mentioned.
fn harness_counts(s: &EstateSummary) -> String {
    let parts: Vec<String> = [
        (s.sessions_claude, "claude"),
        (s.sessions_codex, "codex"),
        (s.sessions_pi, "pi"),
        (s.sessions_cursor, "cursor"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, label)| format!("{n} {label}"))
    .collect();
    if parts.is_empty() {
        "no local sessions".into()
    } else {
        format!("{} sessions", parts.join(" · "))
    }
}

pub(crate) fn human(r: &EstateReport) {
    let s = &r.summary;
    println!(
        "cxwatch audit · static config vs usage in {}",
        harness_counts(s)
    );
    println!(
        "  units {} · findings {} · ≈{} tok flagged (per-unit costs; always-loaded units cost this every session)",
        s.units,
        s.findings,
        tok_fmt(s.tokens_flagged)
    );
    for st in &r.session_stats {
        println!(
            "  {} sessions: median ≈{} tok · p90 ≈{} tok · {} over ≈{} tok",
            st.harness,
            tok_fmt(st.median_tokens),
            tok_fmt(st.p90_tokens),
            st.over_long,
            tok_fmt(LONG_SESSION_TOKENS)
        );
    }
    if r.findings.is_empty() {
        println!("  ✔ config is clean");
    }
    for f in &r.findings {
        println!(
            "  {:<20} {:>7} {:>5}  {}: {} → {}",
            f.rule,
            tok_or_unknown(f.tokens),
            format!("{}×", f.uses),
            f.unit,
            f.detail,
            f.action
        );
        println!("      fix: {}", f.fix);
    }
    if let Some(sem) = &r.semantic {
        println!("  semantic ({}):", sem.model_used);
        println!(
            "    contradictions:\n      {}",
            sem.contradiction.replace('\n', "\n      ")
        );
        println!(
            "    duplication:\n      {}",
            sem.bloating.replace('\n', "\n      ")
        );
    }
    if !r.findings.is_empty() {
        println!(
            "  → rerun with -o plan.md for an agent-ready fix plan, or --fix to apply mechanical fixes"
        );
    }
}

pub(crate) const GROUPS: [(&str, &str); 14] = [
    ("dead-mcp", "Disable unused MCP servers"),
    ("dead-skill", "Delete or demote dead skills"),
    (
        "repeated-directive",
        "Promote repeated instructions into CLAUDE.md",
    ),
    (
        "blocked-command",
        "Allow or steer away from repeatedly denied commands",
    ),
    ("failing-command", "Unbreak repeatedly failing commands"),
    ("duplicate-directive", "Merge duplicated directives"),
    ("heavy-block", "Tighten heavy instruction blocks"),
    ("hook-tax", "Slim hook payloads"),
    ("dead-command", "Delete unused commands"),
    ("long-sessions", "Split long sessions"),
    ("orphan-memory", "Repair memory indexes: orphaned files"),
    ("dangling-index", "Repair memory indexes: dangling entries"),
    ("stale-ref", "Fix stale references"),
    ("stale-memory", "Review stale memories"),
];

pub(crate) fn markdown(r: &EstateReport) -> String {
    let s = &r.summary;
    let mut md = format!(
        "# cxwatch audit fix report\n\n\
         - Sessions scanned: {}\n- Units audited: {}\n- Fixes: {}\n- Tokens flagged: ~{}\n\n\
         ## For the executing agent\n\n\
         You are cleaning up an AI coding agent's static context. Work through the checklists below top to\n\
         bottom; each item states its own concrete fix. Tick items off as you go. Anything involving a\n\
         deletion or config edit: show the user exactly what you are about to change and get confirmation\n\
         first. Do not touch anything not listed here. When finished, summarize what was applied and what\n\
         was skipped.\n\n\
         ## Fixes\n\n",
        harness_counts(s),
        s.units,
        s.findings,
        tok_fmt(s.tokens_flagged)
    );
    for (rule, heading) in GROUPS {
        let group: Vec<_> = r.findings.iter().filter(|f| f.rule == rule).collect();
        if group.is_empty() {
            continue;
        }
        let saved: usize = group.iter().map(|f| f.tokens).sum();
        let saved_note = if saved > 0 {
            format!(", ~{} tok", tok_fmt(saved))
        } else {
            String::new()
        };
        md.push_str(&format!("### {heading} ({}{saved_note})\n\n", group.len()));
        for f in group {
            let tok_note = if f.tokens > 0 {
                format!(" [~{} tok]", tok_fmt(f.tokens))
            } else {
                String::new()
            };
            md.push_str(&format!(
                "- [ ] **{}**{tok_note}: {}\n      - why: {}\n      - file: `{}`\n",
                f.unit, f.fix, f.detail, f.path
            ));
        }
        md.push('\n');
    }
    if !r.session_stats.is_empty() {
        md.push_str(&format!(
            "## Session size (rough estimates)\n\n| harness | sessions | median | p90 | over ~{} |\n|---|---|---|---|---|\n",
            tok_fmt(LONG_SESSION_TOKENS)
        ));
        for st in &r.session_stats {
            md.push_str(&format!(
                "| {} | {} | ~{} | ~{} | {} |\n",
                st.harness,
                st.sessions,
                tok_fmt(st.median_tokens),
                tok_fmt(st.p90_tokens),
                st.over_long
            ));
        }
        md.push('\n');
    }
    if !r.blocks.is_empty() {
        md.push_str("## Always-loaded instruction blocks (priced per heading)\n\n| file | block | tokens |\n|---|---|---|\n");
        for b in &r.blocks {
            md.push_str(&format!(
                "| {} | {} | ~{} |\n",
                b.file,
                b.heading,
                tok_fmt(b.tokens)
            ));
        }
        md.push('\n');
    }
    if let Some(sem) = &r.semantic {
        md.push_str(&format!(
            "## Semantic findings ({})\n\nLLM-reported; discuss with the user before acting and propose a fix per item.\n\n\
             ### Contradictions\n{}\n\n### Duplication\n{}\n",
            sem.model_used, sem.contradiction, sem.bloating
        ));
    }
    md
}

// ---------- autofix ----------

#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(tag = "kind")]
pub(crate) enum FixOp {
    AppendLine { file: String, line: String },
    DeleteMatchingLine { file: String, contains: String },
    Trash { path: String },
    Command { argv: Vec<String> },
    DeleteTomlTable { file: String, table: String },
    Manual,
}

impl FixOp {
    pub(crate) fn describe(&self) -> String {
        match self {
            FixOp::AppendLine { file, line } => format!("append `{line}` to {file}"),
            FixOp::DeleteMatchingLine { file, contains } => {
                format!("delete the line containing `{contains}` from {file}")
            }
            FixOp::Trash { path } => format!("move {path} to the cxwatch trash"),
            FixOp::Command { argv } => format!("run `{}`", argv.join(" ")),
            FixOp::DeleteTomlTable { file, table } => {
                format!("delete the [{table}] block from {file}")
            }
            FixOp::Manual => "manual edit needed".into(),
        }
    }
}

fn backticked(s: &str) -> Option<String> {
    let a = s.find('`')?;
    let b = s.rfind('`')?;
    (b > a).then(|| s[a + 1..b].to_string())
}

/// Derive the mechanical fix for a finding. Manual means: hand it to a human/agent.
pub(crate) fn fix_op(f: &EstateFinding) -> FixOp {
    match f.rule {
        // claude and cursor skills live in their own user-owned dir; codex/pi skills are plugin/package-managed
        "dead-skill"
            if ["/.claude/skills/", "/.cursor/skills/"]
                .iter()
                .any(|dir| f.path.contains(dir)) =>
        {
            FixOp::Trash {
                path: Path::new(&f.path)
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| f.path.clone()),
            }
        }
        "dead-command" => FixOp::Trash {
            path: f.path.clone(),
        },
        "dead-mcp" => {
            let name = f.unit.rsplit(':').next().unwrap_or("").to_string();
            if f.unit.contains("claude:") {
                FixOp::Command {
                    argv: vec!["claude".into(), "mcp".into(), "remove".into(), name],
                }
            } else {
                FixOp::DeleteTomlTable {
                    file: f.path.clone(),
                    table: format!("mcp_servers.{name}"),
                }
            }
        }
        "repeated-directive" => match backticked(&f.fix) {
            Some(line) => FixOp::AppendLine {
                file: f.path.clone(),
                line,
            },
            None => FixOp::Manual,
        },
        "orphan-memory" => match backticked(&f.fix) {
            Some(line) => FixOp::AppendLine {
                file: Path::new(&f.path)
                    .parent()
                    .map(|p| p.join("MEMORY.md").display().to_string())
                    .unwrap_or_else(|| f.path.clone()),
                line,
            },
            None => FixOp::Manual,
        },
        "dangling-index" => match backticked(&f.fix) {
            Some(contains) => FixOp::DeleteMatchingLine {
                file: f.path.clone(),
                contains,
            },
            None => FixOp::Manual,
        },
        _ => FixOp::Manual,
    }
}

fn trash_dest(path: &str) -> Result<PathBuf> {
    let dir = crate::cache_dir().join("trash");
    std::fs::create_dir_all(&dir)?;
    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("item");
    Ok(dir.join(format!("{epoch}-{name}")))
}

fn backup(file: &str) -> Result<()> {
    if Path::new(file).is_file() {
        std::fs::copy(file, trash_dest(file)?)?;
    }
    Ok(())
}

/// Apply a mechanical fix. Every destructive step is backed up under ~/.cache/cxwatch/trash.
pub(crate) fn apply_fix(op: &FixOp) -> Result<String> {
    match op {
        FixOp::Manual => anyhow::bail!("no mechanical fix; use the exported plan"),
        FixOp::AppendLine { file, line } => {
            backup(file)?;
            let mut s = std::fs::read_to_string(file).unwrap_or_default();
            if s.contains(line.as_str()) {
                return Ok(format!("already present in {file}"));
            }
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(line);
            s.push('\n');
            std::fs::write(file, s)?;
            Ok(format!("appended to {file}"))
        }
        FixOp::DeleteMatchingLine { file, contains } => {
            backup(file)?;
            let s = std::fs::read_to_string(file)?;
            let kept: Vec<&str> = s
                .lines()
                .filter(|l| !l.contains(contains.as_str()))
                .collect();
            let removed = s.lines().count() - kept.len();
            if removed == 0 {
                anyhow::bail!("no line containing `{contains}` in {file}");
            }
            std::fs::write(file, kept.join("\n") + "\n")?;
            Ok(format!("removed {removed} line(s) from {file}"))
        }
        FixOp::Trash { path } => {
            let dest = trash_dest(path)?;
            std::fs::rename(path, &dest)?;
            Ok(format!("moved to {}", dest.display()))
        }
        FixOp::Command { argv } => {
            let out = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()?;
            if out.status.success() {
                Ok(format!("ran `{}`", argv.join(" ")))
            } else {
                anyhow::bail!(
                    "`{}` failed: {}",
                    argv.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                )
            }
        }
        FixOp::DeleteTomlTable { file, table } => {
            backup(file)?;
            let s = std::fs::read_to_string(file)?;
            let mut kept = Vec::new();
            let mut skip = false;
            let mut removed = 0usize;
            for line in s.lines() {
                let t = line.trim();
                if t.starts_with('[') {
                    let name = t.trim_matches(['[', ']']).trim_matches('"');
                    skip = name == table || name.starts_with(&format!("{table}."));
                }
                if skip {
                    removed += 1;
                } else {
                    kept.push(line);
                }
            }
            if removed == 0 {
                anyhow::bail!("no [{table}] block in {file}");
            }
            std::fs::write(file, kept.join("\n") + "\n")?;
            Ok(format!("removed {removed} line(s) ([{table}]) from {file}"))
        }
    }
}

fn fix_flow(r: &EstateReport, yes: bool) -> Result<()> {
    use std::io::{BufRead, Write};
    let mechanical: Vec<&EstateFinding> = r
        .findings
        .iter()
        .filter(|f| fix_op(f) != FixOp::Manual)
        .collect();
    if mechanical.is_empty() {
        println!("no mechanical fixes available; export the plan for the rest (-o plan.md)");
        return Ok(());
    }
    println!(
        "{} mechanical fixes · backups go to {}",
        mechanical.len(),
        crate::cache_dir().join("trash").display()
    );
    let (mut applied, mut skipped, mut all) = (0usize, 0usize, yes);
    let stdin = std::io::stdin();
    'outer: for f in mechanical {
        let op = fix_op(f);
        println!("\n  {:<18} {}: {}", f.rule, f.unit, f.detail);
        println!("  fix: {}", op.describe());
        let go = all || {
            print!("  apply? [y]es [N]o [a]ll [q]uit ");
            std::io::stdout().flush()?;
            let mut ans = String::new();
            stdin.lock().read_line(&mut ans)?;
            match ans.trim() {
                "y" | "Y" => true,
                "a" | "A" => {
                    all = true;
                    true
                }
                "q" | "Q" => break 'outer,
                _ => false,
            }
        };
        if go {
            match apply_fix(&op) {
                Ok(msg) => {
                    applied += 1;
                    println!("  ✔ {msg}");
                }
                Err(e) => println!("  ✗ {e}"),
            }
        } else {
            skipped += 1;
        }
    }
    println!("\napplied {applied} · skipped {skipped} · everything else needs the exported plan");
    Ok(())
}

pub(crate) fn estate_cmd(
    json: bool,
    want_semantic: bool,
    output: Option<String>,
    fix: bool,
    yes: bool,
) -> Result<()> {
    let mut r = audit();
    if fix {
        return fix_flow(&r, yes);
    }
    if want_semantic {
        r.semantic = Some(semantic_pass(&r).unwrap_or_else(|e| Semantic {
            contradiction: format!("semantic unavailable: {e}"),
            bloating: String::new(),
            model_used: crate::semantic_model(),
        }));
    }
    if let Some(out) = output {
        std::fs::write(&out, markdown(&r))?;
        println!("wrote {out}");
    } else if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        human(&r);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_skill_command_and_mcp_usage() {
        let line = r#"{"x":[{"name":"Skill","input":{"skill":"graphify"}},{"name":"mcp__chrome-devtools__click"}]} <command-name>/effort await tools.mcp__chrome_devtools__click({})"#;
        let mut skills = HashMap::new();
        let mut mcp = HashMap::new();
        let mut cmds = HashMap::new();
        count_captures(
            line,
            "\"name\":\"Skill\",\"input\":{\"skill\":\"",
            |c| c == '"',
            &mut skills,
        );
        count_captures(
            line,
            "<command-name>/",
            |c| !(c.is_ascii_alphanumeric() || "-_:".contains(c)),
            &mut cmds,
        );
        count_mcp(line, &mut mcp);
        assert_eq!(skills.get("graphify"), Some(&1));
        assert_eq!(mcp.get("chrome-devtools"), Some(&1));
        assert_eq!(mcp.get("chrome_devtools"), Some(&1));
        assert_eq!(cmds.get("effort"), Some(&1));
    }

    #[test]
    fn canon_matches_across_separators() {
        let mut mcp = HashMap::new();
        mcp.insert("chrome_devtools".to_string(), 84usize);
        assert_eq!(uses_of(&mcp, "chrome-devtools"), 84);
        assert_eq!(uses_of(&mcp, "figma"), 0);
    }

    #[test]
    fn skill_reads_from_paths() {
        let line = r#"sed -n '1,220p' /Users/x/.codex/plugins/cache/openai-curated/github/63976030/skills/gh-address-comments/SKILL.md"#;
        let mut reads = HashMap::new();
        count_skill_reads(line, &mut reads);
        assert_eq!(reads.get("gh-address-comments"), Some(&1));
        // pi/claude read tool style counts too
        let mut reads2 = HashMap::new();
        count_skill_reads(
            r#"{"arguments":{"path":"/Users/x/.claude/skills/graphify/SKILL.md"}}"#,
            &mut reads2,
        );
        assert_eq!(reads2.get("graphify"), Some(&1));
    }

    #[test]
    fn prose_skill_mention_is_not_usage() {
        let line =
            "- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph";
        let mut reads = HashMap::new();
        count_skill_reads(line, &mut reads);
        assert!(reads.is_empty());
    }

    #[test]
    fn escaped_string_length() {
        assert_eq!(escaped_len(r#"abc\"def\\gh" trailing"#), 12);
        assert_eq!(escaped_len(r#"plain" x"#), 5);
    }

    #[test]
    fn hook_payload_measured_with_sample() {
        let line = r#"{"type":"attachment","attachment":{"type":"hook_success","hookName":"SessionStart:startup","hookEvent":"SessionStart","content":"---\nname: mullet\n---"}}"#;
        let mut hooks = HashMap::new();
        count_hooks(line, &mut hooks);
        let stat = &hooks["SessionStart:startup"];
        assert_eq!(stat.fires, 1);
        assert!(stat.tokens > 0);
        assert!(stat.sample.contains("mullet"));
    }

    #[test]
    fn unicode_hook_payload_does_not_panic() {
        let payload = "é".repeat(2_000);
        let encoded = serde_json::to_string(&payload).unwrap();
        let line = format!(
            "{{\"type\":\"hook_success\",\"hookName\":\"SessionStart:unicode\",\"content\":{encoded}}}"
        );
        let mut hooks = HashMap::new();
        count_hooks(&line, &mut hooks);
        assert_eq!(hooks["SessionStart:unicode"].fires, 1);
        assert!(!hooks["SessionStart:unicode"].sample.is_empty());
    }

    #[test]
    fn skill_reads_stay_in_their_harness() {
        let line = r#"await tools.exec_command({cmd:"sed -n '1,220p' /x/skills/shared/SKILL.md"})"#;
        let mut usage = Usage::default();
        count_transcript(line, Harness::Codex, &mut usage);
        assert_eq!(usage.skill_reads_codex.get("shared"), Some(&1));
        assert!(usage.skill_reads_pi.is_empty());
        assert!(usage.skill_reads_claude.is_empty());
    }

    #[test]
    fn index_link_extraction() {
        let idx = "# Notes\n- [A](a.md) — hook\n- [B](b.md)\n- [ext](https://x.com/y.md)\n";
        assert_eq!(
            index_links(idx),
            vec!["a.md".to_string(), "b.md".to_string()]
        );
    }

    fn finding(rule: &'static str, unit: &str, path: &str, fix: &str) -> EstateFinding {
        EstateFinding {
            rule,
            unit: unit.into(),
            path: path.into(),
            fix: fix.into(),
            tokens: 0,
            uses: 0,
            detail: String::new(),
            action: "x",
        }
    }

    #[test]
    fn fix_ops_derived_from_findings() {
        let f = finding("dead-mcp", "mcp claude:figma", "/h/.claude.json", "");
        assert_eq!(
            fix_op(&f),
            FixOp::Command {
                argv: vec![
                    "claude".into(),
                    "mcp".into(),
                    "remove".into(),
                    "figma".into()
                ]
            }
        );
        let f = finding("dead-mcp", "mcp codex:figma", "/h/.codex/config.toml", "");
        assert_eq!(
            fix_op(&f),
            FixOp::DeleteTomlTable {
                file: "/h/.codex/config.toml".into(),
                table: "mcp_servers.figma".into()
            }
        );
        let f = finding(
            "dead-skill",
            "skill graphify",
            "/h/.claude/skills/graphify/SKILL.md",
            "",
        );
        assert_eq!(
            fix_op(&f),
            FixOp::Trash {
                path: "/h/.claude/skills/graphify".into()
            }
        );
        let f = finding("dead-skill", "skill codex:linear", "/x/SKILL.md", "");
        assert_eq!(fix_op(&f), FixOp::Manual);
        let f = finding(
            "dead-skill",
            "skill cursor:vue",
            "/h/.cursor/skills/vue/SKILL.md",
            "",
        );
        assert_eq!(
            fix_op(&f),
            FixOp::Trash {
                path: "/h/.cursor/skills/vue".into()
            }
        );
        let f = finding(
            "orphan-memory",
            "memory p/a.md",
            "/m/memory/a.md",
            "append to /m/memory/MEMORY.md: `- [a](a.md) — d`",
        );
        assert_eq!(
            fix_op(&f),
            FixOp::AppendLine {
                file: "/m/memory/MEMORY.md".into(),
                line: "- [a](a.md) — d".into()
            }
        );
        let f = finding("stale-ref", "memory p/b.md", "/m/b.md", "edit it");
        assert_eq!(fix_op(&f), FixOp::Manual);
    }

    #[test]
    fn apply_append_delete_and_toml() {
        let dir = std::env::temp_dir().join(format!("cxwatch-fix-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let idx = dir.join("MEMORY.md");
        std::fs::write(&idx, "# Notes\n- [a](a.md) — x\n").unwrap();
        let file = idx.display().to_string();
        apply_fix(&FixOp::AppendLine {
            file: file.clone(),
            line: "- [b](b.md) — y".into(),
        })
        .unwrap();
        assert!(std::fs::read_to_string(&idx).unwrap().contains("(b.md)"));
        // idempotent
        let msg = apply_fix(&FixOp::AppendLine {
            file: file.clone(),
            line: "- [b](b.md) — y".into(),
        })
        .unwrap();
        assert!(msg.contains("already present"));
        apply_fix(&FixOp::DeleteMatchingLine {
            file: file.clone(),
            contains: "(a.md)".into(),
        })
        .unwrap();
        assert!(!std::fs::read_to_string(&idx).unwrap().contains("(a.md)"));

        let toml = dir.join("config.toml");
        std::fs::write(&toml, "[a]\nx = 1\n[mcp_servers.figma]\nurl = \"y\"\n[mcp_servers.figma.env]\nk = \"v\"\n[b]\nz = 2\n").unwrap();
        apply_fix(&FixOp::DeleteTomlTable {
            file: toml.display().to_string(),
            table: "mcp_servers.figma".into(),
        })
        .unwrap();
        let s = std::fs::read_to_string(&toml).unwrap();
        assert!(!s.contains("figma") && s.contains("[a]") && s.contains("[b]"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blocks_priced_per_heading() {
        let text = "intro line\n\n# Setup\nrun the thing\n\n## Rules\nalways test\nnever push\n";
        let blocks = price_blocks("X.md", text);
        let headings: Vec<&str> = blocks.iter().map(|b| b.heading.as_str()).collect();
        assert_eq!(headings, vec!["(preamble)", "Setup", "Rules"]);
        assert!(blocks.iter().all(|b| b.tokens > 0));
    }

    #[test]
    fn git_stats_on_tracked_file() {
        // this repo's own Cargo.toml is committed, so stats must resolve
        let (age, commits) = git_stats(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("Cargo.toml")
                .as_path(),
        )
        .expect("tracked file");
        assert!(commits >= 1);
        assert!(age < 36_500);
        assert!(git_stats(Path::new("/tmp/definitely-not-in-git.xyz")).is_none());
    }

    #[test]
    fn command_head_normalization() {
        assert_eq!(command_head("git push origin main"), "git push");
        assert_eq!(command_head("git -C /x log"), "git");
        assert_eq!(command_head("cd /repo && cargo test --all"), "cargo test");
        assert_eq!(command_head("rg foo src/"), "rg");
        assert_eq!(command_head(""), "?");
    }

    fn bash_call(id: &str, cmd: &str) -> String {
        format!(
            r#"{{"type":"assistant","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"{id}","name":"Bash","input":{{"command":"{cmd}"}}}}]}}}}"#
        )
    }

    fn bash_result(id: &str, text: &str, is_error: bool) -> String {
        format!(
            r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"{id}","content":"{text}","is_error":{is_error}}}]}}}}"#
        )
    }

    #[test]
    fn bash_outcomes_split_denials_from_failures() {
        let hay = [
            bash_call("t1", "git push origin main"),
            bash_result(
                "t1",
                "The user doesn't want to proceed with this tool use.",
                true,
            ),
            bash_call("t2", "git push --tags"),
            bash_result("t2", "fatal: remote error", true),
            bash_call("t3", "git push"),
            bash_result("t3", "Everything up-to-date", false),
        ]
        .join("\n");
        let mut map = HashMap::new();
        count_bash_outcomes(&hay, &mut map);
        let stat = &map["git push"];
        assert_eq!(stat.runs, 3);
        assert_eq!(stat.denials, 1);
        assert_eq!(stat.fails, 1);
        assert!(stat.fail_tokens > 0);
        assert!(stat.sample.contains("--tags"));
    }

    fn user_msg(text: &str, sidechain: bool) -> String {
        format!(
            r#"{{"type":"user","isSidechain":{sidechain},"message":{{"role":"user","content":"{text}"}}}}"#
        )
    }

    #[test]
    fn directives_counted_once_per_session_with_exclusions() {
        let session = [
            user_msg("use simple language", false),
            user_msg("Use simple language!", false), // same session, same norm: not double counted
            user_msg("yes go ahead", false),         // acknowledgement
            user_msg("do the thing", true),          // sidechain
            user_msg("<command-name>/mcp</command-name>", false), // slash command wrapper
            user_msg("fix it", false),               // too short
        ]
        .join("\n");
        let mut map = HashMap::new();
        count_directives(&session, &mut map);
        count_directives(&session, &mut map); // second session
        assert_eq!(map.len(), 1);
        let stat = &map["use simple language"];
        assert_eq!(stat.sessions, 2);
        assert_eq!(stat.sample, "use simple language");
    }

    #[test]
    fn token_estimate_counts_content_fields() {
        // 16 content chars across two fields -> 16/8 = 2
        assert_eq!(
            token_estimate(r#"{"text":"aaaaaaaa","content":"bbbbbbbb","other":"ignored"}"#),
            2
        );
        assert_eq!(token_estimate("no json here"), 0);
    }

    #[test]
    fn percentile_bounds() {
        assert_eq!(percentile(&[], 50), 0);
        assert_eq!(percentile(&[7], 90), 7);
        assert_eq!(percentile(&[1, 2, 3, 4, 100], 50), 3);
        assert_eq!(percentile(&[1, 2, 3, 4, 100], 100), 100);
    }

    #[test]
    fn harness_with_no_sessions_is_never_mentioned() {
        let mut s = EstateSummary {
            sessions_claude: 42,
            sessions_codex: 0,
            sessions_pi: 0,
            sessions_cursor: 0,
            units: 0,
            findings: 0,
            tokens_flagged: 0,
        };
        assert_eq!(harness_counts(&s), "42 claude sessions");
        s.sessions_pi = 7;
        assert_eq!(harness_counts(&s), "42 claude · 7 pi sessions");
        s.sessions_cursor = 3;
        assert_eq!(harness_counts(&s), "42 claude · 7 pi · 3 cursor sessions");
        s.sessions_claude = 0;
        s.sessions_pi = 0;
        s.sessions_cursor = 0;
        assert_eq!(harness_counts(&s), "no local sessions");
    }

    #[test]
    fn cursor_bubbles_count_skill_reads_and_size() {
        let read = serde_json::json!({"type":2,"text":"","toolFormerData":{"name":"read_file","toolCallId":"c1",
            "rawArgs":"{\"target_file\": \"/Users/x/.cursor/skills/vue-conventions/SKILL.md\"}",
            "result":"{\"contents\":\"abcdefgh\"}"}});
        let prose_text = "see ~/.cursor/skills/other/SKILL.md for details";
        let prose = serde_json::json!({"type":2,"text":prose_text});
        let mut usage = Usage::default();
        count_cursor_session(&[read, prose], &mut usage);
        assert_eq!(usage.cursor_sessions, 1);
        assert_eq!(usage.skill_reads_cursor.get("vue-conventions"), Some(&1));
        assert!(!usage.skill_reads_cursor.contains_key("other")); // a mention is not a read
        assert_eq!(
            usage.session_toks[Harness::Cursor.idx()],
            vec![(8 + prose_text.len()) / 4]
        );
    }

    #[test]
    fn skill_name_from_read_path() {
        assert_eq!(
            skill_from_path("/Users/x/.cursor/skills/foo-bar/SKILL.md"),
            Some("foo-bar".into())
        );
        assert_eq!(
            skill_from_path("/Users/x/.cursor/skills/foo/notes/SKILL.md"),
            None
        );
        assert_eq!(skill_from_path("/Users/x/foo/SKILL.md"), None);
        assert_eq!(
            skill_from_path("/Users/x/.cursor/skills/foo/README.md"),
            None
        );
    }

    #[test]
    fn slash_only_cursor_skills_are_skipped() {
        assert!(model_invocation_disabled(
            "---\nname: review\ndisable-model-invocation: true\n---\n# Review\n"
        ));
        assert!(!model_invocation_disabled(
            "---\nname: review\ndescription: x\n---\nbody"
        ));
        assert!(!model_invocation_disabled(
            "no frontmatter, disable-model-invocation: true in prose"
        ));
    }

    #[test]
    fn harness_skill_needs_session_evidence() {
        let dir = std::env::temp_dir().join(format!("cxwatch-skill-test-{}", std::process::id()));
        let skill = dir.join("skills/foo");
        std::fs::create_dir_all(&skill).unwrap();
        let md = skill.join("SKILL.md");
        std::fs::write(&md, "guidance").unwrap();
        // a future "now" makes the fresh file look past the grace period
        let now = SystemTime::now() + std::time::Duration::from_secs(100 * 86_400);
        let reads = HashMap::new();
        let mut findings = Vec::new();
        let mut units = 0;
        let mut seen = HashSet::new();
        push_harness_skill(
            &md,
            "codex",
            0,
            &reads,
            &mut seen,
            &mut units,
            &mut findings,
            now,
        );
        assert!(findings.is_empty(), "no sessions means no finding");
        assert_eq!(units, 0);
        push_harness_skill(
            &md,
            "codex",
            5,
            &reads,
            &mut seen,
            &mut units,
            &mut findings,
            now,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "dead-skill");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repeated_directive_fix_is_mechanical() {
        let f = finding(
            "repeated-directive",
            "directive \"use simple language\"",
            "/h/.claude/CLAUDE.md",
            "add it to ~/.claude/CLAUDE.md so it is loaded every session: `use simple language`",
        );
        assert_eq!(
            fix_op(&f),
            FixOp::AppendLine {
                file: "/h/.claude/CLAUDE.md".into(),
                line: "use simple language".into()
            }
        );
    }

    #[test]
    fn missing_path_detection() {
        let body =
            "See /tmp/definitely-not-real/xyz.rs and /rest/e2e/reset and /runs/{id} and /tmp";
        let missing = missing_paths(body);
        assert_eq!(missing, vec!["/tmp/definitely-not-real/xyz.rs".to_string()]);
    }
}
