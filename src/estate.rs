use crate::{tok_fmt, Semantic};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const GRACE_DAYS: u64 = 14;
const STALE_DAYS: u64 = 120;
const HOOK_TAX_MIN_TOKENS: usize = 500;
const HEAVY_BLOCK_TOKENS: usize = 400;

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
pub(crate) struct EstateReport {
    pub version: u8,
    pub findings: Vec<EstateFinding>,
    /// Always-loaded instruction files priced per heading block.
    pub blocks: Vec<Block>,
    /// Positive usage counts, for JSON consumers and the semantic digest.
    pub usage: Vec<String>,
    pub semantic: Option<Semantic>,
    pub summary: EstateSummary,
}

// ---------- usage join: what the transcripts actually show ----------

#[derive(Default)]
struct HookStat {
    fires: usize,
    bytes: usize,
    sample: String,
}

#[derive(Default)]
struct Usage {
    claude_sessions: usize,
    codex_sessions: usize,
    pi_sessions: usize,
    skills: HashMap<String, usize>,      // Skill tool invocations (claude)
    commands: HashMap<String, usize>,    // slash commands (claude)
    mcp_claude: HashMap<String, usize>,  // mcp__server__ calls per harness
    mcp_codex: HashMap<String, usize>,
    hooks: HashMap<String, HookStat>,
    skill_reads: HashMap<String, usize>, // skills/<name>/SKILL.md reads, all harnesses
}

fn scan_usage(home: &Path) -> Usage {
    enum H {
        Claude,
        Codex,
        Pi,
    }
    let mut u = Usage::default();
    let roots = [
        (home.join(".claude/projects"), H::Claude),
        (home.join(".codex/sessions"), H::Codex),
        (home.join(".codex/archived_sessions"), H::Codex),
        (home.join(".pi/agent/sessions"), H::Pi),
    ];
    for (root, harness) in roots {
        let mut files = Vec::new();
        crate::walk_jsonl(&root, &mut files);
        for f in files {
            let Ok(s) = std::fs::read_to_string(&f) else { continue };
            count_skill_reads(&s, &mut u.skill_reads);
            match harness {
                H::Claude => {
                    u.claude_sessions += 1;
                    count_captures(&s, "\"name\":\"Skill\",\"input\":{\"skill\":\"", |c| c == '"', &mut u.skills);
                    count_captures(&s, "<command-name>/", |c| !(c.is_ascii_alphanumeric() || "-_:".contains(c)), &mut u.commands);
                    count_mcp(&s, &mut u.mcp_claude);
                    count_hooks(&s, &mut u.hooks);
                }
                H::Codex => {
                    u.codex_sessions += 1;
                    count_mcp(&s, &mut u.mcp_codex);
                }
                H::Pi => u.pi_sessions += 1,
            }
        }
    }
    u
}

fn count_captures(hay: &str, pat: &str, stop: impl Fn(char) -> bool, map: &mut HashMap<String, usize>) {
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        let end = rest.find(&stop).unwrap_or(rest.len());
        if end > 0 && end < 64 {
            *map.entry(rest[..end].to_string()).or_default() += 1;
        }
    }
}

fn count_mcp(hay: &str, map: &mut HashMap<String, usize>) {
    let pat = "\"name\":\"mcp__";
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        if let Some(end) = rest.find("__") {
            if end > 0 && end < 64 {
                *map.entry(rest[..end].to_string()).or_default() += 1;
            }
        }
    }
}

fn count_hooks(hay: &str, map: &mut HashMap<String, HookStat>) {
    let pat = "\"type\":\"hook_success\",\"hookName\":\"";
    for (i, _) in hay.match_indices(pat) {
        let rest = &hay[i + pat.len()..];
        let Some(nend) = rest.find('"') else { continue };
        let name = rest[..nend].to_string();
        let window = &rest[nend..rest.len().min(nend + 300)];
        let bytes = window
            .find("\"content\":\"")
            .map(|ci| {
                let body_start = nend + ci + 11;
                let len = escaped_len(&rest[body_start..]);
                let e = map.entry(name.clone()).or_default();
                if e.sample.is_empty() {
                    e.sample = rest[body_start..body_start + len.min(2000)].to_string();
                }
                len
            })
            .unwrap_or(0);
        let e = map.entry(name).or_default();
        e.fires += 1;
        e.bytes += bytes;
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
        let is_read = ["path\\\":", "path\":\"", "sed ", "cat ", "head "].iter().any(|m| back.contains(m));
        if !is_read {
            continue;
        }
        if let Some(j) = back.rfind("skills/") {
            let name = &back[j + 7..];
            if !name.is_empty()
                && name.len() < 64
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                *map.entry(name.to_string()).or_default() += 1;
            }
        }
    }
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
    s.chars().filter(|c| !"-_".contains(*c)).collect::<String>().to_lowercase()
}

fn uses_of(map: &HashMap<String, usize>, name: &str) -> usize {
    let c = canon(name);
    map.iter().filter(|(k, _)| canon(k) == c).map(|(_, v)| v).sum()
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
            if uses == 0 && age_days(now, md.modified().ok()) > GRACE_DAYS {
                let reads = usage.skill_reads.get(&name).copied().unwrap_or(0);
                let reads_note = if reads > 0 {
                    format!(" ({reads} raw file reads observed — hooks or manual)")
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
        push_harness_skill(&f, "codex", usage.codex_sessions, &usage.skill_reads, &mut seen, &mut units, &mut findings, now);
    }
    for f in pi_skill_files(&home.join(".pi/agent/npm")) {
        push_harness_skill(&f, "pi", usage.pi_sessions, &usage.skill_reads, &mut seen, &mut units, &mut findings, now);
    }

    // Claude commands: ~/.claude/commands/*.md
    if let Ok(rd) = std::fs::read_dir(home.join(".claude/commands")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "md") {
                continue;
            }
            let Ok(md) = p.metadata() else { continue };
            let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            units += 1;
            if usage.commands.get(&name).copied().unwrap_or(0) == 0
                && age_days(now, md.modified().ok()) > GRACE_DAYS
            {
                findings.push(EstateFinding {
                    rule: "dead-command",
                    unit: format!("command /{name}"),
                    path: p.display().to_string(),
                    fix: format!("confirm with the user, then `rm {}`", p.display()),
                    tokens: crate::estimate_tokens(&std::fs::read_to_string(&p).unwrap_or_default()),
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
    if let Ok(s) = std::fs::read_to_string(home.join(".claude.json")) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
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
        units += 1;
        let (own, other, other_label, sessions) = if *harness == "claude" {
            (&usage.mcp_claude, &usage.mcp_codex, "codex", usage.claude_sessions)
        } else {
            (&usage.mcp_codex, &usage.mcp_claude, "claude", usage.codex_sessions)
        };
        if uses_of(own, name) == 0 {
            let cross = uses_of(other, name);
            let cross_note = if cross > 0 {
                format!(" (used {cross}× in {other_label} — keep it there only)")
            } else {
                String::new()
            };
            let config = if *harness == "claude" { ".claude.json" } else { ".codex/config.toml" };
            let fix = if *harness == "claude" {
                format!("run `claude mcp remove {name}` (or delete the \"{name}\" entry under mcpServers in ~/.claude.json)")
            } else {
                format!("delete the `[mcp_servers.{name}]` block (and any `[mcp_servers.{name}.*]` sub-tables) from ~/.codex/config.toml")
            };
            findings.push(EstateFinding {
                rule: "dead-mcp",
                unit: format!("mcp {harness}:{name}"),
                path: home.join(config).display().to_string(),
                fix,
                tokens: 0,
                uses: 0,
                detail: format!(
                    "mounted ({scope}), 0 calls across {sessions} {harness} sessions — instructions + tool listing paid every session{cross_note}"
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
                    let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
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
                            path: p.display().to_string(),
                            fix: format!(
                                "append to {}: `- [{}]({fname}) — {desc}`",
                                mem.join("MEMORY.md").display(),
                                fname.trim_end_matches(".md")
                            ),
                            tokens: crate::estimate_tokens(&body),
                            uses: 0,
                            detail: "on disk but missing from MEMORY.md index — never loaded".into(),
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
                                "edit {} — update or remove each reference to: {}",
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
                        "edit ~/.claude/CLAUDE.md: keep at most one `{name}` trigger line, delete the other mentions — the skill's own description already announces it"
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
                    "edit {} — update or remove each reference to: {}",
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
                    detail: format!("~{} tok paid on every request of every session", tok_fmt(b.tokens)),
                    action: "tighten",
                });
            }
            blocks.push(b);
        }
    }
    blocks.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    // hook tax: payloads observed injected into transcripts
    for (name, stat) in &usage.hooks {
        let tokens = stat.bytes / 4;
        if tokens > HOOK_TAX_MIN_TOKENS {
            findings.push(EstateFinding {
                rule: "hook-tax",
                unit: format!("hook {name}"),
                path: home.join(".claude/settings.json").display().to_string(),
                fix: format!(
                    "with the user, decide if the `{name}` payload earns ~{} tok per session; if not, slim the injected text or narrow the hook matcher in ~/.claude/settings.json",
                    tok_fmt(tokens / stat.fires.max(1))
                ),
                tokens,
                uses: stat.fires,
                detail: format!(
                    "injects ~{} tok per firing, {} firings observed",
                    tok_fmt(tokens / stat.fires.max(1)),
                    stat.fires
                ),
                action: "review necessity",
            });
        }
    }

    findings.sort_by(|a, b| rank(a.rule).cmp(&rank(b.rule)).then(b.tokens.cmp(&a.tokens)));

    let mut used: Vec<String> = Vec::new();
    let mut push_usage = |kind: &str, map: &HashMap<String, usize>| {
        let mut v: Vec<_> = map.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (name, n) in v {
            used.push(format!("{kind} {name}: {n} uses"));
        }
    };
    push_usage("skill", &usage.skills);
    push_usage("skill-read", &usage.skill_reads);
    push_usage("command", &usage.commands);
    push_usage("mcp(claude)", &usage.mcp_claude);
    push_usage("mcp(codex)", &usage.mcp_codex);
    let hook_samples: Vec<(String, String)> = usage
        .hooks
        .iter()
        .filter(|(_, s)| !s.sample.is_empty())
        .map(|(n, s)| (n.clone(), s.sample.clone()))
        .collect();

    let tokens_flagged = findings.iter().map(|f| f.tokens).sum();
    let mut report = EstateReport {
        version: crate::REPORT_VERSION,
        summary: EstateSummary {
            sessions_claude: usage.claude_sessions,
            sessions_codex: usage.codex_sessions,
            sessions_pi: usage.pi_sessions,
            units,
            findings: findings.len(),
            tokens_flagged,
        },
        findings,
        blocks,
        usage: used,
        semantic: None,
    };
    report.usage.extend(hook_samples.into_iter().map(|(n, s)| format!("hook-sample {n}: {s}")));
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
    if reads.get(&name).copied().unwrap_or(0) == 0 && age_days(now, md.modified().ok()) > GRACE_DAYS {
        let fix = if harness == "codex" {
            format!("disable or uninstall the Codex plugin providing `{name}` (deleting from the plugin cache gets re-synced)")
        } else {
            format!("remove the pi package providing `{name}` from ~/.pi/agent/npm")
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
    let commits: Vec<u64> = stdout.lines().filter_map(|l| l.trim().parse().ok()).collect();
    let last = *commits.first()?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
    Some((now.saturating_sub(last) / 86_400, commits.len()))
}

fn git_note(path: &Path) -> String {
    match git_stats(path) {
        Some((age, commits)) => format!("; git: {commits} commit{}, last change {age}d ago", if commits == 1 { "" } else { "s" }),
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
    const FS_ROOTS: [&str; 7] = ["/Users/", "/tmp/", "/private/", "/var/", "/etc/", "/opt/", "/home/"];
    let home = std::env::var("HOME").unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for tok in body.split_whitespace() {
        let t = tok
            .trim_matches(|c: char| "()[]`'\",;:*.".contains(c))
            .trim_end_matches('/');
        let expanded = if let Some(rest) = t.strip_prefix("~/") { format!("{home}/{rest}") } else { t.to_string() };
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
        ("CLAUDE.md (global instructions)", home.join(".claude/CLAUDE.md")),
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
                    if f.path().extension().is_some_and(|x| x == "md") {
                        if let Ok(s) = std::fs::read_to_string(f.path()) {
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
    }
    let digest = crate::cap_middle(digest, 50_000);
    let prompt = format!(
        "You are auditing an AI coding agent's static context (global instructions, skills, memory files, hook payloads) for waste.\n\
         Find CONTRADICTIONS (directives that conflict with each other, with themselves, or with the observed usage stats) \
         and DUPLICATION (the same guidance stated in multiple places). Cite source names. Be specific.\n\n\
         CONTRADICTIONS:\n- <list>\n\nDUPLICATION:\n- <list>\n\n\
         Observed usage ({} claude / {} codex / {} pi sessions):\n{}\n\nContext sources:\n{}",
        report.summary.sessions_claude,
        report.summary.sessions_codex,
        report.summary.sessions_pi,
        report.usage.join("\n"),
        digest
    );
    crate::llm_sections(&prompt)
}

// ---------- output ----------

pub(crate) fn tok_or_unknown(tokens: usize) -> String {
    if tokens == 0 { "?".into() } else { format!("~{}", tok_fmt(tokens)) }
}

pub(crate) fn human(r: &EstateReport) {
    let s = &r.summary;
    println!(
        "cxwatch estate — static context vs usage in {} claude · {} codex · {} pi sessions",
        s.sessions_claude, s.sessions_codex, s.sessions_pi
    );
    println!(
        "  units {} · findings {} · ≈{} tok flagged (per-unit costs; always-loaded units cost this every session)",
        s.units,
        s.findings,
        tok_fmt(s.tokens_flagged)
    );
    if r.findings.is_empty() {
        println!("  ✔ estate is clean");
    }
    for f in &r.findings {
        println!(
            "  {:<20} {:>7} {:>5}  {} — {} → {}",
            f.rule,
            tok_or_unknown(f.tokens),
            format!("{}×", f.uses),
            f.unit,
            f.detail,
            f.action
        );
    }
    if let Some(sem) = &r.semantic {
        println!("  semantic ({}):", sem.model_used);
        println!("    contradictions:\n      {}", sem.contradiction.replace('\n', "\n      "));
        println!("    duplication:\n      {}", sem.bloating.replace('\n', "\n      "));
    }
}

pub(crate) const GROUPS: [(&str, &str); 10] = [
    ("dead-mcp", "Disable unused MCP servers"),
    ("dead-skill", "Delete or demote dead skills"),
    ("duplicate-directive", "Merge duplicated directives"),
    ("heavy-block", "Tighten heavy instruction blocks"),
    ("hook-tax", "Slim hook payloads"),
    ("dead-command", "Delete unused commands"),
    ("orphan-memory", "Repair memory indexes — orphaned files"),
    ("dangling-index", "Repair memory indexes — dangling entries"),
    ("stale-ref", "Fix stale references"),
    ("stale-memory", "Review stale memories"),
];

pub(crate) fn markdown(r: &EstateReport) -> String {
    let s = &r.summary;
    let mut md = format!(
        "# cxwatch estate — fix report\n\n\
         - Sessions scanned: {} claude · {} codex · {} pi\n- Units audited: {}\n- Fixes: {}\n- Tokens flagged: ~{}\n\n\
         ## For the executing agent\n\n\
         You are cleaning up an AI coding agent's static context. Work through the checklists below top to\n\
         bottom; each item states its own concrete fix. Tick items off as you go. Anything involving a\n\
         deletion or config edit: show the user exactly what you are about to change and get confirmation\n\
         first. Do not touch anything not listed here. When finished, summarize what was applied and what\n\
         was skipped.\n\n\
         ## Fixes\n\n",
        s.sessions_claude,
        s.sessions_codex,
        s.sessions_pi,
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
        let saved_note = if saved > 0 { format!(" — ~{} tok", tok_fmt(saved)) } else { String::new() };
        md.push_str(&format!("### {heading} ({}{saved_note})\n\n", group.len()));
        for f in group {
            let tok_note = if f.tokens > 0 { format!(" [~{} tok]", tok_fmt(f.tokens)) } else { String::new() };
            md.push_str(&format!(
                "- [ ] **{}**{tok_note} — {}\n      - why: {}\n      - file: `{}`\n",
                f.unit, f.fix, f.detail, f.path
            ));
        }
        md.push('\n');
    }
    if !r.blocks.is_empty() {
        md.push_str("## Always-loaded instruction blocks (priced per heading)\n\n| file | block | tokens |\n|---|---|---|\n");
        for b in &r.blocks {
            md.push_str(&format!("| {} | {} | ~{} |\n", b.file, b.heading, tok_fmt(b.tokens)));
        }
        md.push('\n');
    }
    if let Some(sem) = &r.semantic {
        md.push_str(&format!(
            "## Semantic findings ({})\n\nLLM-reported — discuss with the user before acting; propose a fix per item.\n\n\
             ### Contradictions\n{}\n\n### Duplication\n{}\n",
            sem.model_used, sem.contradiction, sem.bloating
        ));
    }
    md
}

pub(crate) fn estate_cmd(json: bool, want_semantic: bool, output: Option<String>) -> Result<()> {
    let mut r = audit();
    if want_semantic {
        r.semantic = Some(semantic_pass(&r).unwrap_or_else(|e| Semantic {
            contradiction: format!("semantic unavailable: {e}"),
            bloating: String::new(),
            model_used: crate::SEMANTIC_MODEL.into(),
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
        let line = r#"{"x":[{"name":"Skill","input":{"skill":"graphify"}},{"name":"mcp__chrome-devtools__click"}]} <command-name>/effort"#;
        let mut skills = HashMap::new();
        let mut mcp = HashMap::new();
        let mut cmds = HashMap::new();
        count_captures(line, "\"name\":\"Skill\",\"input\":{\"skill\":\"", |c| c == '"', &mut skills);
        count_captures(line, "<command-name>/", |c| !(c.is_ascii_alphanumeric() || "-_:".contains(c)), &mut cmds);
        count_mcp(line, &mut mcp);
        assert_eq!(skills.get("graphify"), Some(&1));
        assert_eq!(mcp.get("chrome-devtools"), Some(&1));
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
        count_skill_reads(r#"{"arguments":{"path":"/Users/x/.claude/skills/graphify/SKILL.md"}}"#, &mut reads2);
        assert_eq!(reads2.get("graphify"), Some(&1));
    }

    #[test]
    fn prose_skill_mention_is_not_usage() {
        let line = "- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph";
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
        assert!(stat.bytes > 15);
        assert!(stat.sample.contains("mullet"));
    }

    #[test]
    fn index_link_extraction() {
        let idx = "# Notes\n- [A](a.md) — hook\n- [B](b.md)\n- [ext](https://x.com/y.md)\n";
        assert_eq!(index_links(idx), vec!["a.md".to_string(), "b.md".to_string()]);
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
        let (age, commits) = git_stats(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml").as_path())
            .expect("tracked file");
        assert!(commits >= 1);
        assert!(age < 36_500);
        assert!(git_stats(Path::new("/tmp/definitely-not-in-git.xyz")).is_none());
    }

    #[test]
    fn missing_path_detection() {
        let body = "See /tmp/definitely-not-real/xyz.rs and /rest/e2e/reset and /runs/{id} and /tmp";
        let missing = missing_paths(body);
        assert_eq!(missing, vec!["/tmp/definitely-not-real/xyz.rs".to_string()]);
    }
}
