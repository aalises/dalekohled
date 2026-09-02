# cxwatch 🔭

**See the context your coding agent no longer needs.**

cxwatch audits coding-agent sessions and persistent agent setup. It ranks stale context by token cost, shows the evidence for each finding, and gives you a clear cleanup path.

**Supported harnesses: Claude Code, Codex, pi, OpenCode, and Cursor.**

![cxwatch terminal demo](demo.gif)

Long sessions collect old file reads, replaced tool output, and large reasoning blocks. Agent setup also grows over time. Skills, commands, MCP servers, hooks, and memory files can stay active after their value is gone.

cxwatch answers four practical questions:

- How much of this session can I reclaim?
- Which exact items cause the waste?
- Which parts of my agent setup show no observed use?
- Which fixes can I apply now, and which ones need review?

## One tool, two views

| View | What it does | Start it |
|---|---|---|
| Session audit | Finds stale reads and large context items in one run | `cxwatch audit SESSION` |
| Config audit | Compares static agent setup with observed transcript use | `cxwatch audit` |

The default audits use local files. They do not change your agent configuration. cxwatch writes only its cache and the reports that you request. The `--fix` option is the only audit mode that changes agent setup.

## Supported harnesses

| Harness | Session data | Config data |
|---|---|---|
| Claude Code | `~/.claude/projects` | Skills (user and installed plugins), commands, MCP servers, hooks, memory, and `CLAUDE.md` |
| Codex | `~/.codex/sessions` and `~/.codex/archived_sessions` | Plugin skills, user skills in `~/.codex/skills` and `~/.agents/skills`, MCP servers, and `AGENTS.md` |
| pi | `~/.pi/agent/sessions` | Package skills |
| OpenCode | `~/.local/share/opencode/opencode.db` | `~/.config/opencode/AGENTS.md` |
| Cursor | Agent and chat conversations in the app's `state.vscdb` | User skills in `~/.cursor/skills` |

cxwatch reads OpenCode and Cursor session data through the local `sqlite3` command in read-only mode.

Cursor keeps its conversations in `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` on macOS, `~/.config/Cursor/User/globalStorage/state.vscdb` on Linux, and `%APPDATA%\Cursor\User\globalStorage\state.vscdb` on Windows. cxwatch reads that store directly. The text-only hook transcripts under `~/.cursor/projects` are mirrors of the same conversations without tool calls, so cxwatch does not read them.

## Install and start

You need Rust 1.88 or later.

```bash
cargo install --git https://github.com/aalises/dalekohled
cxwatch audit
```

The first command installs cxwatch. The second command audits your agent config.

If you use OpenCode or Cursor, the `sqlite3` command must be available in your `PATH`.

To install from a local clone:

```bash
git clone https://github.com/aalises/dalekohled.git
cd dalekohled
cargo install --path .
```

## Your first audit

```bash
cxwatch sessions
cxwatch audit path/to/session.jsonl
cxwatch audit
```

The first command lists every discovered session. The second audits one of them. The third audits your persistent agent setup. Review the largest findings first, and use `-o cleanup.md` to export a Markdown cleanup plan.

## Command guide

| Command | Result |
|---|---|
| `cxwatch sessions` | Lists all discovered sessions |
| `cxwatch audit SESSION` | Audits one session transcript |
| `cxwatch audit` | Audits skills, commands, MCP servers, hooks, memory, and instruction files |
| `cxwatch audit -o report.md` | Writes a Markdown report instead of printing (works with and without a session) |
| `cxwatch audit --fix` | Offers each supported mechanical config fix for confirmation |

A `SESSION` can be a transcript path. OpenCode sessions use the internal `opencode:<id>` form and Cursor sessions the `cursor:<id>` form; `cxwatch sessions` prints both.

## Session audit

A session audit reads one transcript and sorts findings by estimated token cost.

| Check | What it means |
|---|---|
| `stale-read` | A file read happened before a later edit of the same file |
| `superseded-read` | A file read happened before a later read of the same file |
| `huge-thinking` | A reasoning block contains more than 2,000 tokens |
| `huge-output` | A tool result contains more than 2,500 tokens |

For stale and superseded reads, cxwatch assigns the cost of the related tool result. The summary shows estimated session tokens, reclaimable tokens, and a reclaimable percentage.

```text
events 644 · session ≈218.4k tok · 47 findings · ≈135.8k tok reclaimable (62%)
```

The session audit reports waste. Every finding names a copy inside the conversation to drop at the next compaction. cxwatch never asks you to change files on disk, and it does not remove history from a running agent session.

## Config audit

A config audit checks persistent context against observed use in local transcripts. It also audits how you and the agent interact: repeated instructions, commands that keep failing or getting blocked, and session length.

| Check | What it means |
|---|---|
| `dead-mcp` | An MCP server has no observed calls in its configured agent |
| `dead-skill` | A skill has no observed use after a 14-day grace period; a single use clears it |
| `duplicate-skill` | One skill is mounted from two places in the same harness, or two skills in a harness have near-identical descriptions |
| `dead-command` | A Claude Code command has no observed use |
| `repeated-directive` | You typed the same instruction in three or more sessions; it belongs in `CLAUDE.md` |
| `blocked-command` | A shell command was permission-denied three or more times |
| `failing-command` | A shell command failed in at least half of three or more runs |
| `long-sessions` | A quarter or more of a harness's sessions exceed roughly 150k tokens |
| `duplicate-directive` | `CLAUDE.md` repeats guidance for a skill |
| `hook-tax` | A Claude Code hook injects a large payload |
| `orphan-memory` | A memory file is missing from `MEMORY.md` |
| `dangling-index` | `MEMORY.md` points to a file that does not exist |
| `stale-ref` | An instruction or memory file points to a missing path |
| `stale-memory` | A memory file has not changed for 120 days |
| `heavy-block` | An always-loaded instruction section contains more than 400 tokens |

A harness with no local sessions gives no evidence, so cxwatch omits it from the report entirely: no findings, no zero counts. Dead means zero observed uses: a unit used even once is never listed, so a skill you only need now and then is safe. The report also shows a per-harness session size distribution (median, p90, and the count of long sessions) from rough per-transcript token estimates.

To keep long reports readable, each check shows its ten costliest findings in full. The terminal output summarizes the rest in one line, the Markdown plan opens with a summary table and lists the rest in brief, and the JSON output is always complete.

Each finding includes:

- the rule and affected unit;
- the estimated token cost;
- the observed-use count;
- the relevant file path;
- a proposed action and concrete fix.

“No observed use” is evidence from the transcripts that cxwatch can read. It is not proof that you will never need the item. Review the cleanup plan before you remove configuration.

## Apply safe fixes

cxwatch can apply a limited set of mechanical config fixes:

- add a missing memory index entry;
- remove a broken memory index entry;
- append a repeated instruction to `~/.claude/CLAUDE.md`;
- move an unused Claude Code or Cursor skill, or an unused Claude Code command, to the cxwatch trash;
- remove an unused Claude Code MCP server with `claude mcp remove`;
- remove an unused Codex MCP table from `config.toml`.

Run the interactive fix flow:

```bash
cxwatch audit --fix
```

For each fix, choose `y`, `n`, `a` to apply all remaining fixes, or `q` to stop. To apply all supported fixes without prompts:

```bash
cxwatch audit --fix --yes
```

Before cxwatch edits a file, it saves a copy under `~/.cache/cxwatch/trash`. cxwatch moves deleted files and directories to the same location. A fix that runs an external command uses that command’s behavior. Findings that need judgment stay report-only.

## Local analysis and optional semantic analysis

Deterministic audits stay on your computer. They parse transcripts, count tokens, match file operations, and compare configured units with observed calls.

The optional semantic pass looks for contradictions and repeated guidance that fixed rules cannot detect. For the config audit this includes instructions you keep typing in different words across sessions, with a proposed `CLAUDE.md` line for each, and skills in one harness whose descriptions cover the same job:

```bash
cxwatch audit path/to/run.jsonl --semantic
cxwatch audit --semantic -o cleanup.md
```

Semantic analysis needs the `pi` command. The default model is `moonshotai/kimi-k3`. Set `CXWATCH_SEMANTIC_MODEL` to select another model:

```bash
CXWATCH_SEMANTIC_MODEL=provider/model cxwatch audit --semantic
```

The semantic pass sends a limited digest through `pi` to the configured model provider. The digest can contain session messages, instructions, skill text, and memory text. Check the provider’s data policy before you enable this option.

## Output for scripts and cleanup tasks

Use JSON when another tool must process the report:

```bash
cxwatch audit path/to/run.jsonl --json
cxwatch audit --json
```

The JSON includes the report version, summary, findings, token counts, and fix details.

Use Markdown when a person or another agent must review the work:

```bash
cxwatch audit path/to/run.jsonl -o session-report.md
cxwatch audit -o cleanup.md
```

The config plan groups findings by action and gives each item a concrete checklist entry.

## Accuracy and limits

- Token counts use the `o200k` tokenizer. They are estimates, not provider billing data.
- The report depends on the transcript formats that each agent writes.
- Shell analysis recognizes common file readers such as `cat`, `head`, `tail`, and `sed`.
- A config use count includes only the transcripts that are available on the computer.
- Codex, pi, and Cursor skill use is observed as reads of `SKILL.md`, matched by skill name, so two copies of one skill share a use count. Codex plugin skills count only for plugins that `~/.codex/config.toml` lists as enabled; Claude plugin skills come from the versions that `installed_plugins.json` marks as installed.
- Cursor skills marked `disable-model-invocation: true` load only on request, so cxwatch does not audit them. Cursor's MCP servers, rules, hooks, and commands are not audited yet.
- The semantic pass can find nuanced problems, but its output still needs review.
- cxwatch audits context. It does not compact or rewrite an active session.

## Development

Run the checks:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The terminal demo uses [VHS](https://github.com/charmbracelet/vhs). The repository includes `demo.tape` and the generated `demo.gif`. The tape stages a synthetic `$HOME` with `demo/fixtures.py` before recording, so the published media contains no real session data. Re-record with `vhs demo.tape`.

## License

cxwatch uses the MIT License. See [LICENSE](LICENSE).
