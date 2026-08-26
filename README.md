# cxwatch 🔭

**See the context your coding agent no longer needs.**

cxwatch audits coding-agent sessions and persistent agent setup. It ranks stale context by token cost, shows the evidence for each finding, and gives you a clear cleanup path.

**Supported harnesses: Claude Code, Codex, pi, and OpenCode.**

![cxwatch terminal demo](demo.gif)

Long sessions collect old file reads, replaced tool output, and large reasoning blocks. Agent setup also grows over time. Skills, commands, MCP servers, hooks, and memory files can stay active after their value is gone.

cxwatch answers four practical questions:

- How much of this session can I reclaim?
- Which exact items cause the waste?
- Which parts of my agent setup show no observed use?
- Which fixes can I apply now, and which ones need review?

## One tool, three views

| View | What it does | Start it |
|---|---|---|
| Session audit | Finds stale reads and large context items in one run | `cxwatch` |
| Estate audit | Compares static agent setup with observed transcript use | `cxwatch estate` |
| Rot-o-meter | Shows a compact score for status lines and terminal bars | `cxwatch status` |

The default audits use local files. They do not change your agent configuration. cxwatch writes only its cache and the reports that you request. The `--fix` option is the only audit mode that changes agent setup.

## Supported harnesses

| Harness | Session data | Estate data |
|---|---|---|
| Claude Code | `~/.claude/projects` | Skills, commands, MCP servers, hooks, memory, and `CLAUDE.md` |
| Codex | `~/.codex/sessions` and `~/.codex/archived_sessions` | Plugin skills, MCP servers, and `AGENTS.md` |
| pi | `~/.pi/agent/sessions` | Package skills |
| OpenCode | `~/.local/share/opencode/opencode.db` | `~/.config/opencode/AGENTS.md` |

cxwatch reads OpenCode session data through the local `sqlite3` command in read-only mode.

## Install and start

You need Rust 1.88 or later.

```bash
cargo install --git https://github.com/aalises/dalekohled
cxwatch
```

The first command installs cxwatch. The second command opens the session picker.

If you use OpenCode, the `sqlite3` command must be available in your `PATH`.

To install from a local clone:

```bash
git clone https://github.com/aalises/dalekohled.git
cd dalekohled
cargo install --path .
```

## Your first audit

Run cxwatch with no arguments:

```bash
cxwatch
```

Then:

1. Type part of a project name or prompt to filter the session list.
2. Select a session and press `Enter`.
3. Review the largest findings first.
4. Press `Ctrl+E` to audit persistent agent setup.
5. Press `e` in a report to export a Markdown cleanup plan.

For a quick non-interactive check:

```bash
cxwatch report
cxwatch estate
cxwatch status
```

## Command guide

| Command | Result |
|---|---|
| `cxwatch` | Opens the interactive session picker |
| `cxwatch report [SESSION]` | Audits one session, or the most recent session |
| `cxwatch explain [SESSION] -o report.md` | Writes a Markdown session report and runs the semantic pass |
| `cxwatch sessions` | Lists all discovered sessions |
| `cxwatch pick [--semantic]` | Opens the picker and can enable semantic analysis at startup |
| `cxwatch estate` | Audits skills, commands, MCP servers, hooks, memory, and instruction files |
| `cxwatch estate -o cleanup.md` | Writes a reviewable Markdown cleanup plan |
| `cxwatch estate --fix` | Offers each supported mechanical fix for confirmation |
| `cxwatch status [SESSION]` | Prints a one-line score for a selected or recent session |
| `cxwatch statusline` | Reads Claude Code status-line data from standard input and scores the current session |

A `SESSION` can be a transcript path. OpenCode sessions use the internal `opencode:<id>` form that `cxwatch sessions` prints.

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

The session audit reports waste. It does not remove history from a running agent session.

## Estate audit

An estate audit checks persistent context against observed use in local transcripts.

| Check | What it means |
|---|---|
| `dead-mcp` | An MCP server has no observed calls in its configured agent |
| `dead-skill` | A skill has no observed use after a 14-day grace period |
| `dead-command` | A Claude Code command has no observed use |
| `duplicate-directive` | `CLAUDE.md` repeats guidance for a skill |
| `hook-tax` | A Claude Code hook injects a large payload |
| `orphan-memory` | A memory file is missing from `MEMORY.md` |
| `dangling-index` | `MEMORY.md` points to a file that does not exist |
| `stale-ref` | An instruction or memory file points to a missing path |
| `stale-memory` | A memory file has not changed for 120 days |
| `heavy-block` | An always-loaded instruction section contains more than 400 tokens |

Each finding includes:

- the rule and affected unit;
- the estimated token cost;
- the observed-use count;
- the relevant file path;
- a proposed action and concrete fix.

“No observed use” is evidence from the transcripts that cxwatch can read. It is not proof that you will never need the item. Review the cleanup plan before you remove configuration.

## Apply safe fixes

cxwatch can apply a limited set of mechanical estate fixes:

- add a missing memory index entry;
- remove a broken memory index entry;
- move an unused Claude Code skill or command to the cxwatch trash;
- remove an unused Claude Code MCP server with `claude mcp remove`;
- remove an unused Codex MCP table from `config.toml`.

Run the interactive fix flow:

```bash
cxwatch estate --fix
```

For each fix, choose `y`, `n`, `a` to apply all remaining fixes, or `q` to stop. To apply all supported fixes without prompts:

```bash
cxwatch estate --fix --yes
```

In the interactive estate view, select a finding and press `f` twice. The first press shows the exact operation. The second press applies it.

Before cxwatch edits a file, it saves a copy under `~/.cache/cxwatch/trash`. cxwatch moves deleted files and directories to the same location. A fix that runs an external command uses that command’s behavior. Findings that need judgment stay report-only.

## Keep the score visible

`cxwatch status` prints a one-line rot score:

```text
[codex] rot  62% ██████░░░░ ~135.8k tok reclaimable · 47 findings
```

Without a session argument, it scores the most recent discovered session. cxwatch caches the line by session size, so frequent status refreshes do not repeat the full audit when the session did not change.

### Claude Code status line

Add this setting to `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "cxwatch statusline"
  }
}
```

Claude Code sends the current transcript path on standard input. `cxwatch statusline` uses that path, so the score follows the active Claude Code session.

### tmux

Add these lines to `~/.tmux.conf`:

```tmux
set -g status-right '#(cxwatch status)'
set -g status-interval 15
```

This form shows the latest discovered session across all supported agents.

## Local analysis and optional semantic analysis

Deterministic audits stay on your computer. They parse transcripts, count tokens, match file operations, and compare configured units with observed calls.

The optional semantic pass looks for contradictions and repeated guidance that fixed rules cannot detect:

```bash
cxwatch report --semantic
cxwatch estate --semantic -o cleanup.md
cxwatch pick --semantic
```

`cxwatch explain` also runs the semantic pass.

Semantic analysis needs the `pi` command. The default model is `moonshotai/kimi-k3`. Set `CXWATCH_SEMANTIC_MODEL` to select another model:

```bash
CXWATCH_SEMANTIC_MODEL=provider/model cxwatch report --semantic
```

The semantic pass sends a limited digest through `pi` to the configured model provider. The digest can contain session messages, instructions, skill text, and memory text. Check the provider’s data policy before you enable this option.

## Output for scripts and cleanup tasks

Use JSON when another tool must process the report:

```bash
cxwatch report --json
cxwatch estate --json
```

The JSON includes the report version, summary, findings, token counts, and fix details.

Use Markdown when a person or another agent must review the work:

```bash
cxwatch explain path/to/run.jsonl -o session-report.md
cxwatch estate -o cleanup.md
```

The estate plan groups findings by action and gives each item a concrete checklist entry.

## Interactive controls

### Session picker

| Key | Action |
|---|---|
| Type text | Filter by agent, project, or prompt |
| `Up` / `Down` | Move through sessions |
| `Enter` | Audit the selected session |
| `Ctrl+E` | Open the estate audit |
| `Tab` | Enable or disable semantic analysis |
| `Esc` | Clear the filter, or exit when the filter is empty |
| `Ctrl+C` | Exit |

### Report view

| Key | Action |
|---|---|
| `Up` / `Down` | Scroll |
| `Enter` | Show the proposed estate fix |
| `f` twice | Confirm and apply a mechanical estate fix |
| `e` | Export a Markdown report |
| `Esc` | Return to the picker |
| `q` | Exit |

The `Enter` and `f` actions apply only to estate findings.

## Accuracy and limits

- Token counts use the `o200k` tokenizer. They are estimates, not provider billing data.
- The report depends on the transcript formats that each agent writes.
- Shell analysis recognizes common file readers such as `cat`, `head`, `tail`, and `sed`.
- An estate use count includes only the transcripts that are available on the computer.
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
