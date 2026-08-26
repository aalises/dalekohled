# dalekohled 🔭

> *dalekohled* (Czech: telescope) — a linter for your AI agents' context.

Same way a code linter says *"unused variable, dead import, these two things conflict"* — but for your
CLAUDE.md, skills, memory files, MCP servers, hooks and session transcripts. The CLI is called **`cxwatch`**.

![demo](demo.gif)

Every agent with tool access eventually **rots its own context**: file reads go stale after edits, tool
outputs get rerun and superseded, thinking blocks bloat. And the *static* estate rots too — skills nobody
invokes, MCP servers nobody calls, memories pointing at deleted paths, directives that contradict each
other. Harnesses handle this with blind threshold compaction. `cxwatch` tells you *what* is decaying,
*why*, *how many tokens* it costs — and *how to fix it*.

Two tiers, like a linter:

- **Script tier** — deterministic and fast. Parses transcripts and the file estate, prices every unit in
  tokens, and joins what's *declared* against what the transcripts show is *used*.
- **LLM tier** (`--semantic`) — contradiction and duplication analysis across instruction prose, fed with
  the real usage stats so it can catch "this directive disagrees with observed behavior".

## Install

Requires [Rust](https://rustup.rs) (edition 2024). Optional: the `pi` CLI on your PATH for `--semantic` passes.

```bash
git clone https://github.com/aalises/dalekohled.git
cd dalekohled
cargo install --path .
```

Or straight from the repo (uses your git credentials):

```bash
cargo install --git https://github.com/aalises/dalekohled
```

## Quick start

```bash
cxwatch                    # TUI: pick a session, get an interactive rot report
cxwatch estate             # audit static context (skills/commands/MCP/memory/hooks)
cxwatch estate --semantic -o plan.md   # agent-ready fix report
```

All commands:

```bash
cxwatch                    # TUI picker (ctrl+e inside opens the estate control panel)
cxwatch pick --semantic    # start with the LLM pass enabled
cxwatch report [path]      # scan a session (default: most recent across harnesses)
cxwatch report --json      # machine-readable
cxwatch explain [path]     # write a Markdown session report
cxwatch sessions           # flat list of all sessions
cxwatch estate             # static-context audit, ledger to stdout
cxwatch estate --json      # machine-readable (includes per-finding `path` and `fix`)
cxwatch estate --semantic -o plan.md   # fix report with LLM contradiction/duplication findings
```

### TUI keys

- **picker** — type to filter (fzf-style), `↑↓` move, `enter` analyze,
  `ctrl+e` estate control panel, `tab` toggle semantic, `esc` clear filter / quit
- **report / estate** — `↑↓` scroll, `enter` show the concrete fix, `e` export Markdown,
  `esc` back, `q` quit

## Session rules (context rot)

Four deterministic rules, each priced by the **tool result** it would reclaim
(results are linked to calls via `toolCallId` / `tool_use_id` / `call_id`):

- `stale-read` — a file was read, then edited later → the read in context no longer matches disk
- `superseded-read` — the same file was read again later → the earlier copy is dead weight
  (covers shell reads too: `cat`, `head`, `sed -n`, …)
- `huge-thinking` — thinking blocks over 2 000 tokens → condense candidates
- `huge-output` — a single tool result over 2 500 tokens → trim or summarize

Reads *after* the last edit are fresh and never flagged. Findings sort by reclaimable tokens.

## Estate audit (the linter part)

Session rot is linear waste — it dies with the session. **Static context rot is multiplied waste**:
every byte of skills, instructions, MCP config, memory and hook payloads is paid on every request of
every session. `cxwatch estate` joins the declared estate against observed usage:

| rule | what it catches | action |
|---|---|---|
| `dead-mcp` | MCP server mounted, 0 calls in that harness (notes cross-harness usage) | disable |
| `dead-skill` | skill never invoked (claude: Skill tool/slash; codex/pi: SKILL.md reads) | delete or demote |
| `duplicate-directive` | skill referenced repeatedly in CLAUDE.md on top of its description | merge |
| `hook-tax` | tokens hooks inject per session, measured from observed payloads | review |
| `dead-command` | custom slash command never used | delete |
| `orphan-memory` | memory file missing from the MEMORY.md index — never loaded | repair index |
| `dangling-index` | MEMORY.md entry pointing at a nonexistent file | repair index |
| `stale-ref` | memory/instructions referencing filesystem paths that no longer exist | update |
| `stale-memory` | memories unmodified for 120+ days | review |

The TUI estate view is a control panel: a stacked token bar by category, the ledger below, and `enter`
on any finding reveals its concrete fix.

## Fix reports for agents

`cxwatch estate -o plan.md` writes an **executable fix report**: checklists grouped by action, each item
carrying the exact remediation (`run \`claude mcp remove figma\``, the precise MEMORY.md line to append),
the evidence, and the absolute file path — plus a preamble instructing the executing agent to confirm
destructive steps with you. Hand it straight to an agent:

```bash
cxwatch estate --semantic -o plan.md
claude "work through plan.md"
```

## Supported harnesses

| harness     | sessions                                  | estate                                          |
|-------------|-------------------------------------------|-------------------------------------------------|
| Claude Code | `~/.claude/projects`                       | skills, commands, memory, hooks, `~/.claude.json` MCP |
| Codex       | `~/.codex/{sessions,archived_sessions}`    | `config.toml` MCP, plugin skills, AGENTS.md     |
| pi          | `~/.pi/agent/sessions`                     | npm package skills                              |

Usage is mined from each harness's own transcripts; skills newer than 14 days get a grace period.
Everything is report-only — the human (or their agent, with confirmation) decides what to delete.

## Demo

`demo.tape` is a [VHS](https://github.com/charmbracelet/vhs) script — re-record with `vhs demo.tape`.
Note: recordings show real session previews from the machine they run on.

## Tests

```bash
cargo test
```

## Roadmap

1. ~~multi-harness parsers, result-linked token accounting, TUI, estate audit, fix reports~~ ✅
2. real tokenizer (currently `len/4` estimate), git age/churn signals, per-block CLAUDE.md pricing
3. LLM tier v2: atomic-claim decomposition, content-hash caching, re-run on file change
4. `cxwatch daemon` — per-session watcher, real-time notifications, pluggable rules
