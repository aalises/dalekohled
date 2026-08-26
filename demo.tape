# cxwatch demo — render with: vhs demo.tape
# Fully self-contained: builds a synthetic $HOME (demo/fixtures.py) first,
# so the recording never shows real session data.

Output demo.gif
Output demo.mp4

Set Shell "zsh"
Set Theme "Catppuccin Mocha"
Set FontSize 26
Set Width 2400
Set Height 1350
Set Padding 32
Set TypingSpeed 75ms

# ── setup: staged home with synthetic sessions (hidden) ──
Hide
Type "python3 demo/fixtures.py >/dev/null 2>&1 && export HOME=/tmp/cxwatch-demo-home && clear"
Enter
Show

# ── intro card ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;36m🔭  cxwatch\033[0m — \033[1msee the context your coding agent no longer needs\033[0m\n\n   agents hoard stale file reads, superseded output and dead configuration.\n   cxwatch finds it, prices it in tokens, and fixes it.\n\n   works with \033[1mClaude Code · Codex · pi · OpenCode\033[0m\n\n   \033[2mall data in this demo is synthetic (demo/fixtures.py)\033[0m\n'`
Enter
Show
Sleep 4s

# ── ① the picker ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m①  PICK A SESSION\033[0m\n\n   every harness on your machine, one picker —\n   type to filter, badges per agent, live prompt previews\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch"
Sleep 600ms
Enter
Sleep 3s
Type "opencode"
Sleep 2.2s
Escape
Sleep 800ms

# ── ② the rot report ──
Type "0198beef"
Sleep 1.5s
Enter
Sleep 4.5s
Escape
Sleep 600ms
Escape
Sleep 500ms

# ── ③ the estate audit ──
Ctrl+E
Sleep 5s
Down@250ms 2
Sleep 1.2s
Enter
Sleep 2.5s
Type "f"
Sleep 3s
Type "e"
Sleep 2s
Type "q"
Sleep 500ms
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m③  THE ESTATE AUDIT\033[0m\n\n   what you just saw: skills nobody invokes, MCP servers nobody calls,\n   broken memory indexes, oversized instruction blocks —\n   joined against real usage from your transcripts.\n\n   \033[32mpress f twice to apply a fix — every change backed up first\033[0m\n'`
Enter
Show
Sleep 4s

# ── ④ hand it to an agent ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m④  HAND IT TO AN AGENT\033[0m\n\n   export an executable cleanup plan — checklists, exact commands,\n   file paths and evidence. paste it into any coding agent.\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch estate -o cxwatch-cleanup.md && head -n 24 cxwatch-cleanup.md"
Sleep 600ms
Enter
Sleep 6s
Type "clear && sed -n '/Always-loaded/,$p' cxwatch-cleanup.md"
Sleep 600ms
Enter
Sleep 4s

# ── ⑤ the rot-o-meter ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m⑤  THE ROT-O-METER\033[0m\n\n   a live rot score for any harness —\n   Claude Code statusline, tmux status bar, shell prompt\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch status ~/.codex/sessions/2026/08/20/rollout-*.jsonl"
Sleep 500ms
Enter
Type "cxwatch status ~/.claude/projects/-Users-demo-dev-acmeapi/*.jsonl"
Sleep 500ms
Enter
Type "cxwatch status"
Sleep 500ms
Enter
Sleep 4.5s

# ── outro card ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;36m🔭  cxwatch\033[0m — a linter for your coding agents\n\n   \033[1mgithub.com/aalises/dalekohled\033[0m\n\n   cargo install --git https://github.com/aalises/dalekohled\n\n   \033[2mMIT · sessions + estate + autofix + rot-o-meter\033[0m\n'`
Enter
Show
Sleep 4.5s
