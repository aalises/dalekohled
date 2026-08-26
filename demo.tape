# cxwatch demo — render with: vhs demo.tape
# Re-record any time; tweak the filter string to feature a different session.

Output demo.gif
Output demo.mp4

Set Shell "zsh"
Set Theme "Catppuccin Mocha"
Set FontSize 26
Set Width 2400
Set Height 1350
Set Padding 32
Set TypingSpeed 75ms

# ── Act 1: every agent session on the machine, instantly identifiable ──
Type "cxwatch"
Sleep 800ms
Enter
Sleep 3.5s

# four harnesses — filter to one project: opencode (yellow) rows appear among claude/pi
Type "dev/n8n"
Sleep 2.5s
Escape
Sleep 800ms

# now down to one identifiable session (the 66%-rot codex monster)
Type "019e1614"
Sleep 2.5s

# ── Act 2: the context-rot report ──
Enter
Sleep 4s
Down@220ms 10
Sleep 3s

# ── Act 3: the estate audit — the "useless context" ledger ──
Escape
Sleep 1s
Escape
Sleep 1.2s
Ctrl+E
Sleep 9s
Down@200ms 8
Sleep 1.5s

# enter reveals the concrete fix for the selected finding
Enter
Sleep 3s

# export the ledger as shareable markdown
Type "e"
Sleep 2.5s

Type "q"
Sleep 1s

# ── Act 4: the fix report — hand it to an agent to execute ──
Type "clear"
Enter
Sleep 500ms
Type "cxwatch estate -o prune-plan.md"
Sleep 800ms
Enter
Sleep 7s
Type "head -n 26 prune-plan.md"
Sleep 800ms
Enter
Sleep 6s

# per-block pricing of always-loaded instructions
Type "clear && sed -n '/Always-loaded/,$p' prune-plan.md"
Sleep 800ms
Enter
Sleep 5s
