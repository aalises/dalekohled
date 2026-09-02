# cxwatch demo — render with: vhs demo.tape
# Fully self-contained: builds the release binary and a synthetic $HOME
# (demo/fixtures.py) first, so the recording never shows real session data.

Output demo.gif
Output demo.mp4

Set Shell "zsh"
Set Theme "Catppuccin Mocha"
Set FontSize 26
Set Width 2400
Set Height 1550
Set Padding 32
Set TypingSpeed 75ms

# ── setup: fresh build + staged home with synthetic sessions (hidden) ──
Hide
Type `cargo build --release >/dev/null 2>&1 && export PATH="$PWD/target/release:$PATH" && python3 demo/fixtures.py >/dev/null 2>&1 && export HOME=/tmp/cxwatch-demo-home && clear`
Enter
Show

# ── intro card ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;36m🔭  cxwatch\033[0m — \033[1msee the context your coding agent no longer needs\033[0m\n\n   agents hoard stale file reads, superseded output and dead configuration.\n   cxwatch finds it, prices it in tokens, and fixes it.\n\n   works with \033[1mClaude Code · Codex · pi · OpenCode · Cursor\033[0m\n\n   \033[2mall data in this demo is synthetic (demo/fixtures.py)\033[0m\n'`
Enter
Show
Sleep 4s

# ── ① see every session ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m①  SEE EVERY SESSION\033[0m\n\n   every harness on your machine, one list —\n   newest first, sized, with the source agent\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch sessions"
Sleep 600ms
Enter
Sleep 4.5s

# ── ② audit a session ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m②  AUDIT A SESSION\033[0m\n\n   point cxwatch at any transcript — stale reads, superseded copies,\n   oversized thinking and output, each priced in tokens\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch audit ~/.claude/projects/-Users-demo-dev-acmeshop/33333333-*.jsonl"
Sleep 600ms
Enter
Sleep 5s
Type "clear && cxwatch audit cursor:aaaaaaaa-0000-4000-8000-000000000001"
Sleep 600ms
Enter
Sleep 4.5s

# ── ③ audit your config ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m③  AUDIT YOUR CONFIG\033[0m\n\n   skills nobody invokes, MCP servers nobody calls, instructions you\n   keep retyping, commands that keep failing or getting blocked,\n   sessions that run too long — joined against real usage\n   from your transcripts\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch audit"
Sleep 600ms
Enter
Sleep 7s

# ── ④ autofix ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m④  AUTOFIX\033[0m\n\n   mechanical fixes applied for you —\n   \033[32mevery change backed up to the cxwatch trash first\033[0m\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch audit --fix --yes"
Sleep 600ms
Enter
Sleep 7s

# ── ⑤ hand it to an agent ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;33m⑤  HAND IT TO AN AGENT\033[0m\n\n   export an executable cleanup plan — checklists, exact commands,\n   file paths and evidence. paste it into any coding agent.\n'`
Enter
Show
Sleep 3s
Hide
Type "clear"
Enter
Show
Type "cxwatch audit -o cxwatch-cleanup.md && head -n 24 cxwatch-cleanup.md"
Sleep 600ms
Enter
Sleep 6s
Type "clear && sed -n '/Session size/,$p' cxwatch-cleanup.md"
Sleep 600ms
Enter
Sleep 4s

# ── outro card ──
Hide
Type `clear && printf '\n\n\n\n   \033[1;36m🔭  cxwatch\033[0m — a linter for your coding agents\n\n   \033[1mgithub.com/aalises/dalekohled\033[0m\n\n   cargo install --git https://github.com/aalises/dalekohled\n\n   \033[2mMIT · session audit + config audit + autofix\033[0m\n'`
Enter
Show
Sleep 4.5s
