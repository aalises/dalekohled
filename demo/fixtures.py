#!/usr/bin/env python3
"""Create a staged $HOME with synthetic agent sessions for demo recording.

Usage:
    python3 demo/fixtures.py [target-home]   # default /tmp/cxwatch-demo-home
    HOME=/tmp/cxwatch-demo-home cxwatch      # or: vhs demo.tape

The data is entirely synthetic ("acmeshop" project) but shaped exactly like
real Claude Code / Codex / pi / OpenCode transcripts, and it triggers every
session and estate rule at least once.
"""

import json
import os
import shutil
import sqlite3
import sys
import time

HOME = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cxwatch-demo-home"
NOW = time.time()
OLD = NOW - 200 * 86400  # older than every grace/staleness window

BIG_CODE = "".join(
    f"const row{i} = cart.items[{i}].price * cart.items[{i}].qty; // recompute line total\n"
    for i in range(320)
)
THINKING = (
    "I need to trace the checkout flow and compare the computed totals against "
    "the payment gateway response before changing anything at all. " * 120
)
HOOK_PAYLOAD = "# team-conventions\nAlways run the linter and the unit tests before committing anything. " * 60


def write(rel, content, mtime=None):
    path = os.path.join(HOME, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    if mtime:
        os.utime(path, (mtime, mtime))


def jsonl(lines):
    # compact separators: real harnesses write "key":"value" with no spaces,
    # and cxwatch's usage patterns match that exact shape
    return "\n".join(json.dumps(l, separators=(",", ":")) for l in lines) + "\n"


shutil.rmtree(HOME, ignore_errors=True)

# ---------- claude sessions ----------

session_rotten = [
    {"type": "user", "uuid": "u0", "message": {"role": "user", "content": "can you fix the cart total rounding bug in checkout?"}},
    {"type": "attachment", "attachment": {"type": "hook_success", "hookName": "SessionStart:startup", "content": HOOK_PAYLOAD}},
    {"type": "assistant", "uuid": "u1", "message": {"role": "assistant", "content": [
        {"type": "thinking", "thinking": THINKING},
        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/Users/demo/dev/acmeshop/src/cart.ts"}}]}},
    {"type": "user", "uuid": "u2", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": BIG_CODE}]}},
    {"type": "assistant", "uuid": "u3", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "/Users/demo/dev/acmeshop/src/cart.ts"}}]}},
    {"type": "user", "uuid": "u4", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t2", "content": BIG_CODE}]}},
    {"type": "assistant", "uuid": "u5", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t3", "name": "Edit", "input": {"file_path": "/Users/demo/dev/acmeshop/src/cart.ts"}}]}},
    {"type": "user", "uuid": "u6", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t3", "content": "ok"}]}},
    {"type": "assistant", "uuid": "u7", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t4", "name": "Skill", "input": {"skill": "deploy-helper"}}]}},
    {"type": "assistant", "uuid": "u8", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t5", "name": "mcp__github__create_pr", "input": {}}]}},
    {"type": "assistant", "uuid": "u9", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Fixed the rounding bug in cart totals and opened a PR."}]}},
]
write(".claude/projects/-Users-demo-dev-acmeshop/11111111-1111-4111-8111-111111111111.jsonl", jsonl(session_rotten), NOW - 60)

session_clean = [
    {"type": "user", "uuid": "v0", "message": {"role": "user", "content": "add rate limiting to the public API"}},
    {"type": "attachment", "attachment": {"type": "hook_success", "hookName": "SessionStart:startup", "content": HOOK_PAYLOAD}},
    {"type": "assistant", "uuid": "v1", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Done — token bucket at the gateway, 100 req/min per key."}]}},
]
write(".claude/projects/-Users-demo-dev-acmeapi/22222222-2222-4222-8222-222222222222.jsonl", jsonl(session_clean), NOW - 180)

# ---------- codex session ----------

codex = [
    {"timestamp": "2026-08-20T09:00:00.000Z", "type": "session_meta",
     "payload": {"id": "0198beef-0000-7000-8000-000000000000", "cwd": "/Users/demo/dev/acmeshop"}},
    {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [
        {"type": "input_text", "text": "audit the payments module and address the PR review comments"}]}},
    {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c1",
     "arguments": json.dumps({"cmd": "sed -n '1,200p' src/payments.ts"})}},
    {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1", "output": BIG_CODE}},
    {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c2",
     "arguments": json.dumps({"cmd": "sed -n '1,400p' src/payments.ts"})}},
    {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c2", "output": BIG_CODE}},
    {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c3",
     "arguments": json.dumps({"cmd": "cat src/gateway.ts"})}},
    {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c3", "output": BIG_CODE}},
    {"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [
        {"type": "output_text", "text": "Review comments addressed; retry logic extracted into gateway.ts."}]}},
]
write(".codex/sessions/2026/08/20/rollout-2026-08-20T09-00-00-0198beef-0000-7000-8000-000000000000.jsonl", jsonl(codex), NOW - 120)

# ---------- pi session ----------

pi = [
    {"type": "message", "id": "p1", "message": {"role": "user", "content": [{"type": "text", "text": "optimize the search indexer, it feels slow on large catalogs"}]}},
    {"type": "message", "id": "p2", "message": {"role": "assistant", "content": [
        {"type": "toolCall", "id": "tc1", "name": "read", "arguments": {"path": "/Users/demo/dev/acmeshop/src/indexer.ts"}}]}},
    {"type": "message", "id": "p3", "message": {"role": "toolResult", "toolCallId": "tc1", "content": [{"type": "text", "text": BIG_CODE[:4000]}]}},
    {"type": "message", "id": "p4", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Batched the writes and added an LRU for the tokenizer — 6x faster."}]}},
]
write(".pi/agent/sessions/--Users-demo-dev-acmeshop--/2026-08-20T10-00-00-000Z_0198cafe.jsonl", jsonl(pi), NOW - 240)

# ---------- opencode db ----------

db_dir = os.path.join(HOME, ".local/share/opencode")
os.makedirs(db_dir, exist_ok=True)
db = sqlite3.connect(os.path.join(db_dir, "opencode.db"))
db.executescript(
    """
    CREATE TABLE session (id text primary key, project_id text, slug text, directory text,
        title text, version text, time_created integer, time_updated integer);
    CREATE TABLE message (id text primary key, session_id text, time_created integer,
        time_updated integer, data text);
    CREATE TABLE part (id text primary key, message_id text, session_id text,
        time_created integer, time_updated integer, data text);
    """
)
ms = int((NOW - 300) * 1000)
for i, title in enumerate(["Refactor checkout flow", "Payment gateway audit"]):
    sid = f"ses_demo{i}"
    db.execute("INSERT INTO session VALUES (?,?,?,?,?,?,?,?)",
               (sid, "prj", f"slug{i}", "/Users/demo/dev/acmeshop", title, "1", ms - i * 60000, ms - i * 60000))
    db.execute("INSERT INTO message VALUES (?,?,?,?,?)",
               (f"msg_{i}a", sid, ms, ms, json.dumps({"role": "user"})))
    db.execute("INSERT INTO part VALUES (?,?,?,?,?,?)",
               (f"prt_{i}a", f"msg_{i}a", sid, ms, ms, json.dumps({"type": "text", "text": title.lower()})))
    db.execute("INSERT INTO message VALUES (?,?,?,?,?)",
               (f"msg_{i}b", sid, ms + 1, ms + 1, json.dumps({"role": "assistant"})))
    db.execute("INSERT INTO part VALUES (?,?,?,?,?,?)",
               (f"prt_{i}b", f"msg_{i}b", sid, ms + 1, ms + 1, json.dumps(
                   {"type": "tool", "tool": "read", "callID": f"oc{i}",
                    "state": {"status": "completed", "input": {"filePath": "/Users/demo/dev/acmeshop/src/checkout.ts"},
                              "output": BIG_CODE[:3000]}})))
db.commit()
db.close()

# ---------- estate ----------

write(".claude/skills/legacy-importer/SKILL.md",
      "---\nname: legacy-importer\ndescription: Import products from the legacy CSV exporter.\n---\n\n"
      + "Steps to import the legacy catalog dumps. " * 60, OLD)
write(".claude/skills/deploy-helper/SKILL.md",
      "---\nname: deploy-helper\ndescription: Ship a release to staging and production.\n---\n\nRun the deploy pipeline.\n", OLD)
write(".claude/commands/scaffold.md", "Scaffold a new acmeshop module with tests and docs.\n", OLD)
write(".claude/commands/ship.md", "Tag, changelog, deploy to prod, announce in the channel.\n", OLD)
write(".claude/CLAUDE.md",
      "# deploy-helper\nUse the deploy-helper skill for releases. When I say ship it, invoke deploy-helper.\n\n"
      "# Release process notes\n" + "The release train leaves every Tuesday; check the migration matrix, warm the caches, rotate the canary cohort, then watch the error budget dashboards for thirty minutes before promoting. " * 18)
write(".claude.json", json.dumps({"mcpServers": {"figma": {}, "github": {}}}))
write(".codex/config.toml", "[mcp_servers.jira]\nurl = \"https://example.invalid/mcp\"\n")
write(".codex/AGENTS.md", "Use pnpm. Keep PRs small. Never commit secrets.\n")

mem = ".claude/projects/-Users-demo-dev-acmeshop/memory/"
write(mem + "MEMORY.md",
      "# acmeshop notes\n- [use-pnpm](feedback_use_pnpm.md) — always use pnpm, never npm\n"
      "- [build-cache](reference_build_cache.md) — where the build cache lives\n")
write(mem + "feedback_use_pnpm.md",
      "---\nname: use-pnpm\ndescription: Always use pnpm, never npm\ntype: feedback\n---\n\nUse pnpm for everything.\n", OLD)
write(mem + "reference_build_cache.md",
      "---\nname: build-cache\ndescription: Build cache location\ntype: reference\n---\n\nThe cache lives at /tmp/acme-build-cache/ and is safe to delete.\n", OLD)
write(mem + "feedback_no_force_push.md",
      "---\nname: no-force-push\ndescription: Never force-push shared branches\ntype: feedback\n---\n\nNever force-push to main or release branches.\n")

print(f"staged home ready: {HOME}")
print(f"try: HOME={HOME} cxwatch")
