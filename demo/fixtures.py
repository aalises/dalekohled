#!/usr/bin/env python3
"""Create a staged $HOME with synthetic agent sessions for demo recording.

Usage:
    python3 demo/fixtures.py [target-home]   # default /tmp/cxwatch-demo-home
    HOME=/tmp/cxwatch-demo-home cxwatch audit  # or: vhs demo.tape

The data is entirely synthetic ("acmeshop" project) but shaped exactly like
real Claude Code / Codex / pi / OpenCode / Cursor transcripts, and it triggers every
session and config rule at least once.
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

# ---------- claude interaction sessions: repeated directive, denied + failing commands ----------
# two of the three are oversized so the long-sessions advisory fires too

DENIAL = "The user doesn't want to proceed with this tool use. The tool use was rejected."
FILLER = ("// " + "checkout regression trace, keep for the report. " * 3 + "\n") * 9000


def interaction_session(n, long):
    lines = [
        {"type": "user", "uuid": f"w{n}0", "message": {"role": "user", "content": "use simple language, no fluff"}},
        {"type": "assistant", "uuid": f"w{n}1", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"b{n}1", "name": "Bash", "input": {"command": "git push origin main"}}]}},
        {"type": "user", "uuid": f"w{n}2", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"b{n}1", "content": DENIAL, "is_error": True}]}},
        {"type": "assistant", "uuid": f"w{n}3", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"b{n}2", "name": "Bash", "input": {"command": "pnpm test --filter checkout"}}]}},
        {"type": "user", "uuid": f"w{n}4", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"b{n}2", "content": "Error: Cannot find module 'vitest'", "is_error": True}]}},
    ]
    if long:
        lines.append({"type": "user", "uuid": f"w{n}5", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"b{n}3", "content": FILLER}]}})
    lines.append({"type": "assistant", "uuid": f"w{n}9", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Plain summary: tests still red, push blocked; see above."}]}})
    return lines


for n, long in ((3, True), (4, True), (5, False)):
    write(f".claude/projects/-Users-demo-dev-acmeshop/{n}{n}{n}{n}{n}{n}{n}{n}-{n}{n}{n}{n}-4{n}{n}{n}-8{n}{n}{n}-{n * 12}.jsonl",
          jsonl(interaction_session(n, long)), NOW - 90 * n)

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

# ---------- cursor db ----------
# Cursor keeps chats in the app's global state store: one composerData row per
# conversation and one bubbleId row per turn (a tool call and its result share a bubble).

cursor_dir = os.path.join(
    HOME,
    "Library/Application Support/Cursor/User/globalStorage"
    if sys.platform == "darwin"
    else ".config/Cursor/User/globalStorage",
)
os.makedirs(cursor_dir, exist_ok=True)
cdb = sqlite3.connect(os.path.join(cursor_dir, "state.vscdb"))
cdb.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
CID = "aaaaaaaa-0000-4000-8000-000000000001"
CART = "/Users/demo/dev/acmeshop/src/cart.ts"


def bubble(bid, kind, **fields):
    b = {"_v": 3, "type": kind, "bubbleId": bid, "text": "", "createdAt": "2026-08-20T11:00:00.000Z"}
    b.update(fields)
    return b


def tool_bubble(bid, name, raw_args, result):
    return bubble(bid, 2, toolFormerData={
        "name": name, "toolCallId": f"tool_{bid}", "status": "completed",
        "rawArgs": json.dumps(raw_args), "params": "{}", "result": json.dumps(result)})


cursor_bubbles = [
    bubble("b1", 1, text="the cart total is off by a cent on discounted items, fix it"),
    tool_bubble("b2", "read_file", {"target_file": CART}, {"contents": BIG_CODE}),
    tool_bubble("b3", "read_file", {"target_file": CART}, {"contents": BIG_CODE}),
    tool_bubble("b4", "search_replace", {"file_path": CART, "old_string": "round(total)", "new_string": "round(line)"},
                {"resultForModel": "Success. Updated the following files:\nM src/cart.ts"}),
    bubble("b5", 2, text="Rounded per line item instead of on the sum; totals now match the gateway."),
]
ms = int((NOW - 420) * 1000)
cdb.execute("INSERT INTO cursorDiskKV VALUES (?,?)", (f"composerData:{CID}", json.dumps({
    "composerId": CID, "name": "Fix cart rounding on discounts", "unifiedMode": "agent",
    "createdAt": ms - 60000, "lastUpdatedAt": ms,
    "fullConversationHeadersOnly": [{"bubbleId": b["bubbleId"], "type": b["type"]} for b in cursor_bubbles]})))
for b in cursor_bubbles:
    cdb.execute("INSERT INTO cursorDiskKV VALUES (?,?)", (f"bubbleId:{CID}:{b['bubbleId']}", json.dumps(b)))
cdb.commit()
cdb.close()

# ---------- config ----------

write(".claude/skills/legacy-importer/SKILL.md",
      "---\nname: legacy-importer\ndescription: Import products from the legacy CSV exporter.\n---\n\n"
      + "Steps to import the legacy catalog dumps. " * 60, OLD)
write(".claude/skills/deploy-helper/SKILL.md",
      "---\nname: deploy-helper\ndescription: Ship a release to staging and production.\n---\n\nRun the deploy pipeline.\n", OLD)
write(".cursor/skills/vue-conventions/SKILL.md",
      "---\nname: vue-conventions\ndescription: House style for Vue components.\n---\n\n"
      + "Use script setup, typed props, and scoped styles. " * 40, OLD)
write(".claude/commands/ship.md", "Tag, changelog, deploy to prod, announce in the channel.\n", OLD)
write(".claude/CLAUDE.md",
      "# Releases\nWhen I say ship it, invoke the deploy-helper skill.\n\n"
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
      "---\nname: build-cache\ndescription: Build cache location\ntype: reference\n---\n\nThe build cache lives next to the repo checkout and is safe to delete.\n", OLD)
write(mem + "feedback_no_force_push.md",
      "---\nname: no-force-push\ndescription: Never force-push shared branches\ntype: feedback\n---\n\nNever force-push to main or release branches.\n")

print(f"staged home ready: {HOME}")
print(f"try: HOME={HOME} cxwatch audit")
