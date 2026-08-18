---
name: codex-agent-mesh
description: Coordinate bounded local delegation through Codex Agent Mesh, including install, configuration, capability checks, idempotent task submission, reconnect-safe observation, and durable result review. Use when the user asks to install or configure the plugin, or when its MCP tools report a healthy daemon.
---

# Codex Agent Mesh

If the user asks to install, set up, configure, or rebind roles, read
`references/install-and-configure.md` and execute it. Routing changes
belong in mesh settings, never in AGENTS.md.

Use the MCP tools only after the daemon is healthy. Codex remains the
planner and ACK reviewer. Role bindings come from mesh settings, not from
this skill.

Call `list_agents` and use its `role_bindings`, `coordinator_native`, and
`native_models`. Do not read routing from AGENTS.md.

- If the bound target is in `coordinator_native` (default `luna`): spawn a
  Codex subagent with `native_models.<target>`. Do not `delegate_task`,
  do not look for a CLI, and do not treat a missing row in `agents` as
  an error.
- If the bound target is a CLI listed `ENABLED` in `agents`:
  `delegate_task` with that role.
- If a Trellis check step would run, use the mesh `review` binding first.
  Fall back to `trellis-check` only when that binding cannot run.

Bundled defaults (override in settings, never here): implementation=claude,
research=grok, review=luna, freelancer=kimi. Freelancer only when the
user names that role.

Do not infer a cross-provider fallback from generic health. Never invent
a mesh CLI for a coordinator-native binding.

When handing off between stages, put this package in `delegate_task.objective`
or in the `mesh-review` prompt. Do not send a free-form recap.

```
## Original user request
<verbatim user text; never rewrite>

## Brief
目标:
范围:
非目标:
验收标准:
相关文件或上下文:
风险:
待确认事项:

## Evidence
<only for review: actual diff, test/lint results, uncertainties>

## Consult question
<only for freelancer/consult: one concrete question>
```

The original user request outranks any generated brief. Preflight
(`research`) is read-only and may only produce the Brief. Builder
(`implementation`) sees Original + Brief, then investigates, edits, and
verifies. Reviewer (`review` / `mesh-review`) is read-only and answers
only PASS, CHANGES_REQUIRED, or INCONCLUSIVE. Consult (`freelancer`) is
one question, no workspace edits; call it only when the reviewer is
INCONCLUSIVE, there is a concrete high-risk issue, or the user names
that role.

For `delegate_task`, provide that package as the objective, a desired
role, explicit repository/isolation requirements, and one new
`command_key`. Retain that key for retries: if a mutation response is
lost or uncertain, replay the identical request with the same key. Never
generate a replacement key to guess whether the first request took
effect. Save the returned `task_id` and any event cursor.

## Observe, Wait, and Reconnect

Use `inspect_task` for the durable snapshot and replay bounds. For live
observation, call `wait_task` with `until=attention` and `wait_ms=30000`.
That holds until a terminal result or a pending approval/input; it does
not return on every `text_delta` page. Watch streaming output in the
`follow` console instead. If the daemon rejects `until`, omit it and keep
`wait_ms=30000`. A bridge or client reconnect does not change task
ownership: reconnect, inspect, then resume waiting from the last durable
cursor. Treat `CURSOR_EXPIRED`, `AMBIGUOUS_AFTER_DISPATCH`,
`NEEDS_ATTENTION`, and bounded setup/transport diagnostics as visible
uncertainty; do not claim completion or retry an external effect without
the returned evidence.

## Approval and Input

Provider input and approval waits are durable interactions. Present their exact
prompt and consequences to the user, then answer only through `send_task_input`
with the current generation, nonce, digest, and a retained command key. Do not
reuse a stale interaction token, silently approve, or substitute an answer.
An expired, rejected, or uncertain interaction requires an explicit new plan.

## Review and ACK

On a terminal result, inspect the outcome and evidence before calling
`review_task`. A review must name the exact `result_id`, `result_version`, and
`ack_token` supplied by the daemon. ACK is durable and idempotent, but it is not
permission to discard the result before it is understood. Do not review a
different result version or infer that a transport disconnect performed the ACK.

## Worktrees and Dashboard

Write work uses an isolated, detached mesh worktree at the requested base
commit. It is not automatically merged, rebased, or deleted by this skill.
The current-directory path is an exceptional best-effort mode and requires both
its explicit configuration opt-in and an explicit approval; do not request it
as a shortcut around dirty, unborn, non-Git, or isolation failures.

`inspect_task` may return a one-time local dashboard bootstrap URL. Open it
only on the local machine, do not share it, and treat it as a short-lived bearer
credential. The dashboard observes the same durable task state; task approval,
review, and delegation remain MCP/user actions. Settings writes and improvement
controls are independently feature-gated, so a disabled control is unavailable
rather than emulated.

## Improvement and Trust

Improvement proposals are evidence-bearing, single-knob, allowlisted candidates;
they never edit executable code or silently change prompts. Keep candidates in
observation/canary until their deterministic fixture, safety, and promotion
gates pass. A rollback or freeze is a manual-review state, not a retry signal.

The bridge never installs or trusts a cache copy as an ordinary RPC peer. Setup
must explicitly publish the retained digest-addressed runtime. If stderr reports
`development-unsigned`, treat the artifact as local development only, never as
an official release. Official artifacts have a valid pinned Authenticode signer,
hashed metadata, SHA256SUMS, and an SBOM; runtime setup independently enforces
its trust boundary.
