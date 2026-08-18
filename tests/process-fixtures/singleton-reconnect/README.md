# Singleton/reconnect interactive fixture protocol

The two process-acceptance scripts are fail-closed consumers of an external,
interactive Windows fixture driver. The product binary deliberately has no
production fault-injection or storage-seeding switch, so the scripts do not
pretend that ordinary CLI status can prove `RunEx` cardinality, lock ownership,
or commit-boundary kills.

Pass the driver with `-FixtureDriver <absolute path>` and its independently
computed lower-hex SHA-256 with `-FixtureDriverSha256 <hex64>`. Supplying only
one is an error. Driver files and every existing path component must be
non-reparse, and the bytes are rehashed before any invocation. A PowerShell driver is
invoked through `pwsh -NoProfile -NonInteractive -File`; any other file is
executed directly. Every invocation receives:

```text
--protocol codex-agent-mesh-process-fixture-v1 --action <action> --input <json-file>
```

It must exit zero and emit exactly one bounded JSON object with:

```json
{
  "protocol": "codex-agent-mesh-process-fixture-v1",
  "action": "...",
  "status": "PASS",
  "fixture_invocation_token": "..."
}
```

`preflight` must additionally report `platform: "windows-x64"`,
`interactive_user: true`, `filesystem: "NTFS"`, exact install/task/runtime
digests and paths, `provider_scheduler: false`, a test-only deterministic seed
source, an absolute bridge launch command, and the capabilities requested by
the calling script. The preflight binds SHA-256 for the bridge launcher and
retained runtime. Every response echoes the fresh per-invocation token;
prepare/snapshot/cleanup also echo `run_token`, while reconnect cases and
cursor replay echo `case_token`. Reconnect case output also attests that Rust and TypeScript
validated the exact canonical command and every returned wire response; the
consumer rejects evidence missing either decoder result.

Singleton actions are `singleton.prepare`, `singleton.snapshot`, and
`singleton.cleanup`. Preparation must stop or start only the exact owned task.
Snapshot evidence includes the per-round `RunEx` delta, the sole daemon PID and
generation, Task Scheduler instance count, daemon-lock owner PID, named-pipe
owner PID, exact process image/digest evidence, and one connect/handshake
observation for every supplied bridge PID.
The observed bridge PID set must be unique and exactly equal to the launched
set. Cold rounds require a `RunEx` delta of one; warm rounds require zero. Since
preflight establishes an exact ACTIVE fixture, every bridge must return a
successful `list_agents_result`; setup diagnostics are not accepted as race
success.

Reconnect actions are `reconnect.case`, `reconnect.cursor-result-replay`, and
`reconnect.cleanup`. Each case supplies one of the four M3 mutations, one of the
bridge/helper/daemon kill targets, and one request/response boundary. Evidence
must include the exact base64 canonical request/replay bytes, a one-byte conflict
variant, unchanged command key, one durable-effect locator/count, exact killed
PID/image/boundary, replay/conflict outcomes, and post-restart task state.
Cursor/result replay must return byte-identical persisted events and terminal
tuple evidence before and after restart.

The fixture may seed storage/router state only through a separately built
test-only fixture API. It must report that fact. It must never claim provider
execution: Milestone 3 has no provider scheduler. Drivers must identify and stop
processes by exact PID/owned task identity, must not kill by image name, and must
not delete resources they did not create.

Temporary fixture cleanup is independently bounded to 4,096 descendants and 32
levels. It walks without following descendants, rejects any reparse point, and
then removes only the validated files and empty directories. The direct temp
parent, workspace ancestry, create-new flushed ownership marker, bounded strict
UTF-8 marker content, and every descendant must revalidate before deletion.
