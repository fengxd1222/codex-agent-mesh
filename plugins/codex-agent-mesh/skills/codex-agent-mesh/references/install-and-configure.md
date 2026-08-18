# Install and configure Codex Agent Mesh

Use this file when the user asks to install, set up, configure, or rebind
the plugin. Execute the steps. Do not edit `AGENTS.md` to change routing.

## Preconditions

- Windows x64.
- PowerShell 7 (`pwsh`).
- Work from a clone of this repository. Detect the repo root as the
  directory that contains `scripts/package-plugin.ps1`. Never copy a
  machine-specific path from another computer.
- Node.js 22+ and Rust 1.96+ with the MSVC toolchain and Windows SDK if you
  must rebuild. Fresh clones do not include `release/`: run `npm ci`, then
  package before installing.
- Never purge unless the user explicitly accepts losing the task database.
- Never commit credentials, runtime data, logs, provider state, or the local
  marketplace manifest created below.

## 1. Discover the current install

```powershell
$repoRoot = (Get-Location).Path
$cacheExe = "$env:USERPROFILE\.codex\plugins\cache\codex-agent-mesh-local\codex-agent-mesh\0.1.0\bin\windows-x64\mesh-daemon.exe"
$releaseExe = Join-Path $repoRoot "release\codex-agent-mesh\bin\windows-x64\mesh-daemon.exe"
$exe = $null
if (Test-Path -LiteralPath $cacheExe) {
  $exe = $cacheExe
}
elseif (Test-Path -LiteralPath $releaseExe) {
  $exe = $releaseExe
}
if ($null -eq $exe) {
  Write-Output "ABSENT (no cached or release daemon)"
}
else {
  & $exe status --install-slot stable
}
```

- `ABSENT` → continue to package (step 2), then setup (step 3).
- `ACTIVE` and `runtime_integrity=EXACT` → skip rebuild unless the user
  asked for an upgrade.
- `SETUP_DRIFTED` → cache helper SHA ≠ retained runtime. Do not hand-edit
  cache files to "fix" it. Rebuild, then ask before purge.

## 2. Package (from this repo)

```powershell
$repoRoot = (Get-Location).Path
npm ci
pwsh -NoProfile -File scripts/package-plugin.ps1
$exe = if (Test-Path -LiteralPath $cacheExe) { $cacheExe } else { $releaseExe }
```

That writes a development-unsigned bundle to `release/codex-agent-mesh`.
`release/` is ignored and is absent from a fresh clone until this step runs.
Copy the whole bundle over the Codex cache plugin root:

`%USERPROFILE%\.codex\plugins\cache\codex-agent-mesh-local\codex-agent-mesh\0.1.0\`

The cache `mesh-daemon.exe` SHA must equal the retained runtime SHA after
setup. If they differ on an existing ACTIVE install, setup will drift.

## 3. Setup and start

Use the cache exe (or `release\codex-agent-mesh\bin\windows-x64\mesh-daemon.exe`
as an external controller):

```powershell
& $exe setup --install-slot stable
& $exe start --install-slot stable
& $exe status --install-slot stable
```

Upgrade that needs a new runtime SHA: ask the user, then

```powershell
& $releaseExe remove --purge-data --install-slot stable
```

from an exe **outside** the install tree, copy the new bundle into cache,
then `setup` and `start`. Purge deletes the task database and install id.

No marketplace manifest is committed because repository-level local-platform
dot directories are intentionally excluded from published source. After cloning
and packaging, create a local marketplace manifest that points at the generated
bundle, then register the repository root and install the plugin:

```powershell
$repoRoot = (Get-Location).Path
Set-Location $repoRoot
$manifestDir = Join-Path $repoRoot ".agents\plugins"
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
@'
{
  "name": "codex-agent-mesh-local",
  "interface": {
    "displayName": "Codex Agent Mesh (local development)"
  },
  "plugins": [
    {
      "name": "codex-agent-mesh",
      "source": {
        "source": "local",
        "path": "./release/codex-agent-mesh"
      },
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL"
      },
      "category": "Productivity"
    }
  ]
}
'@ | Set-Content -Encoding utf8 (Join-Path $manifestDir "marketplace.json")

codex plugin marketplace add $repoRoot
codex plugin add codex-agent-mesh@codex-agent-mesh-local
```

Ask the user to fully restart Codex after the first install or a skill
change.

Role defaults ship in source as
`crates/mesh-daemon/src/settings/default-config.toml`. First `setup`
copies them into the new machine's LocalAppData install. Do not commit
or copy `%LOCALAPPDATA%\codex-agent-mesh\...`.

## 4. Configure roles (settings only)

Settings file (after setup):

`%LOCALAPPDATA%\codex-agent-mesh\installs\<install_id>\data\config.toml`

Or the dashboard settings form. Bindings are:

| Token                             | Kind         | What happens                                     |
| --------------------------------- | ------------ | ------------------------------------------------ |
| `claude` / `grok` / `kimi` / `pi` | local CLI    | `delegate_task` if `list_agents` says `ENABLED`  |
| `luna`                            | Codex-native | spawn a Codex subagent with `native_models.luna` |

`pi` is bindable; it has no admitted spawn surface yet.

Default:

```toml
[settings.role_bindings]
implementation = "claude"
research = "grok"
review = "luna"
freelancer = "kimi"

[settings.native_models]
luna = "gpt-5.6-luna"
```

Implementation → Luna Max:

```toml
[settings.role_bindings]
implementation = "luna"
```

Implementation → Grok:

```toml
[settings.role_bindings]
implementation = "grok"

[settings.enabled_adapters]
grok = true
```

Implementation → Pi (config only until spawn exists):

```toml
[settings.role_bindings]
implementation = "pi"

[settings.enabled_adapters]
pi = true

[settings.executable_paths]
pi = 'C:\Users\<user>\.pi\bin\pi.exe'
```

First-run setup seeds detected Claude/Grok/Kimi paths when those exes
exist. Enable any extra CLI the user named.

## 5. Verify

1. `status` → `ACTIVE`, daemon `RUNNING`, `runtime_integrity=EXACT`.
2. `list_agents` → `role_bindings` and `native_models` match the file;
   CLI rows the user enabled are `ENABLED`.
3. Do not treat a missing `luna` row in `agents` as failure.

## Forbidden

- Do not edit `AGENTS.md` to change who implements, researches, or reviews.
- Do not invent `luna.exe` or a mesh CLI for a coordinator-native binding.
- Do not purge without an explicit user yes.
- Do not bypass setup by pointing MCP at the cache exe as an RPC peer.
