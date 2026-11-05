# Fleet manifest

`acidbase fleet` keeps a manifest of the repositories that consume acidbase:
where each one lives, on which host, and which CLI it exposes. Rollout loops
read it instead of carrying their own lists, repo-creation scripts append to
it, and a census compares it with the disk so drift shows up before a
fleet-wide claim does.

The manifest describes a portfolio, so it belongs to the private side of a
dual-published metarepo (`config/fleet.toml`, not on the public allowlist).
The command that maintains it is public.

## Schema

```toml
[census]
# Consumers under the roots that are deliberately not members.
ignore = []

# Directories whose immediate children `fleet census` scans, per host.
[census.roots]
windows = ['C:\repos']
wsl = ["~"]

# How each host reaches the other's paths.
[hosts.windows]
wsl_home = '\\wsl.localhost\Ubuntu\home\<user>'

[hosts.wsl]
windows_mount = "/mnt"

[[repo]]
name = "example"                 # directory name by default
host = "windows"                 # "windows" or "wsl" (or another sys.platform)
path = 'C:\repos\example'        # as its own host spells it; WSL uses "~/..."
cli = "example"                  # must be in [project.scripts]
mypy = "src"                     # optional type-check target for rollout loops
note = "free text"               # optional; shown in the Markdown inventory
```

`[[repo]]` tables stay in abecedarian order of `name`
(`acidbase.collation.abc_key`: case-interleaved, `A a B b ...`). `fleet add`
inserts at the right place through tomlkit, so comments and hand formatting
survive; hand edits are fine as long as the order holds.

## Commands

- `acidbase fleet add [REPO] [--cli NAME] [--mypy TARGET] [--note TEXT] [--dry-run]`
  registers a repository (the current directory by default). It refuses
  projects without an acidbase dependency (comments do not count) and the
  metarepo itself, infers the CLI from `[project.scripts]` (ignoring a bare
  `push` alias), and stores the path the way its host spells it. A repository
  on a Windows drive registered from WSL (`/mnt/c/...`) is stored as a
  Windows path, and vice versa for the WSL home seen from Windows. Registering
  the same repository again is a no-op, so scripts can call it
  unconditionally.
- `acidbase fleet remove NAME [--host HOST]` drops a registration, e.g.
  before re-adding a repository that moved.
- `acidbase fleet census [--local-only]` checks every registration and scans
  the roots. States: `OK`, `MISSING`, `NOT-A-CONSUMER`, `CLI-MISMATCH`,
  `UNREADABLE`, `UNREGISTERED` (with the `fleet add` command that fixes it),
  and `UNREACHABLE` for the other host when no route is configured or it is
  not running. Exit code 1 means drift; `UNREACHABLE` is informational.
- `acidbase fleet list [--host HOST] [--format table|json|tsv|markdown]`
  prints the manifest. JSON and TSV add each repository's path on the
  running host (`local_path`; `-` in TSV when unreachable), so loops need no
  path translation of their own. TSV columns: name, host, path, local path,
  cli, mypy (`-` when empty).

Every subcommand takes `--fleet-file`; without it the manifest is
`$ACIDBASE_FLEET_FILE`, then `config/fleet.toml` found by walking up from the
current directory.

## Using it in loops

PowerShell, building the `path -> "cli|mypy"` map rollout loops expect:

```powershell
$FLEET = [ordered]@{}
uv run acidbase fleet list --host windows --format json | ConvertFrom-Json |
  ForEach-Object { $FLEET[$_.local_path] = "$($_.cli)|$(if ($_.mypy) { $_.mypy } else { '-' })" }
```

bash:

```bash
while IFS=$'\t' read -r name host path local_path cli mypy; do
  echo "$name -> $cli at $local_path"
done < <(uv run acidbase fleet list --host wsl --format tsv)
```

One `acidbase hooks` call can cover every reachable member:

```powershell
uv run acidbase hooks @(uv run acidbase fleet list --format json | ConvertFrom-Json |
  Where-Object local_path | ForEach-Object local_path)
```

## Repo creation

A repo-creation script should register the new repository as its last step,
after the first commit and the push, and treat a failure as a warning:

```bash
uv run acidbase fleet add . --fleet-file /path/to/metarepo/config/fleet.toml \
  || echo "register later: uv run acidbase fleet add <repo>"
```
