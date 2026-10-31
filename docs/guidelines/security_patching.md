# Cross-platform security patching

`acidbase patch` is a cross-platform driver for owner-wide dependency security
patching. It runs the same flow on Windows pwsh and Ubuntu/WSL bash: finds the
owner's repositories using a vulnerable dependency at-or-below a version
threshold, applies the bump (via `uv` for PyPI packages or `npm` for npm
packages), publishes the fix (push or PR), and verifies that Dependabot alerts
close. The string `pip` is GitHub's SBOM/Dependabot label for the PyPI
ecosystem; acidbase does not call `pip` directly, it drives `uv`.

## Prerequisites

- `git` and `gh` (authenticated via `gh auth login`) on PATH for every run.
- `uv` on PATH when `--ecosystem pip` (default).
- `npm` on PATH when `--ecosystem npm`.
- A clone of every affected repo on disk; `acidbase patch` skips repos that
  cannot be located locally and prints them as `MISSING`.
- Optional: a `[profiles.<RepoName>]` block in
  `acidbase/config/security_patch.toml` for any repo whose checkout path,
  publish flow, or `npm_dir` deviates from the defaults.

## Quick start

Recommended: read the alert table first, then copy the suggested invocation.

```bash
# 1. List Dependabot alerts owner-wide; the `Advisory` column contains the
#    exact CVE/GHSA you should pass to --cve, and a "Suggested patch commands"
#    block at the bottom prints the ready-to-paste --new-version per package.
uv run acidbase alerts --owner <github-owner>

# 2. Run the patch flow with --max-vulnerable omitted; the scan defaults to
#    "any version strictly below --new-version".
uv run acidbase patch \
    --owner <github-owner> \
    --dep GitPython \
    --new-version 3.1.50 \
    --cve CVE-2026-42215

# Or, when you really need a tighter window (e.g. backporting an old fix):
uv run acidbase patch \
    --owner <github-owner> \
    --dep GitPython \
    --max-vulnerable 3.1.49 \
    --new-version 3.1.50 \
    --cve CVE-2026-42215
```

The command prints a *Vulnerable repositories* table from the SBOM scan, then
walks each affected repo and ends with a *Summary* table including a
post-run `Alert` column (`FIXED` / `OPEN` / `-`).

## CLI reference

| Flag                     	| Default    	| Purpose                                                                                                                                                                                                                    	|
| -------------------------	| -----------	| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
| `--owner`                	| required   	| GitHub org/user owning the repos to scan                                                                                                                                                                                   	|
| `--dep`                  	| required   	| Dependency name (case-insensitive)                                                                                                                                                                                         	|
| `--max-vulnerable`       	| optional   	| Inclusive upper bound (PEP 440). When omitted, the scan matches any version strictly below `--new-version`                                                                                                                 	|
| `--new-version`          	| required   	| Target version: `uv add --no-sync <dep>>=<new>`                                                                                                                                                                            	|
| `--cve`                  	| required   	| Advisory ID written into the commit message; accepts either CVE or GHSA, copied from the `Advisory` column in `acidbase alerts`                                                                                            	|
| `--config`               	| auto-detect	| Path to a `security_patch.toml` override                                                                                                                                                                                   	|
| `--strategy`             	| `push`     	| `push` (commit + push to default branch) or `pr` (open a PR)                                                                                                                                                               	|
| `--dry-run`              	| off        	| Do everything but skip uv/git/gh side effects                                                                                                                                                                              	|
| `--skip-verify`          	| off        	| Bypass the Dependabot polling step                                                                                                                                                                                         	|
| `--sync-env`             	| off        	| pip only: after each successful bump, run `uv sync --frozen` in that repo so its local venv gets the fix immediately; auto-skipped when the venv is not native to the executing side                                       	|
| `--verify-max-wait-sec`  	| 180        	| Total budget for verification polling                                                                                                                                                                                      	|
| `--verify-poll-every-sec`	| 15         	| Interval between verification polls                                                                                                                                                                                        	|
| `--ecosystem`            	| `pip`      	| Which SBOM/Dependabot ecosystem to scan and patch. `pip` (default) targets PyPI entries and drives `uv`; `npm` targets npm entries and drives `npm install` with a `package.json` `overrides` fallback for transitive pins.	|

## Config file

The committed default lives at
`acidbase/config/security_patch.toml`. Resolution order when `--config`
is not passed:

1. `$ACIDBASE_SECURITY_CONFIG` env var, if it points to an existing file
2. The first `config/security_patch.toml` walking up from the current cwd

A minimal example (replace placeholders with your real paths):

```toml
[defaults]
# Roots are tried in order; the first one whose `<root>/<repo>` exists wins.
roots = [
    "C:/path/to/your/repos",
    "//wsl.localhost/<distro>/home/<user>",
    "/home/<user>",
]
# Repos always skipped during scans (empty mirrors, study-only forks, archived).
skip = ["study-fork", "archived-repo"]
# Default push command. `{branch}` and `{repo}` are filled in at run time.
push_command = ["git", "push", "origin", "{branch}"]

# Per-repo override: a repo checked out under two different casings.
[profiles.SomeRepo]
locals = ["somerepo", "SomeRepo"]

# Per-repo override: a repo with a custom publish wrapper and non-standard root.
[profiles.custom-app]
paths = [
    "D:/projects/custom-app",
    "//wsl.localhost/<distro>/home/<user>/custom-app",
]
push_command = ["uv", "run", "custom-app", "push"]
```

### Path resolution

For a repo `<Repo>` the resolver tries, in order:

1. Per-repo `paths = [...]` — first existing wins
2. Per-repo `path = "..."` — single absolute path
3. `defaults.roots` joined with per-repo `locals` (or `local`, or the repo
   name verbatim) — first existing wins

Anything still unresolved is reported as `MISSING` in the summary; nothing
fails the batch.

### Push command templating

Both `defaults.push_command` and per-repo `push_command` are argv lists. The
tokens `{branch}` and `{repo}` are filled at runtime. Any other placeholder
will raise loudly so a typo is impossible to ship silently.

Examples:

- `["git", "push", "origin", "{branch}"]` — vanilla, default
- `["uv", "run", "{repo}", "push"]` — wrapper CLI per repo
- `["make", "release"]` — bespoke makefile target

## Strategies

- **`push`** (default): commits land on the default branch and the resolved
  `push_command` runs. Mirrors the runbook exactly.
- **`pr`**: a feature branch `security/<dep>-<version>` is created from the
  freshly-pulled default branch, the bump is committed there, the branch is
  pushed, and `gh pr create` opens a PR. Auto-merge with squash is enabled
  best-effort via `gh pr merge --auto --squash`; failure to enable auto-merge
  does not fail the row (annotated in the `Note` column instead).

## Virtual environments are never synced by default

The pip flow moves `pyproject.toml`, `uv.lock`, and any verifiable uv-export
`requirements*.txt` — nothing else. The bump runs `uv add --no-sync`, so the
target repo's `.venv` is never synced, created, or replaced. This matters for
mixed-platform checkouts: a syncing `uv add` from the "wrong" side (Windows
uv reaching a `\\wsl.localhost\` checkout when the WSL routing in
`shell.run` cannot apply, or WSL-side acidbase against an `/mnt/c` repo)
treats the foreign-platform venv as invalid and rebuilds it — which is how a
Linux `.venv` got gutted over the 9P share (`lib/` deleted, then a fatal
error on the dangling `lib64` symlink) during the cryptography 50.0.0 run.
After pulling a security bump, refresh each repo's environment on its native
side with `uv sync` when you next work there.

Opt in per run with `--sync-env` to refresh environments eagerly: after each
`DONE` bump the flow additionally runs `uv sync --frozen` (installing exactly
the just-committed lock, never rewriting it). The sync keeps the same safety
envelope by running only when the venv is native to the uv performing it:

- `.venv` absent — sync; the executing side creates a fresh native env.
- POSIX `bin/` layout + WSL-routed repo or POSIX host — sync (distro-native uv).
- Windows `Scripts/` layout + Windows host — sync.
- Foreign or unrecognisable layout — skipped with `env sync skipped: ...` in
  the Note; run `uv sync` on the repo's native side instead.

A failed sync never fails the row (the security commit already landed): the
Note gains `env sync failed: <tail>`, and a success gains `synced env`. npm
runs ignore the flag because `npm install` already updates `node_modules`.

## Verification

Once all bumps are pushed/PR'd, the verifier polls
`/repos/{owner}/{repo}/dependabot/alerts` per repo. A repo is marked `FIXED`
when zero open alerts remain for the package. The poll loop sleeps
`verify-poll-every-sec` between rounds and gives up after
`verify-max-wait-sec`, marking the remainder as `OPEN`. An `OPEN` row almost
always means the dep is pulled in transitively; bump the *parent* and rerun.

## Worked example: GitPython CVE-2026-42215

```bash
uv run acidbase patch \
    --owner <github-owner> \
    --dep GitPython \
    --max-vulnerable 3.1.49 \
    --new-version 3.1.50 \
    --cve CVE-2026-42215 \
    --strategy push
```

Expected final table:

```text
Repo        Path                            Status Note                 Alert
repo-a      C:/projects/repo-a              DONE   bumped to >=3.1.50   FIXED
repo-b      C:/projects/repo-b              DONE   bumped to >=3.1.50   FIXED
repo-c      C:/projects/repo-c              DONE   bumped to >=3.1.50   FIXED
repo-d      C:/projects/repo-d              DONE   bumped to >=3.1.50   OPEN
```

A row ending in `OPEN` (e.g. `repo-d` here) means the bump did not move
the *resolved* version because the dep is transitive. Force-resolve and
rerun:

```bash
uv lock --upgrade-package gitpython
uv run acidbase patch ...   # rerun until everyone is FIXED
```

## Multiple requirements files (subdirectory exports)

Some repos ship more than one requirements file derived from the same uv
project — for example a service subtree that needs a flat, hash-free pin set
for its Docker build:

```text
vlc/
  pyproject.toml
  uv.lock
  requirements.txt                 # root export (uv export --frozen ...)
  producer/requirements.txt        # secondary export for the producer image
```

The secondary file is stamped with the command that produced it:

```text
# This file was autogenerated by uv via the following command:
#    uv export --no-hashes --no-dev -o producer/requirements.txt
```

Dependabot scans every manifest, so it can flag `producer/requirements.txt`
(e.g. `authlib==1.6.5`) even when the root project is already patched
(`authlib>=1.6.12`, lock resolves `1.7.2`). The patch flow handles this:

1. If the root `uv.lock` already satisfies `--new-version`, `acidbase` skips
   `uv add` (so an already-patched root does not trip a spurious
   `UVADDFAIL`) and proceeds straight to refreshing exports.
2. Every tracked `requirements*.txt` that still pins the target dep below the
   threshold is inspected. A **uv-export artifact** (identified by the
   autogenerated header) is regenerated by re-running *its own recorded*
   `uv export … -o <that file>` command — which re-pins all of its lines
   consistently from the current lock, not just the one dependency. As a
   safety guard, acidbase only executes a header command that is verifiably
   `uv export` writing back to that same file.
3. A genuinely **hand-maintained** requirements file (no uv-export header)
   is *not* auto-edited; it is surfaced in the `Note` column as needing a
   manual edit, so a hand-pinned file is never silently rewritten.
4. Verification reads the exact manifest the Dependabot alert was filed
   against (e.g. `producer/requirements.txt`), so a fix in a subdirectory
   export is confirmed on that file rather than masked by an already-patched
   root manifest.

The `Note` column makes the action explicit, e.g.
`root already >= 1.6.9; regenerated producer/requirements.txt`.

## npm ecosystem

When a Dependabot alert is for an npm package (label `npm:` in the alert
table, manifest `package-lock.json`), pass `--ecosystem npm` to the same
`acidbase patch` invocation. The scan, patch, publish, and verification
stages all switch to npm-native tooling without affecting any pip flow.

What the npm backend does, per repo:

1. Discovers vulnerable repos via the **Dependabot alerts endpoint**
   (`/repos/{owner}/{repo}/dependabot/alerts`), not the SBOM. GitHub's
   SBOM uses bare names for npm entries (the ecosystem only appears in
   `externalRefs[].referenceLocator` as a PURL such as
   `pkg:npm/yaml@2.8.1`) and is empirically flaky for repos with large
   npm trees. Open alerts are the source-of-truth; `--max-vulnerable`
   and `strict_below` are *not* applied because the alert already
   encodes the vulnerable range.
2. Resolves the npm project directory from `profiles.<Repo>.npm_dir` in
   `security_patch.toml`, otherwise auto-detects the unique
   `package-lock.json` outside `node_modules/`.
3. Refuses to guess on unsupported lockfiles (`pnpm-lock.yaml`,
   `yarn.lock`, `bun.lockb`) and reports `UNSUPPORTED_LOCKFILE`.
4. Reads the current resolved version from `package-lock.json`. If it is
   already `>= --new-version`, the row is `NOOP` and nothing else runs.
5. Otherwise runs `npm install <dep>@^<new-version>`. If the lockfile
   moves to `>= --new-version`, the row commits the `package.json` and
   `package-lock.json` delta and is reported as `DONE`.
6. If `npm install` does *not* move the resolved version (the usual
   transitive case), acidbase inserts `overrides[<dep>] = "^<new>"` into
   `package.json` and re-runs `npm install`. If the lockfile then
   resolves to `>= --new-version`, the row is `DONE`; otherwise it is
   `NPMADDFAIL` with a note describing the resolved version.
7. The verifier inspects `<npm_dir>/package-lock.json` on
   `origin/<branch>` after publish and reports `FIXED` / `OPEN`.

Example (bracket's `npm:yaml` advisory, frontend lockfile):

```bash
uv run acidbase patch \
    --owner <github-owner> \
    --repo bracket \
    --dep yaml \
    --new-version 2.8.3 \
    --cve CVE-2026-33532 \
    --ecosystem npm
```

With `bracket`'s lockfile under `frontend/`, add an `npm_dir` override to
the config so the verifier knows where to look:

```toml
[profiles.bracket]
npm_dir = "frontend"
```

## Companion command: `acidbase alerts`

While `acidbase patch` performs end-to-end remediation, day-to-day situational
awareness is best served by the lighter-weight `acidbase alerts` subcommand.
It works the same on Windows pwsh and Ubuntu/WSL bash.

All Dependabot alerts in a single repository:

```bash
uv run acidbase alerts --owner <github-owner> --repo <repo>
```

All alerts across every non-archived, non-empty repo of the owner (skip list
from `config/security_patch.toml` is honoured):

```bash
uv run acidbase alerts --owner <github-owner>
```

Filter by one or more packages (case-insensitive, repeatable):

```bash
uv run acidbase alerts --owner <github-owner> --dep GitPython
uv run acidbase alerts --owner <github-owner> --dep GitPython --dep requests
```

State and severity filters:

```bash
uv run acidbase alerts --owner <github-owner> --state all
uv run acidbase alerts --owner <github-owner> --severity critical --state open
```

### Output columns

`Repo`, `#` (alert number), `State`, `Severity` (color-coded), `Package`
(prefixed with the ecosystem when known, e.g. `pip:GitPython`),
`Vulnerable` (the advisory's vulnerable version range), `Patched` (first
patched version), `Advisory` (CVE preferred, GHSA fallback), `Manifest`
(lockfile/manifest the alert was found in). A dim summary line at the
bottom restates the active filters and the alert count, followed by a
`Suggested patch commands` block with one ready-to-paste
`uv run acidbase patch ...` invocation per affected package (using the
highest patched version seen for that package and its first known
advisory ID).

### Typical follow-up

```bash
# 1. Triage owner-wide:
uv run acidbase alerts --owner <github-owner> --state open --severity high
# 2. Drill into one repo:
uv run acidbase alerts --owner <github-owner> --repo <repo> --state all
# 3. Patch every affected repo for that one package:
uv run acidbase alerts --owner <github-owner> --dep <Pkg>   # confirm the scope
uv run acidbase patch  --owner <github-owner> --dep <Pkg> --max-vulnerable <V> \
                       --new-version <V+1> --cve <CVE>
```

## Troubleshooting

- **`Missing required tools on PATH`** — install `git`, `gh`, or `uv` and
  retry. The CLI bails before any side effects when a tool is missing.
- **Repo flagged `DIRTY`** — clean or stash local changes before rerunning.
  The tool refuses to commit on top of an existing diff to keep the security
  commit reviewable.
- **Repo flagged `NOTUV`** — only uv-native repos are patched automatically.
  Migrate the repo to uv first, then rerun.
- **Repo flagged `PUSHFAIL` only on certain repos** — the per-repo
  `push_command` likely needs auth or env vars the default `git push` does
  not. Inspect the `log` field on the result (or rerun with `--dry-run` and
  examine the planned argv).
