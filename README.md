# acidbase

> Safe scaffolding, shared workflow, dependency-patch, and CI-baseline tooling for Python repositories,
> packaged as a single ``acidbase`` CLI plus a set of canonical template files.

## What this repository provides

**1. The `acidbase` CLI** — a small Click-based command group that wraps several
project and owner-wide GitHub workflows so they behave identically on Windows
(PowerShell 7+) and on Linux/WSL (bash):

- `acidbase alerts` — list Dependabot alerts for one repo or every repo of an
  owner, with severity / state / package filters and ready-to-paste
  `acidbase patch` suggestions per affected package.
- `acidbase bump` — advance a uv project's own static version by one or more
  uv bump kinds, or set an explicit PEP 440 version. It updates `pyproject.toml`
  and `uv.lock` without synchronizing the environment; see
  [`docs/guidelines/versioning.md`](./docs/guidelines/versioning.md).
- `acidbase dismiss-alert` — dismiss selected alerts with a recorded reason;
  `acidbase reopen-alert` can reverse the decision.
- `acidbase enable-alerts` / `acidbase enable-fixes` — idempotently toggle the
  per-repo Dependabot settings (vulnerability alerts and automated security
  fix PRs respectively). Each helper checks the current state first so it is
  safe to chain from repo-creation scaffolders.
- `acidbase patch` — scan every non-archived repo of a GitHub owner for a
  vulnerable dependency, bump it via `uv add --no-sync <dep>>=<new>` (the
  repo's virtual environment is never touched), publish the fix
  (direct push or PR), and verify Dependabot alerts close. Opt in with
  `--sync-env` to eagerly `uv sync --frozen` repos whose venv is native to
  the executing side. Profiles per repo are configured in
  `config/security_patch.toml`.
- `acidbase push` — pre-commit-aware `git add . && git commit && git push`
  helper with automatic retry when hooks modify staged files. Importable from
  consumer repos via `from acidbase.push import push_command`. Supports a
  dual-publish flow (private remote + public mirror) with allowlist / gitleaks
  pre-flight gates and an interactive destination Q&A; see
  [`docs/guidelines/dual_push.md`](./docs/guidelines/dual_push.md).
- `acidbase reopen-alert` — reopen selected alerts that were previously
  dismissed.
- `acidbase scaffold` — show a read-only adoption plan for an initialized
  Python repository, then add missing baseline files with `--apply`. Existing
  divergent CLI, CI, hook, lint, and secret-scan configuration is preserved;
  `--wire-cli` explicitly couples a new CLI to its dependency, entry point,
  initializer, and package metadata;
  see [`docs/guidelines/scaffolding.md`](./docs/guidelines/scaffolding.md).

Metarepo-to-children propagation (lockfile pin upgrades, config sweeps,
per-repo verification, canonical `uv run <cli> push` close-out) is documented
as a repeatable private runbook in `docs/guidelines/metarepo_rollout.md`.

**2. Canonical CI / lint / secret-scan templates** under `templates/` — a single
source of truth for the GitHub Actions lint workflow, the pre-commit hook set
(uv-lock + ruff + gitleaks), the ruff configuration block, and the gitleaks
configuration:

- `templates/.github/workflows/lint.yml`
- `templates/.gitleaks.toml`
- `templates/.pre-commit-config.yaml`
- `templates/pyproject.lint.toml` (the `[tool.ruff]` block to append)

Downstream repositories adopt these files through `acidbase scaffold` so the
baseline stays consistent without overwriting local policy. See
`templates/README.md` for the rationale behind each choice (why ruff over
black+isort+flake8, why the gitleaks CLI
instead of `gitleaks/gitleaks-action@v2`).

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/jurdabos/acidbase.git
cd acidbase
uv sync
uv run acidbase --help
```

Or install directly from GitHub into another project:

```bash
uv add "acidbase @ git+https://github.com/jurdabos/acidbase.git"
```
## Usage at a glance
Full walkthroughs for the security patch flow (CLI reference, config schema,
strategies, verification, worked examples) live in
[`docs/guidelines/security_patching.md`](./docs/guidelines/security_patching.md).
Quick example:
```bash
# Triage owner-wide alerts and get suggested fix commands.
uv run acidbase alerts --owner <github-owner> --state open --severity high
# Apply a fix across every affected repo and verify the alerts close.
uv run acidbase patch \
    --owner <github-owner> \
    --dep GitPython \
    --new-version 3.1.50 \
    --cve CVE-2026-42215
```
## Development
```bash
uv sync                       # install runtime + dev deps
uv run pytest                 # run the test suite
uv run ruff check .           # lint
uv run ruff format --check .  # formatting check
```
Pre-commit hooks (uv-lock + ruff + gitleaks via the system MIT-licensed binary):
```bash
uv tool install pre-commit --with pre-commit-uv
pre-commit install
pre-commit run --all-files
```
## Repository structure
```
acidbase/
├── src/acidbase/             # Python package
│   ├── cli.py                # Click group and public command registration
│   ├── push.py               # Reusable Git commit-and-push command
│   ├── scaffold.py           # Plan-first baseline adoption
│   ├── versioning.py         # Reusable uv project-version command
│   ├── workflow.py           # Root/tool/subprocess mechanics for child CLIs
│   └── security/             # patch + alert helpers, profile resolver, publishers
├── templates/                # Canonical CI / lint / secret-scan baseline
├── docs/guidelines/          # Public docs (security patching workflow)
├── tests/                    # pytest suite (security/* covers the patch flow)
├── config/security_patch.toml # Example profile config (placeholders only)
├── scripts/list_symbols.py   # Repo-wide function/class inventory utility
├── pyproject.toml            # uv-native project metadata + ruff config
└── PUBLIC_ALLOWLIST.txt      # CI guard: paths allowed to live in this repo
```
## Contributing
See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
The CI lint baseline (`.github/workflows/lint.yml`) and the public allowlist
guard (`.github/workflows/public-allowlist.yml`) must stay green before merge.
## License
[MIT](./LICENSE) — Copyright (c) 2024 Blai (Balázs Torda).
