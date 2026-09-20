# acidbase / templates
Canonical CLI / CI / lint / secret-scan templates for Python repositories.
Treat the files in this directory as the single source of truth. Use
`acidbase scaffold` to plan and apply them so existing local files are never
overwritten accidentally.
## Files
- `.github/workflows/lint.yml` — GitHub Actions: `ruff check`, `ruff format --check`, gitleaks CLI scan.
- `.gitleaks.toml` — secret-scan rules config (extends the upstream default ruleset).
- `.pre-commit-config.yaml` — pre-commit hooks: `uv-lock`, ruff (check + autofix + format), gitleaks.
  Every hook is `repo: local` / `language: system`, so the file pins no `rev:` of its own
  (see "Where tool versions live" below).
- `cli.py` — the CLI skeleton for a new repo: copy to `src/<pkg>/cli.py` and point
  `[project.scripts]` at `<pkg>.cli:main`. It imports the command group from
  `acidbase.cli_utils`, the `bump` command from `acidbase.versioning`, and the
  `push` command from `acidbase.push` rather than restating them, so the repo
  inherits fixes instead of forking them.
- `pyproject.lint.toml` — the `[tool.ruff]` block to append into each repo's `pyproject.toml`.
- `superseded.txt` — normalized digests of every previous version of the files above. A
  child file matching one of them is reported as `stale` by `acidbase scaffold` and replaced
  under `--refresh-baseline`; append the old digest whenever you change a template (a test
  walks git history and fails otherwise).
## Why the CLI template imports rather than copies
The scaffolder previously stamped a ~200-line self-contained `push`
implementation into every new repo — the code that `acidbase.push` was later
extracted from. Repos created before the extraction kept their copy and drifted:
`gdgap` still carried the fork in 2026 and was missing the clean-but-ahead push
guard, dual-publish support, and the Unicode stream fix. A template that imports
cannot drift, and `new_repo.sh` already runs
`uv add 'acidbase @ git+https://github.com/jurdabos/acidbase.git'` for every
non-acidbase project, so the dependency is always present.
## How to apply

Initialize the repository and make its acidbase dependency and
`[project.scripts]` choices, then inspect the read-only plan:

```bash
uv run acidbase scaffold .
```

Apply the plan with `uv run acidbase scaffold . --apply`. Missing files are
created, an absent ruff table is appended, matching files are recognized, and
every divergent local file is preserved. This same operation handles both a
newly initialized repository and adoption of an established one. See
`docs/guidelines/scaffolding.md` for the ownership contract and report states.

When a project has no CLI yet, add `--wire-cli` to the plan and apply commands
to couple `cli.py` with its acidbase dependency, entry point, initializer, and
Hatch package metadata. Then run `uv lock` and `uv sync --frozen`.
## Where tool versions live

Project versions use the shared CLI command documented in
`docs/guidelines/versioning.md`, for example `uv run <project> bump patch`.

Tool versions each have exactly one owner; `.pre-commit-config.yaml` owns none:

| Tool | Single source of truth | Bump with |
| --- | --- | --- |
| ruff | `uv.lock` (`ruff` in `[dependency-groups].dev`) | `uv lock --upgrade-package ruff` |
| uv | the `uv` on PATH | your package manager / `uv self update` |
| gitleaks | `GITLEAKS_VERSION` in `lint.yml` (CI); the system binary locally | edit `lint.yml`; reinstall the binary |

The ruff hook runs `uv run --frozen python -m ruff`, which is the same binary
CI runs via `uv run ruff`, so hook and CI cannot disagree on formatting or
rules. `python -m ruff` rather than bare `ruff` makes a repo that forgot to add
ruff to its dev group fail loudly instead of falling back to whatever ruff is
on PATH.

Do **not** run `pre-commit autoupdate`: there is nothing left for it to update,
and on the historical remote-hook layout it moved the hook to *latest* rather
than to the *locked* version, creating the opposite mismatch.

### Why not `astral-sh/ruff-pre-commit`

The template originally used the upstream remote hook with its own `rev:`. That
is a second, independently pinned copy of ruff next to the one in `uv.lock`,
and the two drift: by 2026-09 ten children sat on hook `v0.8.0` while locking
ruff 0.12-0.16, so the hook formatted to the pre-0.9 style and CI (which uses
the locked ruff) rejected the result. `acidbase scaffold` never updates a file
it has already placed, so the stale pin outlived every later `uv lock`.

`uv run acidbase hooks [TARGET...|--all]` reports each repo as `LOCAL`,
`ALIGNED`, `DRIFT`, `NO-RUFF-HOOK`, etc., lists any remaining remote `rev:`
pins, and exits non-zero on `DRIFT`. Use it in a census before claiming a
rollout is complete.
## Why ruff
Ruff is a single tool that subsumes black, isort, and flake8 — same checks, ~100× faster,
one config block, one CI step. For frozen legacy repos still on black+isort+flake8, keep
the existing toolchain rather than churn the diff; for everything else, prefer ruff.
## Why the gitleaks CLI rather than `gitleaks/gitleaks-action@v2`
The action is license-gated: it calls the GitHub REST API unauthenticated to determine
whether the repo owner is a User or an Organization, and that lookup frequently fails on
shared-runner IPs (60 req/h limit), forcing the action into "license enforcement" mode
even on personal repos. The CLI itself is MIT and free for all use cases, so we install
the pinned upstream binary directly in CI and pair it with a `repo: local` pre-commit hook
that calls the same binary on developer machines.
