# acidbase / templates
Canonical CLI / CI / lint / secret-scan templates for Python repositories.
Treat the files in this directory as the single source of truth. Use
`acidbase scaffold` to plan and apply them so existing local files are never
overwritten accidentally.
## Files
- `.github/workflows/lint.yml` — GitHub Actions: `ruff check`, `ruff format --check`, gitleaks CLI scan.
- `.gitleaks.toml` — secret-scan rules config (extends the upstream default ruleset).
- `.pre-commit-config.yaml` — pre-commit hooks: `uv-lock`, ruff (check + autofix + format), gitleaks.
- `cli.py` — the CLI skeleton for a new repo: copy to `src/<pkg>/cli.py` and point
  `[project.scripts]` at `<pkg>.cli:main`. It imports the command group from
  `acidbase.cli_utils`, the `bump` command from `acidbase.versioning`, and the
  `push` command from `acidbase.push` rather than restating them, so the repo
  inherits fixes instead of forking them.
- `pyproject.lint.toml` — the `[tool.ruff]` block to append into each repo's `pyproject.toml`.
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
## Bumping tool versions

Project versions use the shared CLI command documented in
`docs/guidelines/versioning.md`, for example `uv run <project> bump patch`.

- `pre-commit autoupdate` inside any repo updates the `rev:` pins in `.pre-commit-config.yaml`.
- The pinned `GITLEAKS_VERSION` in `lint.yml` and the gitleaks `rev:` in `.pre-commit-config.yaml`
  should be bumped together; pick a real release tag from https://github.com/gitleaks/gitleaks/releases.
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
