# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [Unreleased]

### Removed

- `main.py`: removed the stub `uv init` left behind, which only printed a greeting. `PUBLIC_ALLOWLIST.txt` and `WARP.md` follow.
- `assets/`: the logos, tagline, showcase and `acidvuca-brand.skill` moved to `cosmetics`, the new authority for design values. The folder never reached the public mirror, so repos depending on acidbase could not use it anyway.

### Added

- `docs/guidelines/house_rules.md`, `docs/guidelines/style_guide.md`: adds "Choose a Folder Before Creating a File" as the one home for this guidance, which moves out of the style guide and drops its `setup.py` example. The uv rule also records that `pip` rejects a default `uv export`.
- `docs/guidelines/house_rules.md`: adds "Default to uv for Python Projects", as a default rather than an absolute, because Astro images and some container builds need `requirements.txt` or `pip`. The rule records that `uv pip install` leaves no record and is removed by the next `uv sync`, and that transitive fixes belong in `override-dependencies`, not `uv add`.
- `docs/guidelines/house_rules.md`: adds "Run MLflow on Windows with One Worker". Any count above 1, the default of 4 included, can print `WinError 10022` tracebacks as uvicorn workers race on one shared socket. The rule records that the error is not fatal, that `--workers 2` does not avoid it, and that `MLFLOW_WORKERS=1` works without the flag.
- `src/acidbase/brand_literals.py`, `src/acidbase/hooks.py`, `tests/test_brand_literals.py`: `acidbase hooks` now warns about brand values pasted into source, without failing, because the rule is new. It reads them from the generated `src/acidbase/acidvuca_brand.py`, so the check holds no copy of its own, and it skips tests, docs, stamped files and a repo's `[tool.acidbase.brand] exempt` globs. `PUBLIC_ALLOWLIST.txt` publishes both modules and the test, because the public `hooks.py` imports them.
- `docs/guidelines/house_rules.md`, `docs/guidelines/style_guide.md`: adds "Take Design Values from Cosmetics", an authority map line and a design conventions section, because colours and fonts had spread across 12 repos with no single source.
- `docs/guidelines/email_alerts.md`, `docs/guidelines/house_rules.md`: correct "nowhere else" for the Alertmanager
  password. `b4p` archives the generated file too, then deletes its plain tar when the run ends, so the lasting copies are
  that file and restic's encrypted one.
- `docs/guidelines/email_alerts.md`: records `--web.external-url` for Alertmanager and Prometheus, because links in alert
  emails otherwise name the container's hostname, and that a real alert went through Gmail from vlc.
- `templates/.gitleaks.toml`, `.gitleaks.toml`: add the `sql-password-literal` rule. The upstream rules look for
  assignments, so they missed a live password committed in `ALTER ROLE ... PASSWORD`. The rule also covers MySQL's
  `IDENTIFIED BY`, and skips shell, Python and template variables and `REAL` placeholders. `templates/superseded.txt`
  records the version it replaces.
- `docs/guidelines/email_alerts.md`, `docs/guidelines/house_rules.md`: record Alertmanager as the one exception to keeping
  the Gmail app password out of plain files, with the wiring proven in vlc: a gitignored `600` file written from the
  keyring by a human, the container running as that file's owner, `smtp_require_tls: false` on port 465, and an outbound
  network.
- `docs/guidelines/house_rules.md`: adds "Keep TimescaleDB Bootstrap SQL Rerunnable". The rule also records that
  `IF NOT EXISTS` skips a changed definition, so it is no substitute for a migration, and how to run such scripts by
  hand.
- `docs/guidelines/house_rules.md`: adds "Prefer Singular Folder Names", for new folders only. Existing plural folders
  stay, and `tests/` keeps its name because a `test/` package shadows Python's standard library `test` package.
- `docs/guidelines/house_rules.md`: adds "Keep Temporary Files Out of Project Repos". Files from a transitory task belong
  outside the repo, because `push` stages everything, while deliberate derivatives stay beside their source. The rule
  also records that a relative pandoc `--extract-media` writes into the current folder, and when a script is worth
  keeping.
- `docs/guidelines/email_alerts.md`, `docs/guidelines/house_rules.md`: record the email alert setup proven in url-rag,
  so other projects can reuse it: the sender, the SMTP settings, where secrets live, the Airflow wiring and the pitfalls.
- `docs/guidelines/house_rules.md`: adds "Isolate Item Failures, Then Report Them". One bad item must not stop a batch,
  but a run must also separate bugs from bad input, report counts, fail on an outage, and never record a failed item as
  done. Unexpected exceptions on outside input do not stop the batch: they go to a human in one digest per run. The rule
  also records that a reporting task placed after an Airflow pipeline can turn a failed run green.
- `src/acidbase/push.py`: `_publish_projection` tags each public snapshot as `snapshot-<12 hex digits>` and pushes the
  branch and tag atomically. Every orphan force-push takes `main` away from the previous commit, while consumers keep
  pinning it in their `uv.lock`, so a commit could disappear and break `uv sync --frozen` across the fleet. The commits
  pinned before this change were tagged by hand. `docs/guidelines/dual_push.md` covers the tags and how to retract one.
- `docs/guidelines/house_rules.md`: adds "Convert ijson Numbers for Pinecone". `ijson` yields `Decimal` by default, and
  Pinecone's client rejects it with a `TypeError` in vectors and metadata alike, as tested on 8.1.0 and 10.3.0. The rule
  also records the `use_float=True` overflow limit, and warns against retry wrappers that turn this error into skipped
  batches.
- `docs/guidelines/house_rules.md`: adds "Separate URL Lists from Committed Code". Collected URL lists live in a
  gitignored file beside a tracked sample, and the rule also covers Docker images, backups, agents and lists that were
  already committed. Citations and public endpoints stay out of scope, so bibliographies keep their URLs.
- `acidbase fleet add|census|list|remove` (`src/acidbase/fleet.py`, registered in `src/acidbase/cli.py`; tests in
  `tests/test_fleet.py`; guide in `docs/guidelines/fleet.md`): a fleet manifest of the repositories that consume
  acidbase, one `[[repo]]` table each (name, host, path, CLI, optional mypy target and note). `add` registers a
  repository, refusing non-consumers (comments do not count) and the metarepo itself, inferring the CLI from
  `[project.scripts]` (a bare `push` alias is ignored), and inserting in `abc_key` order through tomlkit so
  comments survive; re-registering is a no-op, so repo-creation scripts call it unconditionally. `census`
  re-derives the fleet from disk in both directions (`MISSING`, `NOT-A-CONSUMER`, `CLI-MISMATCH`, `UNREADABLE`,
  `UNREGISTERED` with the fixing command; `UNREACHABLE` is informational) and exits 1 on drift. `list` renders
  table, JSON, TSV, or Markdown, with each repository's path on the running host for loops. Paths are stored as
  their own host spells them and translated through an optional `[hosts]` table (WSL home via
  `\\wsl.localhost` from Windows, Windows drives via `/mnt` from WSL), so one census from either side covers
  both. The manifest is located by `--fleet-file`, then `$ACIDBASE_FLEET_FILE`, then `config/fleet.toml` above
  the working directory. In this checkout that file is private (deliberately not on `PUBLIC_ALLOWLIST.txt`);
  `tests/test_fleet.py` validates it when present and skips on the public mirror.
- `acidbase repopatch --owner O --repo R [--dep NAME ...] [--severity S] [--dry-run]`
  (`src/acidbase/security/repopatch.py`, `src/acidbase/security/cli.py`, `src/acidbase/cli.py`; tests in
  `tests/security/test_repopatch.py`): patches every fixable open Dependabot alert of one repository in a single
  run. It plans from one alerts query, grouping alerts per package (pip spelling variants folded) at the highest
  patched version, then runs the existing per-package bump (`patch_repo`) once per package: one commit each, named
  after the advisories it closes. Failures after edits are reverted and the run continues; repository-level
  failures (`DIRTY`, `GITERROR`, `MISSING`, ...) stop the run without reverting anything, so uncommitted user work
  is never touched. The branch is pushed once at the end (one CI run), then each package is verified against
  origin's manifest. Packages without a patched version are listed for manual handling. Push strategy only for
  now. `acidbase alerts --repo X` prints the `repopatch` line when more than one package is patchable, repeating
  any `--dep`/`--severity` filters. Added to `PUBLIC_ALLOWLIST.txt` and `docs/guidelines/security_patching.md`.
  A live `--dry-run` on CanonFodder planned 11 bumps from 88 alerts, with GitPython folded to 3.2.1.
- `templates/.gitignore`: canonical ecosystem `.gitignore` template covering Python, Windows,
  virtual environments, IDEs, caches, data dumps, notebooks, and build artifacts, serving as
  the single source of truth for child repository ignore rules.
- `.gitignore` adoption in `acidbase scaffold` (`src/acidbase/scaffold.py`, `tests/test_scaffold.py`):
  plans and applies baseline gitignore rules. Automatically plans `add` when absent, `keep`
  when all canonical rules are already present, and `extend` (appending only missing canonical
  rules under `# --- appended by acidbase scaffold ---` while preserving all custom local rules)
  when partially populated.
- `PUBLIC_ALLOWLIST.txt`: added `templates/.gitignore` to the canonical templates inventory for
  public projection during `acidbase push`.
- `src/acidbase/collation.py` (`abc_key`, `abc_sorted`; tests in `tests/test_collation.py`): the
  ecosystem abecedary as a reusable sort key, mirroring the cross-language `abc.md`/`make_abc.py`
  sequence: Zone P (ASCII 0..63, `¿`, `¡`, `@`, ASCII 91..96, 123..127) first, then letters with
  case interleaved (`A a B b ... Z z`). Non-ASCII letters follow their NFD base letter, tie-broken by
  codepoint, approximating the abecedary's curated variant order. Both files added to
  `PUBLIC_ALLOWLIST.txt` so the projection import gate keeps resolving `acidbase.scaffold`.

### Changed

- `scripts/list_symbols.py`: writes `function_report.txt` beside itself instead of to a hard-coded `scripts/`, because
  `new_repo` now seeds it into `script/`, and running it there would have recreated the plural folder.
- `templates/.gitignore`: also ignores `tmp/`, `scratch/`, `scratchpad/` and Office lock files (`~$*`), because `push`
  stages everything, so a scratch folder or an open document's lock file would otherwise be committed. `doc/_build/`
  joins `docs/_build/`, because new repos name that folder in the singular.
- `templates/.github/workflows/lint.yml`, `.github/workflows/lint.yml`: the gitleaks download retries with `--retry 5`,
  because a transient 504 from GitHub's release host failed `lint` on code that was fine. `templates/superseded.txt`
  records the replaced template, so `acidbase scaffold --refresh-baseline` can update repos still on it.
- `templates/.gitignore`: replaces `models/` with model artifact types, because that rule also hid source code such as
  Django, SQLAlchemy and dbt models. Unambiguous formats (`*.ckpt`, `*.gguf`, `*.h5`, `*.onnx`, `*.pt`, `*.pth`,
  `*.safetensors`) are ignored everywhere, and `*.bin`, `*.joblib` and `*.pkl` only inside a `models/` directory. Scaffold
  only appends rules, so existing repositories keep `models/`. `templates/superseded.txt` records the replaced template.
- `templates/.gitignore`: stops hiding every `*.csv`, `*.sql`, `*.zip` and `data/`, which silently kept real work out of
  new repositories. Existing repositories keep their own rules. `templates/superseded.txt` records the replaced template.
- `scripts/guard_env.py`: sees through `rtk err`, `rtk test` and `rtk summary`, and treats `rtk smart`, `rtk json` and
  `rtk log` as readers, so the wrappers the RTK rule recommends cannot print a `.env` file.
- `docs/guidelines/house_rules.md`: adds the RTK rule, with Python tools going through uv, because bare `rtk ruff check`
  and `rtk pytest` do not reach a repository's locked environment.
- `templates/.gitleaks.toml`, `.gitleaks.toml`, `.gitleaks-private.toml`: docs and changelogs are no longer exempt from
  secret scanning, because that is where a pasted credential tends to land. False positives go in `.gitleaksignore`.
  The public config keeps the exemption for its `internal-*` rules only, since those docs legitimately name internal
  paths. `templates/superseded.txt` records the replaced template.
- `templates/.github/workflows/lint.yml`, `.github/workflows/lint.yml`: the gitleaks job checks its download against a
  pinned `GITLEAKS_SHA256` and runs `gitleaks git`, because `detect` has been deprecated since v8.19.
  `templates/superseded.txt` records the replaced template.
- `docs/guidelines/house_rules.md`: adds changelog discipline to the standing rules loaded by every agent session. It
  warns that split repos publish `CHANGELOG.md`, because the rule asks for detailed notes on live infra changes.
- `acidbase push` treats a `mixed-line-ending` fix as retryable. The hook rewrites files and exits 1, but git
  normalizes line endings, so pre-commit prints no "files were modified" line and `push` used to stop instead of
  re-staging.
- `templates/.pre-commit-config.yaml`, `.pre-commit-config.yaml`: add the `no-agent-coauthors` commit-msg hook, a
  built-in pygrep check that rejects agent `Co-Authored-By` trailers and needs no tool on the machine.
  `default_install_hook_types` makes a plain `pre-commit install` set it up, and `default_stages` keeps every other
  hook off the commit message. `templates/superseded.txt` records the replaced template.
- `templates/.github/workflows/lint.yml`: bumps `actions/checkout` to v7 and `astral-sh/setup-uv` to v10.3.3, so
  neither runs as a Node 20 action forced onto Node 24. `setup-uv` is pinned in full because it has published only
  immutable tags since v8. `templates/superseded.txt` records the replaced template.
- `templates/.gitignore`, `.gitignore`: ignore `.env.*` alongside `.env`, with `!.env.example` keeping the committed
  template visible. Child repositories receive both rules through `acidbase scaffold`, which appends negations last.
  `templates/superseded.txt` records the replaced template.
- `docs/guidelines/metarepo_rollout.md`: learning-material repos left `<REAL_A6A_FOLDER>` on 2026-11-03. `hadoop` now
  lives at `<REAL_TANUL_FOLDER>\it\hadoop`; `iu-docker` and `iu-kafka`, consumers that were never listed, joined the Windows
  manifest and inventory from `<REAL_TANUL_FOLDER>\iu\subject\data_engineering` (both `LOCAL`, ruff 0.17.3). The census and
  hook-census loops scan the moved paths explicitly, and the non-consumer note records that
  `MotherDuck-DuckDB-Course` moved to `<REAL_TANUL_FOLDER>\it\duckdb`, outside the C-drive scan. The other seven consumers
  the census had been reporting without a manifest entry (`cosmetics`, `kick-the-habit`, `mentaltech`, `ocr`,
  `oddsapi`, `SingleSauce`, `soldesal`; all `LOCAL`, ruff 0.17.3, `bump` wired) joined too, and the Windows
  manifest and the inventory are now sorted by `acidbase.collation.abc_key` instead of codepoint order.
- `docs/guidelines/metarepo_rollout.md`: the inline PowerShell/bash manifests, the hand-written census loops,
  and the static inventory table are gone. `$FLEET` (Windows) and `FLEET_REPOS`/`FLEET_CLIS` (WSL) are built
  from `acidbase fleet list`, so every later phase runs unchanged; Phase 1 is `acidbase fleet census` plus one
  `acidbase hooks` call over every member's local path (WSL repos included); the inventory is printed with
  `acidbase fleet list --format markdown`, and its dated notes moved into the manifest.
- `src/acidbase/security/cli.py` (tests in `tests/security/test_security_cli.py`): `acidbase alerts` now
  suggests patch commands targeted with one `--repo` per repository that showed the alert, instead of an
  owner-wide command that re-scanned every repo's SBOM (about 2-4 GitHub API calls per repo) to rediscover what
  `alerts` had just listed. `acidbase patch --repo` is repeatable to support this; each named repo still runs
  the full per-repo discovery (SBOM, live-manifest stale-graph check, alerts fallback) right before patching, so
  the safety checks are unchanged. The owner-wide command is still printed as an optional sweep, because the
  alert list can miss repos (dismissed or not-yet-raised alerts, rows hidden by a filter), and a note appears
  when `--dep`, `--severity` or a non-`open` `--state` narrowed the list. An `alerts --repo X` query keeps
  suggesting only `--repo X`, without a sweep.
- `src/acidbase/scaffold.py` (`_order_gitignore_rules`, test in `tests/test_scaffold.py`): the
  `# --- appended by acidbase scaffold ---` block is now sorted by `abc_key` instead of following
  template order. The template sorts within `# Section` headers that the appended block drops, so
  the old output read as a series of unrelated sorted runs (`.serena/`, `*.backup`, ..., `*$py.class`).
  Rules are also deduplicated case-insensitively (the template lists `.mypy_cache/` twice, which was
  appended twice), and negation rules (`!pattern`) stay last in template order, because sorting `!`
  to the top would place them before the rules they override.
- `.gitleaks.toml`: allowlisted `templates/.gitignore`. Its `WARP.md` ignore pattern tripped the
  custom `internal-warp-md` rule and blocked `acidbase push` with a false-positive leak. A path
  allowlist is used because `.gitignore` does not support trailing `# gitleaks:allow` comments.
  The regex is unanchored and separator-agnostic because the push preflight runs
  `gitleaks detect --no-git --source <absolute projection dir>`, so on Windows the path gitleaks
  matches is `C:\...\templates\.gitignore`; a first attempt anchored on `^templates/` passed a
  `gitleaks git` scan but still failed the preflight. The pre-existing `^docs/.*\.md$` entry had the
  same latent defect (never matching in the preflight) and now uses the same `(^|[\\/])docs[\\/]` form.
- `templates/README.md` & `docs/guidelines/scaffolding.md`: documented `templates/.gitignore` and
  its non-destructive `extend` adoption behavior for existing repositories.
- `<REAL_A6A_FOLDER>\new_repo.ps1`: updated `$gitignoreSource` in step `[5/12]` to read directly from
  `$AcidbaseTemplates\.gitignore` (with fallback to `<REAL_TANUL_FOLDER>\it\git\sample\python-project.gitignore`),
  fixing broken path to the relocated sample.
- `<REAL_A6A_FOLDER>\new_repo.ps1`: step `[6/12]` no longer aborts fresh-repo creation under
  `Set-StrictMode -Version Latest`. `Add-MissingGitignoreRules` now allows empty strings in `-Rules`
  (the canonical template's blank lines failed parameter binding), and `$missing` is forced to an
  array so `.Count` works when step `[4/12]`'s scaffold already appended every rule (`$null.Count`
  threw). Also fixed two latent StrictMode hazards: the `requires-python` insertion used `"${0}"`
  (an undefined PowerShell variable, not a regex backreference), and step `[11/12]` read `.Length`
  of a possibly-`$null` `git status --porcelain`, which the `catch` reported as a skipped step.
- **`uv.lock` is now the single source of truth for the ruff version.** The
  canonical `.pre-commit-config.yaml` (template and this repo) no longer uses
  the remote `astral-sh/ruff-pre-commit` hook with its own `rev:`; ruff runs
  as a `repo: local` / `language: system` hook via
  `uv run --frozen python -m ruff`, the same binary CI already used through
  `uv run ruff`. The `uv-lock` hook got the same treatment, and the template's
  gitleaks hook now matches this repo's system-binary variant, so the file
  carries no `rev:` at all. Root cause of the drift being fixed: the template
  pinned `v0.8.0` (pre-2025-style formatter), `acidbase scaffold` never
  rewrites a file it has already placed, every later `uv lock` moved the
  locked ruff to 0.12-0.16, and the documented remedy (`pre-commit
  autoupdate`) would have moved the hook to *latest*, not to the *locked*
  version. By 2026-09 ten children formatted with 0.8.0 locally and were
  checked with 0.15/0.16 in CI. `python -m ruff` rather than bare `ruff` so a
  repo without ruff in its dev group fails loudly instead of silently using a
  PATH ruff. Consequence for children: `ruff` must be in
  `[dependency-groups].dev`. The hooks cover `types_or: [python, pyi,
  jupyter, markdown]` because ruff 0.16 formats Python code blocks inside
  Markdown by default and CI's `ruff format --check .` therefore already
  covers `.md` files; a hook with a narrower scope would pass locally and
  fail in CI. acidbase itself moved to `ruff>=0.16.8` for the same reason.
- `pyyaml` joined the runtime dependencies (the hook report parses
  `.pre-commit-config.yaml` properly instead of regex-scraping it, which is
  how the original bash audit produced CRLF phantom mismatches).
- `acidbase bump` now accepts combined components such as `patch beta` and
  `minor alpha`, allowing a new prerelease series to advance its release
  number in the same uv operation. The versioning guide explains each phase,
  PEP 440 ordering, explicit versions, and the separate child-wiring rollout.
- Removed automatic DVC detection, file classification, `dvc add`, and
  `dvc push` from the shared push command. Acidbase now manages Git only;
  data-versioning tools are explicit project-level choices.
### Added

- `acidbase hooks [TARGET...] [--all] [--strict] [--no-pins]`: classifies each
  repository's ruff pre-commit hook against `uv.lock` as `LOCAL`,
  `LOCAL-UNLOCKED`, `LOCAL-UNPINNED`, `ALIGNED`, `DRIFT` (with `<`/`>`
  direction), `REMOTE-UNLOCKED`, `NO-RUFF-HOOK`, `NO-PRECOMMIT`, `NO-LOCK`, or
  `UNREADABLE`; lists every remaining remote `rev:` pin (uv, gitleaks, ...);
  exits 1 on `DRIFT`/`LOCAL-UNLOCKED`/`UNREADABLE` and, under `--strict`, on
  the merely-coincidental `ALIGNED`. `--all` sweeps the `defaults.roots` of
  `config/security_patch.toml`. CRLF- and BOM-tolerant so Windows checkouts
  report the same as WSL ones.
- `tests/test_hooks.py` asserts that the template pins no remote `rev:` and
  that this repo's own `.pre-commit-config.yaml` mirrors the template's shared
  hooks. The two files claimed to mirror each other for a year; this is the
  test that would have caught the `v0.8.0` vs `0.15.14` split.
- `acidbase hooks` reports `LOCAL-NOT-SYNCED` (error) when ruff is locked
  but reachable only through an extra or a non-default dependency group, so a
  plain `uv sync` never installs it and the local hook fails on a fresh
  checkout. Follows `{include-group = ...}` and `tool.uv.default-groups`,
  and counts ruff under `[project].dependencies` as installed (an odd home
  for a linter, but `uv sync` does install it; email had it there and was
  briefly misreported). Found in the wild on CanonFodder during the
  2026-09-20 rollout.
- `acidbase scaffold` distinguishes `stale` from `preserve`: a local file
  that is a verbatim copy of a *previous* acidbase template (normalized
  digests in `templates/superseded.txt`) is an old baseline, not local
  policy. Plain apply still leaves it alone; `--refresh-baseline` replaces it
  (`refresh`), with the same plan-time race check as `extend`. A test walks
  git history and fails when a template changes without the digest of the
  version it replaces being registered, so the registry cannot drift the
  way the hook revs did. On the fleet this immediately surfaced six children
  running the 2026-05 `lint.yml` verbatim.
- The template `lint.yml` (and this repo's) runs `uv run acidbase hooks .`
  before `ruff check`, so a remote ruff pin sneaking back into a child fails
  CI instead of waiting for the next census.
- `.gitattributes` marks `*.md` as LF: ruff 0.16 formats Markdown code
  blocks with `line-ending = "lf"`, and without the attribute every hook run
  on a Windows checkout left content-identical CRLF phantoms.
- `docs/guidelines/metarepo_rollout.md` gained the hook census, a Phase 2b
  for refreshing stale baselines, the exact procedure and pitfalls of the
  2026-09-20 ruff rollout (lint-debt gating, `--all-files` running the
  repo's other hooks, extras vs groups, PyPI-deleted pins re-resolving,
  PowerShell return-value semantics), a ruff-hook column in the inventory,
  and `jobbot` in the WSL manifest.
- `acidbase bump VALUE [--dry-run]` and the reusable
  `acidbase.versioning.bump_command`: delegates static project-version changes
  to `uv version --no-sync`, guards pre-existing `pyproject.toml` and
  `uv.lock` changes, supports uv's bump semantics and explicit PEP 440
  versions, reports the old and new versions, and never commits, tags,
  publishes, pushes, or synchronizes the environment.
- Scaffolded child CLIs now import the shared `bump` command alongside
  `push`; `docs/guidelines/versioning.md` documents the boundary from the
  unrelated dependency-security `acidbase patch` workflow.
- `acidbase scaffold TARGET [--package NAME] [--apply]`: a plan-first,
  non-overwriting baseline installer for initialized Python repositories. It
  adds missing CLI/CI/lint/secret-scan files, recognizes matching files,
  preserves divergent local content, appends ruff tables only when absent,
  and rechecks paths before atomic writes. The default invocation is read-only.
- `acidbase scaffold --wire-cli`: explicitly plans the otherwise
  project-owned dependency, entry point, initializer, and Hatch wheel metadata
  as one coupled change. Established CLIs, non-Hatch builds, conflicting
  commands, and local package inventories fail closed.
- `acidbase.workflow`: strict project-root discovery, executable lookup,
  argv-only command composition, project-local path validation, and subprocess
  exit-code propagation for project-owned lifecycle commands.
- `docs/guidelines/scaffolding.md`: the metalayer/child ownership boundary,
  ASCII-ordered command inventory, adoption states, and child command pattern.
- **PEP 561 `py.typed` marker**: acidbase now ships inline types, so consumer
  repos running strict mypy (`disallow_untyped_defs` et al.) resolve
  `acidbase.push` / `acidbase.cli_utils` for real instead of silencing them via
  `[mypy-acidbase] ignore_missing_imports`. The most safety-critical shared code
  in the ecosystem (subprocess git calls, path resolution, TOML parsing) is now
  also the code checked under each child's own strictness level; a signature
  change that breaks a consumer's CI fails loudly at type-check time rather
  than surfacing as `Any`-poisoned silence. Adoption cost was low because the
  annotation discipline already existed: 13 of 14 modules passed mypy before
  any edits. Enabling the marker required bringing the whole package up to
  scratch first — `py.typed` covers the package, so one sloppy module would
  export its noise to every consumer:
  - `priority_manager.py`: full annotation pass (the one laggard, previously
    17 errors under default settings). Root cause of most errors was one
    subtlety: `pymysql.Connection` is generic over its cursor class, so every
    unparameterized `Connection` annotation made `fetchone()`/`fetchall()`
    look like plain tuples instead of dicts; connections are now annotated
    `MySQLConnection[DictCursor]`, which fixed all 18 downstream `__getitem__`
    and CSV-writer errors structurally. Also switched to explicit keyword args
    for `pymysql.connect()` (the stubs declare them keyword-only), typed the
    `_parse_db_url` port as `str` for `pymysql.connect(**config)` compatibility,
    and added `types-PyMySQL` to the dev group.
  - `push.py::get_project_name`: TOML values are `Any` after `tomllib.load`,
    so the name lookup now verifies `isinstance(name, str)` before returning
    it instead of returning an unvalidated value from untrusted file content.
  - `cli_utils.group`: return type corrected to `Callable[..., click.Group]`
    (it returns Click's decorator when used bare, not a `Group` instance).
  - `security/cli.py`: alert-suggestion rendering no longer feeds a possibly-
    None patched version into `shlex.quote` — entries whose advisory version
    failed `Version()` parsing were previously dropped into the bucket with
    `patched=None` and would have crashed at render time; they are excluded
    upstream and fall back to `<version>` defensively.
  - `security/scanner.py::_fetch_sbom`: `json.loads` returns `Any`; the SBOM
    payload is now verified to be a dict (with a log line naming the actual
    type otherwise) instead of returning untyped data from network input.
  Verified end-to-end: acidbase's own suite (325 passed), ruff clean/format
  clean, default-settings mypy over all 14 source files, strict-consumer
  simulation (`--config-file bpmfinder/mypy.ini` = `disallow_untyped_defs`)
  over all 14 files, wheel-build inclusion of `acidbase/py.typed`, and the
  first consumer migration: bpmfinder's `[mypy-acidbase]` /
  `[mypy-acidbase.*]` overrides deleted, its lock re-resolved against this
  repo, and its full strict mypy passing on the resolved types alone.
### Fixed
- `.github/workflows/public-allowlist.yml`: the allowlist check no longer dies with `no merge base`. It tested whether
  the previous commit existed, which `snapshot-` tags made true, and then diffed two orphan commits that share no
  history. It now tests for a merge base, and otherwise checks every file at `HEAD`, as it did before the tags.
- `templates/.gitignore`, `templates/.github/workflows/lint.yml`, `templates/superseded.txt`: CI no longer
  floats to the newest CPython. The canonical gitignore ignored `.python-version`, so scaffolded children never
  committed one, and the lint job's bare `uv python install` then picked whatever `requires-python` allowed:
  bpmfinder's lint broke on 3.15.2 because numba 0.61.2 (via librosa) refuses Python >=3.14. The template stops
  ignoring `.python-version`, and the lint job now fails with a clear annotation when it is missing instead of
  guessing. The sync step becomes plain `uv sync --frozen` (includes the `dev` group by default) instead of
  `--extra dev || ...`, whose first half always errored because dev tooling lives in `[dependency-groups]`; an
  explicit `--group dev` was rejected because seven children (cosmetics, iu-docker, iu-kafka, mentaltech, ocr,
  oddsapi, SingleSauce) have no `dev` group. The replaced lint template is registered as superseded, and
  `tests/test_scaffold.py` pins both halves of the contract.
- `.gitignore`, `.python-version`, `.github/workflows/lint.yml`: acidbase itself now tracks `.python-version`
  (3.12) and runs the same guarded lint setup.
- `src/acidbase/security/cli.py`: `acidbase alerts` no longer suggests two identical `patch` commands for one pip
  project spelled differently across advisories (e.g. `--dep Pillow` and `--dep pillow`). GitHub keeps each
  advisory's original spelling, while pip names are case- and separator-insensitive (PEP 503), so `_suggest_patches`
  now groups pip alerts by `packaging.utils.canonicalize_name` and shows the most frequent spelling. npm and other
  ecosystems keep raw names. Covered by new tests in `tests/security/test_security_cli.py`.
- **The public mirror shipped a broken package** for one commit: `PUBLIC_ALLOWLIST.txt`
  enumerates publishable paths explicitly, and the new `src/acidbase/cli_utils.py`
  was not added to it. The dual-publish projection therefore published the updated
  `src/acidbase/cli.py` (which does `from acidbase.cli_utils import RichGroup`)
  while filtering out the module it imports, so `import acidbase.cli` raised
  `ModuleNotFoundError` on the public mirror at `4f96339d`. Consumer repos were
  unaffected in practice because they import `acidbase.push`, not `acidbase.cli`
  — but any consumer adopting `RichGroup` would have failed to resolve it.
  Discovered while bumping the consumer `uv.lock` pins: the resolved public SHA
  had no `cli_utils.py`. Fix: added `src/acidbase/cli_utils.py` and
  `tests/test_cli_utils.py` to `PUBLIC_ALLOWLIST.txt` and re-published.
  Note the class of bug — an allowlist that lists files individually silently
  drops every *new* file. The `public-allowlist.yml` guard did not catch it,
  but not for the reason first assumed (it does run on pushes as well as PRs):
  the guard only rejects *changed paths the allowlist fails to cover*, i.e.
  over-publishing. Under-publishing is invisible to it by construction, since
  a file the allowlist forgot never reaches the public repo and so can never
  appear in that repo's changed-file set — and the job is skipped entirely on
  the private repo, where non-allowlisted files are legitimate.
### Added
- **`acidbase push` now gates the public projection on import self-containment**,
  closing the hole that shipped a broken mirror. New
  `_check_projection_imports` parses every `.py` file in the sanitized
  projection and resolves each intra-package import against the modules the
  projection actually publishes; a dangling reference fails the preflight and
  removes `public`/`both` from the destination options. Rendered as a new
  `Imports:` line beside `Gitleaks:`, listing every offending file so each one
  names a path the allowlist should probably admit. Escape hatch:
  `--skip-projection-check`.
  Why static resolution rather than a byte-compile pass: **compiling would not
  have caught this.** `acidbase/cli.py` compiles perfectly whether or not
  `cli_utils.py` exists; the failure only surfaces at *import* time. Resolving
  imports statically also needs no virtualenv, installs nothing, and executes
  none of the published code. Deliberately no "parent package exists" fallback
  — `acidbase` being published says nothing about whether `acidbase.cli_utils`
  is, and accepting the prefix silently neuters the check (caught by the tests
  during development). `from .mod import name` is verified only as far as
  `mod`, since `name` may be an attribute; `from . import name` is fully
  verified because a bare relative name must be a submodule.
  Verified by replaying the original incident: building the real projection
  from an allowlist missing `src/acidbase/cli_utils.py` now fails the gate and
  names `src/acidbase/cli.py`, `templates/cli.py`, and
  `tests/test_cli_utils.py`. Files: `src/acidbase/push.py`
  (`_projection_module_index`, `_iter_internal_imports`,
  `_check_projection_imports`, `PublicPreflight.imports_*`,
  `run_push(skip_projection_check=...)`), `tests/test_push.py` (11 tests:
  layout discovery, the unpublished-sibling regression, third-party/stdlib
  exemption, relative imports, syntax errors, docs-only projections, and the
  `public_safe` gating both ways).
  This is the *preventive* half of the fix; see the new `importable` CI job for
  the detective half.
- `.github/workflows/public-allowlist.yml` gains an `importable` job that
  installs the published package on the public mirror and imports every module
  under `acidbase.` via `pkgutil.walk_packages`. It covers the failure
  direction `enforce-allowlist` is structurally blind to: that job rejects
  changed paths the allowlist does not cover (over-publishing), whereas a file
  the allowlist *forgot* never reaches the mirror and therefore never appears
  in its changed-file set (under-publishing). Importing for real rather than
  re-implementing the resolver in YAML is deliberate — it tests the property
  consumers actually depend on and cannot drift from `push.py`. Together with
  the local pre-flight gate this is prevent-then-detect: the push refuses to
  publish a projection with dangling imports, and CI still fails if something
  reached the mirror via `--skip-projection-check` or another route.
- `templates/cli.py`: the CLI skeleton for scaffolded repos now lives in acidbase
  alongside the CI/lint baseline, and **imports** rather than restates the shared
  behaviour — `acidbase.cli_utils.group` for the command group and
  `acidbase.push.push_command` for `push`. It replaces the ~200-line
  self-contained `cli_push_template.py` that lived in the unversioned
  `~/skeletal/scripts/`, which was the code `acidbase.push` had originally been
  extracted from. That template kept stamping the pre-extraction pattern into
  every new repo, and repos created from it drifted: `gdgap` still carried the
  fork in 2026, missing the clean-but-ahead push guard, dual-publish support,
  and the Unicode stream fix. `~/new_repo.sh` now copies
  `$ACIDBASE_TEMPLATES/cli.py` (it already sourced the CI baseline from that
  directory and already runs `uv add 'acidbase @ git+...'` for every non-acidbase
  project, so the dependency is guaranteed), falling back to the legacy path only
  if the acidbase template is unreachable; the skeletal copy was renamed to
  `cli_push_template.py.retired`. Rationale recorded in `templates/README.md`.
- `RichGroup.main` now calls `ensure_unicode_safe_streams()` before dispatching,
  so every adopting CLI gets UTF-8-safe output without each consumer `main()`
  remembering to. Surfaced during the ecosystem rollout: `transcriber --help`
  rendered `transcribes \ufffd` instead of an em dash, because Windows consoles
  default to a legacy code page (cp1250 here) that cannot encode it. This was a
  pre-existing limitation of the consumer CLIs that Click's 45-char truncation
  had been accidentally hiding — it cut most lines before the first non-ASCII
  character. Confirmed by re-running with `PYTHONIOENCODING=utf-8`, which
  renders the dash correctly. The guard also protects each CLI's own non-ASCII
  output (check-mark/progress glyphs), not just its help. Files:
  `src/acidbase/cli_utils.py`, `tests/test_cli_utils.py` (guard invoked on
  dispatch; em dash survives rendering).
- Canonical non-truncating CLI help for the ecosystem: `src/acidbase/cli_utils.py`
  adds `RichGroup(click.Group)` and a `group()` decorator wrapper. The default
  Click group listing caps each command's short help at 45 chars
  (`get_short_help_str(limit=45)`), so longer descriptions ended with `...` and
  the user had to run `<cmd> --help` to read the rest (e.g. `patch ... verify...`).
  `RichGroup.format_commands` replaces that one section with a Quarto-style
  two-column Rich table: bold command name in the left column, the full first
  paragraph of its help wrapped onto aligned continuation lines in the right,
  sized to the terminal width — no truncation. Every other help section
  (options, description, epilog) keeps Click's default rendering, so the change
  is local to the one lossy spot. The block carries ANSI codes
  (`force_terminal=True`), which Click's `echo` strips on piped output, so it
  is coloured on a terminal and plain text when redirected. `acidbase`'s
  top-level group now uses `cls=RichGroup` (`src/acidbase/cli.py`); consumer
  repos that build a bare-Click group and mount `acidbase.push.push_command`
  (tcnvsrnn, transcriber, ratemyhuman, ...) opt in with
  `from acidbase.cli_utils import group` and replace `@click.group(...)` with
  `@group(...)`. Typer-based repos (uteal) already render help through Rich and
  are unaffected. Files: `src/acidbase/cli_utils.py`, `src/acidbase/cli.py`,
  `tests/test_cli_utils.py` (6: non-truncating short-help extraction, group
  listing without ellipsis + every non-hidden command present, decorator
  defaults to `RichGroup`).
  repo's local environment. After a `DONE` bump the flow additionally runs
  `uv sync --frozen` (installing exactly the just-committed lock, never
  rewriting it), so the fix is installed locally without waiting for the next
  `uv run`/`uv sync` in that repo. The sync preserves the `--no-sync` bump's
  never-rebuild-a-foreign-venv guarantee: the venv flavor is detected via
  directory markers (`Scripts/` = Windows, `bin/` = POSIX — markers rather
  than interpreter files, because a Linux venv's `bin/python` symlink may not
  resolve across the 9P share) and compared against the executing side
  (`shell.wsl_routing` match = distro-native POSIX uv, else the host
  platform). Foreign or unrecognisable layouts (e.g. a Linux `.venv` reached
  from Windows outside WSL routing, a Windows `.venv` under `/mnt/c` reached
  from WSL, or a half-deleted remnant) are skipped with
  `env sync skipped: ...` in the Note; an absent `.venv` is created fresh by
  the native side. A failed sync never demotes the row (the security commit
  already landed) — the Note gains `env sync failed: <tail>`, successes gain
  `synced env`. npm runs ignore the flag with a console notice
  (`npm install` already updates `node_modules`). Files:
  `src/acidbase/security/patcher.py` (`_venv_flavor`,
  `_sync_executor_flavor`, `_sync_environment`, `patch_repo(sync_env=...)`),
  `src/acidbase/security/publisher.py` (strategy pass-through),
  `src/acidbase/security/cli.py` (flag + npm guard),
  `tests/security/test_patcher.py`, `tests/security/test_publisher.py`,
  `tests/security/test_security_cli.py`,
  `docs/guidelines/security_patching.md`, `README.md`.
- `tests/test_push.py`: adopted the 22 basic-workflow helper unit tests
  (`get_project_root`, `_has_changes`, `_hooks_modified_files`,
  `_find_untracked_for_dvc`, `_find_dvc_changed_outs`,
  `_auto_commit_message`) from ratemyhuman's consumer suite — the helpers
  had no coverage in their owning repo; this suite only covered the
  dual-publish projection/preflight layer. Converted from the consumer's
  class-based `@patch("acidbase.push._*")`/`MagicMock` style to this
  suite's flat `patch.object(push_mod, ...)` + `_make_completed` idiom;
  the `get_project_root` cases now exercise the public `start=` parameter.
  Ownership rationale: unit tests of private helpers belong to the owning
  repo so internal refactors cannot break consumer test collection (the
  ratemyhuman ImportError after the `_get_project_root` →
  `get_project_root` rename); consumers keep wiring/contract tests only.
### Fixed
- `acidbase patch` (pip) no longer lets `uv add` sync — and thereby (re)create
  or replace — the target repo's virtual environment: `_apply_uv_bump` now
  runs `uv add --no-sync <dep>>=<new>`. Trigger: while chasing the
  cryptography 50.0.0 `UVADDFAIL`s, a Windows-native `uv add` run directly
  against the `\\wsl.localhost\Ubuntu\...\CanonFodder` checkout treated the
  Linux `.venv` as invalid and started rebuilding it; over the 9P share the
  rebuild deleted `lib/` and then died on the now-dangling `lib64` symlink
  (`error: failed to remove file ... os error 2`), leaving a gutted env that
  blocked every later attempt at "Creating virtual environment".
  `shell.wsl_routing` already sends acidbase's own calls through
  distro-native tooling, but the same hazard remains wherever routing cannot
  apply (UNC spellings the pattern does not cover, or WSL-side acidbase
  against an `/mnt/c` repo with a Windows venv) — and a syncing add was pure
  waste anyway: the flow only needs `pyproject.toml` + `uv.lock` to move
  (exports re-run `uv export` off the lock, commits stage files), while for
  WSL repos it pointlessly reinstalled multi-GB GPU wheel sets per bump.
  Verified empirically that `uv add --no-sync` resolves and writes the lock
  while leaving a foreign-layout `.venv` byte-for-byte untouched (and creates
  no venv when one is absent). Developers resync with `uv sync` on their next
  session in each repo; the Windows self-patch `SELFSKIP` guard stays, since
  its suggested manual command intentionally performs a real add + sync after
  acidbase exits. Files: `src/acidbase/security/patcher.py`,
  `tests/security/test_patcher.py` (argv assertions + venv-preservation
  regression test), `docs/guidelines/security_patching.md`, `README.md`.
- `acidbase patch` (pip) no longer "succeeds" a bump that a `[tool.uv]`
  override neutralised. Trigger: the Pillow 12.3.0 run on `ratemyhuman`, whose
  `pyproject.toml` carries `override-dependencies = ["pillow>=12.2.0", ...]`
  (added to bypass facenet-pytorch's stale pins). uv overrides REPLACE every
  declared requirement for that package — including the project's own direct
  dep — so `uv add "pillow>=12.3.0"` exited 0 having moved only the declared
  specifier (`pyproject.toml` + the lock's `requires-dist` metadata) while the
  resolved `[[package]]` stayed at 12.2.0; the run committed and pushed that
  fix-nothing change, Dependabot's 26 alerts stayed open, and every clean
  re-run then reported a false `NOOP already >= 12.3.0`. Fix:
  `patcher._apply_uv_bump` re-reads `uv.lock` after a successful `uv add`;
  when the resolved version is still below target it reverts the uv add edits
  (`git checkout -- pyproject.toml uv.lock`, keeping the repo clean and
  re-runnable) and returns `UVADDFAIL` with a note naming the pinned version
  and pointing at `[tool.uv] override-dependencies / constraint-dependencies`.
  Files: `src/acidbase/security/patcher.py`,
  `tests/security/test_patcher.py` (override-neutralised bump fails + reverts;
  the curated-root DONE fake now realistically moves the lock on `uv add`).
- `acidbase patch --strategy push` no longer strands committed-but-unpushed
  security bumps on NOOP. Trigger: `evidencia` — an earlier run committed the
  Pillow 12.3.0 bump but its publish never landed, so `main` sat 1 ahead of
  `origin/main` while origin stayed vulnerable; the re-run found the local
  tree already satisfied (`NOOP`) and `PushStrategy` returned before the push
  step, so the stranded commit was never re-attempted (the verifier correctly
  kept reporting the alert `OPEN`). This is the publish-strategy twin of the
  earlier `run_push` clean-but-ahead fix. Fix: on `NOOP` (never on dry runs),
  `PushStrategy` now probes `git rev-list --count @{upstream}..HEAD` (new
  `publisher._count_unpushed`; missing upstream conservatively counts 0) and
  runs the profile's `push_command` when ahead, appending
  `pushed N stranded commit(s)` to the note (or reporting `PUSHFAIL` exactly
  like the DONE path — push execution is now shared via
  `publisher._run_push_command`). Files: `src/acidbase/security/publisher.py`,
  `tests/security/test_publisher.py` (new: stranded push, in-sync skip,
  stranded PUSHFAIL, custom wrapper routing, DONE-path regression guards,
  `_count_unpushed` parsing).
- `acidbase patch` no longer reports a repo as `MISSING` ("no local clone
  discoverable on this host") when `--repo` is given in a casing that differs
  from its `[profiles.<Repo>]` key. Trigger: `uv run acidbase patch --owner
  jurdabos --repo canonfodder ...` (lowercase) on the Windows host where
  `CanonFodder` is checked out on the case-sensitive WSL ext4 mount
  (`<REAL_WSL-UB_HOME>/CanonFodder`). `scanner._discover_via_sbom`
  stamps the hit with the literal `--repo` value, and `resolve_profile` did an
  exact, case-sensitive `profiles.get(repo)` — so the `[profiles.CanonFodder]`
  block (with its explicit `paths` and both-casings `locals`) was skipped
  entirely, and the default-roots fallback then failed because `canonfodder`
  does not exist on the case-sensitive mount (only `CanonFodder` does). Omitting
  `--repo` was unaffected because `gh repo list` returns GitHub's canonical
  `CanonFodder`. Fix: new `profiles._match_profile_key` matches the
  profiles-table key case-insensitively (exact match preferred, casefold
  fallback), so the block's `paths` / `locals` / `push_command` / `npm_dir`
  apply regardless of the requested casing. Files:
  `src/acidbase/security/profiles.py`, `tests/security/test_profiles.py`.
- `acidbase patch`/`alerts` pip discovery now guards against **stale
  dependency-graph (SBOM) nodes**. GitHub rebuilds
  `repos/{owner}/{repo}/dependency-graph/sbom` asynchronously, so for a while
  after a fix is pushed it can still list the pre-bump version as its own
  package node. Observed on `jurdabos/vlc`: the SBOM returned both
  `cryptography==49.0.0` and a phantom `cryptography==48.0.0`, so
  `_discover_via_sbom` logged a `< 48.0.1` HIT for a repo whose every manifest
  (`uv.lock`, root + `producer/requirements.txt`, `pyproject.toml`) was already
  on 49.0.0 — the patch step then verified `FIXED`/`NOOP`, contradicting
  discovery. Now each SBOM version inside the vulnerable window is cross-checked
  against origin's live manifest via the Contents API the verifier already uses
  (new `verifier.resolve_remote_pip_version`: default-branch `uv.lock` then
  `requirements.txt`); when the live version is at/above the threshold the hit
  is demoted to a `STALE-GRAPH` warning (new
  `scanner.discover_affected_repos(on_stale_warning=...)` callback, printed by
  `acidbase patch` regardless of `-v`) instead of surfaced as a vulnerability.
  A demotion still falls through to the Dependabot-alerts fallback, so a genuine
  subdirectory pin the consolidated SBOM hid is preserved. `_gh_get_raw_contents`
  now treats `ref=None` as "default branch" (omits `?ref=`). Files:
  `src/acidbase/security/scanner.py`, `src/acidbase/security/verifier.py`,
  `src/acidbase/security/cli.py`, `tests/security/test_scanner.py`,
  `tests/security/test_verifier.py`.
- `acidbase push` (and the whole `acidbase` CLI) no longer crashes with
  `UnicodeEncodeError` on Windows when stdout/stderr is redirected. Trigger:
  `uv run ratemymeat push --dry-run --no-prompt 2>&1 | Select-Object ...` on a
  cp1250 system — piped output makes CPython fall back to the legacy ANSI code
  page, which cannot encode the circled-digit/check-mark progress glyphs
  (`\u2460`, `\u2713`, ...) that `run_push` prints, so the very first
  `click.echo` raised and the command died before doing anything. New
  `ensure_unicode_safe_streams()` in `src/acidbase/push.py` reconfigures both
  streams to UTF-8 with `errors="replace"` (no-op when the stream is already
  UTF-8 or lacks `reconfigure`); called at the top of `run_push` (covers
  consumer repos importing `push_command`) and in the `acidbase.cli.main`
  group callback (covers every subcommand).
### Changed
- `acidbase push` dual-publish preflight now prints the **full** Included and
  Excluded file lists instead of folding the tail into `... (+N more)`. The
  preflight exists so the operator can audit exactly which paths would land on
  the public mirror and which stay private before choosing a destination;
  truncating either list defeats that review. Only raw `gitleaks` failure
  output remains capped (renamed `_PREFLIGHT_PATH_PREVIEW` →
  `_PREFLIGHT_GITLEAKS_PREVIEW`, now with an explicit `+N more line(s)` note
  pointing at the kept projection dir). File: `src/acidbase/push.py`
  (`_render_preflight`), with a regression test in `tests/test_push.py`.
### Fixed
- `acidbase push` (and every consumer wrapper built on `run_push`, e.g.
  `uv run evidencia push`) no longer reports "Nothing to push" with rc=0 when
  the working tree is clean but local commits were **never pushed**. Trigger:
  `acidbase patch` commits first and then invokes the profile's
  `push_command`; the wrapper saw a clean tree, short-circuited before the
  destination/push step, and exited 0 — so `PushStrategy` logged `push OK`
  while `origin/main` stayed stale. On `evidencia` this stranded TWO security
  commits (Pillow 10.2.0, then pillow 12.2.0) across separate runs, and the
  repo kept resurfacing as a pillow HIT with verifier verdict `OPEN` even
  though the local clone was patched. Fix: new `push._count_unpushed` (via
  `git rev-list --count @{upstream}..HEAD`); a clean tree that is ahead of
  upstream now skips the stage/commit steps but proceeds to destination
  resolution and the push, printing `Working tree clean, but N commit(s)
  ahead of upstream — pushing committed work.` A clean AND synced tree keeps
  the early exit; missing upstream conservatively counts as 0. The stranded
  evidencia commits were pushed manually (`4253665..2a917d4`). Files:
  `src/acidbase/push.py` (`run_push`, `_count_unpushed`),
  `tests/test_push.py` (clean-but-ahead pushes, clean-and-synced skips,
  dry-run plan, `_count_unpushed` parsing).
- `acidbase patch` failure notes for `uv` steps no longer bury the real error.
  Trigger: a `black` bump on `transcriber` failed with a Note showing only
  `warning: VIRTUAL_ENV=...acidbase\.venv does not match the project
  environment path .venv` + `× No solution found` — the actual cause (the
  pyTorch cu128 *nightly* channel had stalled with torch `dev20260408` vs
  torchvision/torchaudio `dev20260407`, no overlapping date, so the project
  was unresolvable; fixed in transcriber by moving the trio to the stable
  cu128 index) was invisible. Two changes: (a)
  `src/acidbase/security/shell.py` `run()` now drops `VIRTUAL_ENV` from every
  child environment — it always names the venv *running acidbase* (via
  `uv run`), never the target repo's, and only produces a noisy uv warning
  prepended to stderr; (b) `UVADDFAIL`/`EXPORTFAIL` notes in
  `src/acidbase/security/patcher.py` use `_output_tail(stdout, stderr)`
  instead of the head-truncated `stderr[:200]`, so the resolver's trailing
  `Because ... unsatisfiable` chain survives into the Summary table. Tests:
  `tests/security/test_shell.py` (env scrub for inherited and explicit env),
  `tests/security/test_patcher.py` (resolver-tail note).
- `acidbase patch` no longer clobbers a **curated root `requirements.txt`**
  and now survives **file-modifying pre-commit hooks**. Trigger: the PyJWT
  bump on `url-rag` — its root `requirements.txt` is generated by
  `scripts/sync_requirements.py` (direct deps only, Airflow core packages
  filtered out for the Astro Runtime ONBUILD guard), but `_apply_uv_bump`
  unconditionally ran `uv export --frozen --output-file=requirements.txt`
  over it; the repo's local `sync-requirements` pre-commit hook then rewrote
  the file mid-commit, pre-commit aborted the commit by design, and acidbase
  reported a terminal `COMMITFAIL` with an empty Note (the `-v` log printed
  only the head-truncated first 200 chars of hook chatter, cutting off the
  verdict). Three changes in `src/acidbase/security/patcher.py`:
  (a) the root `requirements.txt` now goes through the same
  `_parse_uv_export_header` guard as secondary files — only verifiable
  uv-export artifacts are regenerated (via their own recorded command);
  curated files are left alone (and flagged `manual` only when they `==`-pin
  the dep below target), and the commit stages `requirements.txt` only when
  it was actually regenerated (`_self_skip_command` applies the same guard to
  its suggested command);
  (b) `_commit_files` detects hook rewrites after a failed commit
  (`git diff --quiet` rc=1 ≡ worktree differs from index), absorbs them with
  `git add -u`, and retries the commit exactly once — the documented
  pre-commit contract; DONE notes gain `re-staged pre-commit hook edits`;
  (c) `COMMITFAIL` notes now carry the **tail** of the combined
  stdout+stderr (new `_output_tail`, 300 chars) because pre-commit prints
  per-hook verdicts at the end — no more empty/head-truncated notes.
  Tests: `tests/security/test_patcher.py` (curated-root skip, pinned-curated
  manual flag, uv-export-root regeneration via recorded argv, hook-retry
  success, no-retry-without-hook-edits, tail-preserving COMMITFAIL note,
  `_output_tail` unit).
- `acidbase patch`/`alerts` pip discovery: the SBOM path had gone **silently
  blind** because GitHub's dependency-graph SBOM no longer prefixes package
  names with the ecosystem (`pip:GitPython`); entries now arrive as bare names
  (`flask-cors`) with the ecosystem only in `externalRefs[].referenceLocator`
  PURLs (`pkg:pypi/flask-cors@6.0.2`, SPDXID `SPDXRef-pypi-...`).
  `scanner._discover_via_sbom` filtered on the legacy prefix, skipped every
  entry, and silently rode the Dependabot-alerts fallback for all repos
  (observed on a Flask-Cors run: all 34 repos logged "no matching version for
  target dep in SBOM" even where the SBOM listed flask-cors with versions).
  New `scanner._parse_purl` and `scanner._iter_ecosystem_packages` derive the
  ecosystem from the PURL (`pypi`→`pip` via `_PURL_TYPE_TO_ECOSYSTEM`, npm
  scoped names percent-decoded, qualifiers/subpaths stripped), keep the legacy
  name-prefix as fallback for older payloads, and use the PURL `@version` when
  `versionInfo` is absent. Verbose logs now show `eco:name==version` so stale
  duplicate graph nodes (e.g. a flask-cors 3.0.10 node alongside the locked
  6.0.2 — the false-positive source tracked in dependabot/dependabot-core#15259)
  are visible during discovery. Files: `src/acidbase/security/scanner.py`,
  `tests/security/test_scanner.py`.
- `acidbase patch` now fixes vulnerabilities pinned in a **secondary**
  requirements file (e.g. `producer/requirements.txt`) when the root project
  is already patched. Previously the pip backend only regenerated the root
  `requirements.txt`, and on repos whose root was already satisfied (so the
  stale subdirectory export was the only vulnerable manifest) `uv add` ran
  needlessly and failed with an opaque `UVADDFAIL` (empty `Note`). Now:
  (a) `_apply_uv_bump` reads the root `uv.lock` and **skips `uv add` when the
  root already satisfies `--new-version`**; (b) every tracked
  `requirements*.txt` still pinning the dep below the threshold is refreshed —
  uv-export artifacts (recognised by their `# autogenerated by uv` header)
  are regenerated by re-running *their own* recorded `uv export … -o <file>`
  command, guarded so only a verifiable `uv export` writing back to that same
  file is ever executed, while hand-maintained files are reported (not
  auto-edited); (c) `UVADDFAIL`/`EXPORTFAIL` now carry the failing command's
  stderr tail in `Note` so the Summary explains itself without `-v`. The
  alert manifest now rides along on `scanner.VulnerableHit.manifest` and is
  threaded into `verify_remote_bump`, which verifies the exact manifest the
  alert was filed against rather than only the root. Files:
  `src/acidbase/security/patcher.py`, `src/acidbase/security/scanner.py`,
  `src/acidbase/security/verifier.py`, `src/acidbase/security/cli.py`,
  `tests/security/test_patcher.py`, `tests/security/test_scanner.py`,
  `tests/security/test_verifier.py`,
  `docs/guidelines/security_patching.md`.
- `acidbase patch` no longer reports cross-advisory false positives. The pip
  SBOM alerts-fallback (and the npm alerts path) used to flag a repo for the
  patch run whenever it had *any* open Dependabot alert for the target
  package — even when that alert was a different, later advisory whose fix is
  far above the bump target. Bumping (e.g.) Pillow to 10.2.0 for
  CVE-2023-50447 would then also list repos whose only open Pillow alert is a
  later CVE first patched in 12.2.0, and the version-only verifier mislabelled
  them `FIXED` because their manifest already satisfied `>= 10.2.0`. The new
  `scanner._alert_addressed_by_patch` scopes alert matching to advisories the
  planned bump actually addresses: an exact `--cve`/GHSA match is always in
  scope, otherwise the alert is in scope only when the bump target reaches the
  alert's first patched version. `discover_affected_repos` gained
  `patch_target` and `cve_id` parameters (threaded from `--new-version` /
  `--cve` in `acidbase.security.cli.patch_command`); when `patch_target` is
  omitted the scan threshold is used as the reach target. Note that `--cve`
  was previously cosmetic (commit-message only) and now also scopes discovery.
  Files: `src/acidbase/security/scanner.py`, `src/acidbase/security/cli.py`,
  `tests/security/test_scanner.py`, `tests/security/test_security_cli.py`.
- `acidbase patch` Summary now qualifies the `FIXED` verdict by patch status
  so a no-op is visually obvious: `FIXED (already satisfied)` when the repo was
  already at/above the target (`PatchStatus.NOOP`) versus `FIXED (bumped)`
  when this run committed the change (`PatchStatus.DONE`). A bare verifier
  `FIXED` only ever meant "the manifest satisfies `>= new_version`", not "this
  run changed something"; the qualifier removes that ambiguity
  (`cli._alert_display`).
- `src/acidbase/security/scanner.py`: fixed a blind spot in `_discover_via_sbom` where
  multi-manifest repos were silently reported as clean. GitHub's SBOM endpoint consolidates
  each pip package to a single version entry — typically the one resolved in the root
  lockfile — so a subdirectory manifest (e.g. `server/requirements.txt`) pinning an older,
  vulnerable release never appeared in the SBOM. The `_discover_via_sbom` loop exited with
  `matched=False` and no hit even though Dependabot had an open alert for the stale subdirectory
  pin. Fix: when the SBOM loop finishes without a vulnerable match, the function now falls back
  to `fetch_alerts_for_repo` for that repo; an open Dependabot alert for the target
  (ecosystem, package) pair is treated as the per-manifest vulnerability signal that SBOM
  consolidation hid. The fallback is only triggered for repos that already passed the
  `_alerts_enabled` gate, so no extra network calls occur for repos that would have been skipped
  anyway. New tests in `tests/security/test_scanner.py` cover both the fallback-fires and
  the no-false-positive-when-alerts-cleared cases.
- `src/acidbase/push.py`: stopped corrupting `.gitleaks.toml` (and
  `.gitleaks-private.toml`) in the public projection. Previously
  `_build_public_projection` applied every `public_substitutions` rule to
  every UTF-8 file in the projection — including the gitleaks configs
  themselves. The `<REAL_WSL_HOME> → <REAL_WSL_HOME>` substitution rewrote
  the `internal-host-paths` rule's own `<REAL_WSL_HOME>` alternation into the
  literal `<REAL_WSL_HOME>`, turning the rule into a self-match against
  the placeholder. The public-side CI then matched the placeholder at
  every site where `<REAL_WSL_HOME>` had been substituted in the rest of
  the projection (7 hits in `pyproject.toml` and `tests/test_push.py`).
  Fix: added `SUBSTITUTION_EXEMPT_PATHS = {".gitleaks.toml",
  ".gitleaks-private.toml"}`; files in this set are copied byte-for-byte
  into the projection. Defence in depth: `_run_public_preflight` now
  prefers the *projected* `.gitleaks.toml` over the source one, so any
  future deviation between the two is caught locally before pushing.
  Tests pin both the verbatim-copy behaviour and the
  projected-config-preference; `.gitleaks.toml` itself now allowlists
  `.gitleaks-private.toml` so the verbatim-copied private config
  doesn't trip rules via its explanatory header.
### Added
- `acidbase dismiss-alert` and `acidbase reopen-alert` commands, backed by a
  new `update_alert` / `dismiss_alert` / `reopen_alert` route in
  `src/acidbase/security/alerts.py` that wraps
  `PATCH /repos/{owner}/{repo}/dependabot/alerts/{number}`. `dismiss-alert`
  takes a repeatable `--number`, a required `--reason` (one of the new
  `VALID_DISMISS_REASONS`: `fix_started`, `inaccurate`, `no_bandwidth`,
  `not_used`, `tolerable_risk`), an optional `--comment` (GitHub caps it at
  280 chars), and `--dry-run`; `reopen-alert` is the inverse (`state=open`)
  so every dismissal is reversible. The call is issued via `gh api -i` and a
  200 status line is treated as success (`AlertUpdateResult`). Motivated by
  Dependabot opening false-positive `uv.lock` alerts — e.g. `pip:authlib`
  flagged `< 1.6.10` on a repo whose `uv.lock` already pins `1.7.2`, because
  the versionless `{ name = "authlib" }` back-references in the lockfile are
  misparsed while the equivalent `requirements.txt` alerts auto-resolve to
  `fixed`. Wired into the top-level CLI in `src/acidbase/cli.py`; tests in
  `tests/security/test_alerts.py` (route: PATCH shape, comment passthrough,
  reason/state validation, non-200 failure) and
  `tests/security/test_security_cli.py` (per-number dispatch, `--dry-run`
  no-op, non-zero exit on failure, invalid-reason rejection, reopen).
- **Lowered `requires-python` from `>=3.13` to `>=3.12`** in `pyproject.toml`, and bumped `version` to `0.1.1`. The source has always been compatible with Python 3.12 (the canonical ruff `target-version` is already `py312` and no 3.13-only syntax / stdlib is used); the stricter declared bound was an oversight that blocked installation in Python 3.12 environments. The immediate motivation: downstream `url-rag` builds run on the Astronomer Runtime base image (`astrocrpublic.azurecr.io/runtime:3.0-14`), which ships Python 3.12.12, and the runtime's ONBUILD `install-python-dependencies` step (uv-based) failed on `acidbase==0.1.0 depends on Python>=3.13`. No API or behaviour changes; tests pass under both 3.12 and 3.13 wherever the source already supported them.
- `acidbase push` learned a **sanitize-on-publish** dual-publish flow for
  repos that maintain both a private working remote and a public mirror.
  Opt in by adding `[tool.acidbase.push]` to `pyproject.toml` with keys
  `private_remote`, `public_remote`, `allowlist_file`, `gitleaks_config`,
  and an ordered `[[public_substitutions]]` array. In dual mode, after
  the commit step the command (1) builds a sanitized projection of the
  working tree into a temp directory — only allowlisted paths are
  included, every UTF-8 file's contents pass through the substitution
  rules in declaration order, binary files copy through unchanged; (2)
  runs `gitleaks detect --no-git --source <projection> --config
  <gitleaks_config> --redact --no-banner` over the projection so the
  scan reflects exactly what would land on the mirror, with no spillover
  from private history; (3) asks an interactive Q&A for the push
  destination (`private` / `public` / `both` / `none`); (4) pushes to
  the chosen destination(s). The public push is **not** a regular `git
  push`: it is a `git init` + fixed-identity commit + `git push --force`
  of the projection as a single orphan commit, so no private history is
  ever reachable from the public refs. Files touched:
  `src/acidbase/push.py` (config loader, substitution parser,
  projection builder, projection context manager, gitleaks scope
  tightening, preflight rewrite, orphan force-push helper, multi-target
  push executor, new Click options `--to` / `--yes` / `--no-prompt` /
  `--public-message` / `--keep-projection`),
  `pyproject.toml` (opt-in `[tool.acidbase.push]` table plus initial
  `[[public_substitutions]]` rules covering `<REAL_A6E_FOLDER>`,
  `<REAL_A6A_FOLDER>`, WSL-UNC `<REAL_WSL_HOME>`, POSIX `<REAL_WSL_HOME>`, `<REAL_TANUL_FOLDER>`,
  `<REAL_LIFEAT_FOLDER>`),
  `docs/guidelines/dual_push.md` (full user-facing reference, including
  the placeholder-naming convention and the inspection recipe),
  `README.md` (pointer to the new guide),
  `PUBLIC_ALLOWLIST.txt` (allow the new public files),
  `tests/test_push.py` (60+ tests covering config loading,
  substitution parsing / application, topology detection, allowlist
  regex, projection building with UTF-8 + binary + allowlist filter,
  projection context modes (keep vs discard), gitleaks command shape
  with `--no-git`, preflight verdicts, destination resolution
  precedence, public-message resolution, publish-projection git command
  sequence, push ordering, partial-failure return codes, and CLI flag
  validation).
- `[[tool.acidbase.push.public_substitutions]]` array of inline tables
  in `pyproject.toml`. Each entry has a `pattern` (Python regex) and a
  `replacement` (literal string). Rules are applied in declaration
  order, so specific patterns must precede broader ones. The acidbase
  repo's own rules use the `<REAL_*>` ALL_CAPS placeholder convention
  (`<REAL_A6E_FOLDER>`, `<REAL_A6A_FOLDER>`, `<REAL_WSL-UB_HOME>`,
  `<REAL_WSL_HOME>`, `<REAL_TANUL_FOLDER>`, `<REAL_LIFEAT_FOLDER>`) so
  any sanitized token in a built projection is trivially greppable;
  this is documented as a written convention in
  `docs/guidelines/dual_push.md`.
- Non-interactive controls for `acidbase push`:
  `--to [private|public|both|none]` selects the destination and skips
  the prompt; `--yes` accepts the preflight-derived default;
  `--no-prompt` falls back to private-only unless `--to` is supplied;
  `--public-message` overrides the sanitized commit message used for
  the public projection; `--keep-projection` materializes the
  projection at `build/public-projection/` for inspection. The command
  rejects `--to <value> --yes` and `--yes --no-prompt` as mutually
  exclusive, and warns when `--no-prompt` is redundant with `--to`.
### Changed
- `.gitleaks.toml`: removed the bare `docs/projects/` prefix from the
  `internal-private-doc-paths` rule's alternation. The substring is a
  generic directory name; on its own it doesn't reveal any private
  artefact, and real files at that path are already blocked by
  `PUBLIC_ALLOWLIST.txt`. The other entries in the rule
  (`projects_catalog.md`, `project_prioritization.md`,
  `project_priorities.csv`, `style_guide.md`, `migration_log/`) remain
  because they ARE specific private filenames whose mention would
  signal extant internal content. This clears three otherwise-benign
  false positives in workflow comments and the `.gitleaks-private.toml`
  header without weakening the rule's coverage of real markers.
- `.pre-commit-config.yaml`: the local `gitleaks` hook now reads
  `.gitleaks-private.toml` instead of `.gitleaks.toml`. The previous form
  enforced the public-mirror `internal-*` rules on every staged commit and
  would fire on legitimately-internal content even after the earlier
  `git --pre-commit --staged` scoping fix. Strict public-mirror enforcement
  still happens in (a) the `gitleaks (CLI, MIT)` CI job over the public
  mirror's full history and (b) the new `acidbase push --to public/--to
  both` preflight, so the public surface remains double-gated.
- `tests/test_push.py`: rewrote the unlisted-path fixtures in
  `test_check_public_allowlist_rejects_unlisted_paths` to use neutral
  placeholders (`src/extra/module.py`, `notes/draft.md`) instead of the
  actual private-only path prefixes. The test intent is unchanged — we
  only need *some* path that the allowlist does not cover — and the new
  fixtures stay green under the strict public-mirror `.gitleaks.toml`
  ruleset too.
- `acidbase push` push ordering: in `--to both`, the private remote is
  pushed first and the public mirror second. When the private push
  succeeds but the public push fails, the process exits zero (private has
  landed) and prints a backfill hint (`uv run acidbase push --to public
  --no-prompt`) instead of erroring. The original single-remote behaviour
  (bare `git push` to the upstream-tracked branch) is preserved unchanged
  for repos that omit `[tool.acidbase.push]`.
### Fixed
- `.github/workflows/public-allowlist.yml`: the `Enforce PUBLIC_ALLOWLIST.txt`
  job is now gated to `github.repository == 'jurdabos/acidbase'`. Same
  rationale as the gitleaks gate below — this workflow ships to both repos
  but the allowlist check only makes sense on the public mirror; on the
  private repo every PR that touches `src/acidbase/priority_manager.py`,
  `docs/projects/`, or any other private-only artefact would otherwise
  legitimately fail the check.
- `.github/workflows/lint.yml`: the `gitleaks (CLI, MIT)` job is now gated to
  `github.repository == 'jurdabos/acidbase'` so the public-mirror leak-guard
  rules in `.gitleaks.toml` (`internal-private-doc-paths`, `internal-warp-md`,
  `internal-host-paths`) only run where they belong. The same workflow file
  also lives in the private repo (it is on the public allowlist), and on
  that side those rules legitimately match content the private history is
  *supposed* to keep (e.g. `src/acidbase/priority_manager.py`,
  `docs/projects/`, maintainer-local `<REAL_A6A_FOLDER>\\...` paths), which was
  failing PR CI on `jurdabos/acidbase-private`.
- New `gitleaks-private` job in `.github/workflows/lint.yml`, gated to
  `github.repository == 'jurdabos/acidbase-private'`, that runs gitleaks with
  a new `.gitleaks-private.toml` config (extends the upstream default
  ruleset only). This keeps real-secret scanning on the private repo (AWS
  keys, GitHub tokens, generic high-entropy secrets) without the
  false-positive flood from the `internal-*` rules. `.gitleaks-private.toml`
  is on the public allowlist so the public-mirror CI does not reject it,
  but it is never consumed on the public side (the public gitleaks job
  uses `.gitleaks.toml`).
### Added
- `acidbase patch` and `acidbase alerts` learned an `--ecosystem` switch
  (`pip` default, `npm` new) so the scanner and patch backend route by
  package manager. `pip` discovery continues to use GitHub's SBOM
  endpoint and drives `uv add` / `uv export`; `npm` discovery uses
  GitHub's Dependabot alerts endpoint (the SBOM emits bare names for
  npm — the ecosystem only appears in `externalRefs[].referenceLocator`
  as a PURL like `pkg:npm/yaml@2.8.1` — and is also empirically flaky
  for repos with large npm trees) and drives `npm install <dep>@^<new>`
  with a `package.json` `overrides` fallback for transitive pins. Files
  touched:
  `src/acidbase/security/scanner.py` (ecosystem-aware dispatch with
  `_discover_via_sbom` / `_discover_via_alerts` helpers,
  `_split_sbom_name`, `VulnerableHit.ecosystem`),
  `src/acidbase/security/patcher.py` (new statuses `NOTNPM`,
  `NPMADDFAIL`, `UNSUPPORTED_LOCKFILE`; helpers renamed to
  `_apply_uv_bump` / `_preflight_uv` so internal names reflect the tool
  acidbase actually runs, while the public `ecosystem` parameter keeps
  GitHub's SBOM/Dependabot vocabulary),
  `src/acidbase/security/verifier.py` (npm `package-lock.json` v1/v2/v3
  parser, ecosystem dispatch, `npm_dirs` parameter),
  `src/acidbase/security/publisher.py` (threads `ecosystem` through
  `PushStrategy` / `PrStrategy`),
  `src/acidbase/security/cli.py` (ecosystem-aware preflight,
  ecosystem-bucketed `_suggest_patches`, npm `npm_dirs` resolution for
  verification).
- `[profiles.<Repo>].npm_dir` option in `config/security_patch.toml`
  (`src/acidbase/security/profiles.py`) so repos with a non-root npm
  lockfile (e.g. `bracket/frontend/package-lock.json`) point the patcher
  and verifier at the right directory.
- Documentation: `docs/guidelines/security_patching.md` now covers the
  npm flow, prerequisites, `npm_dir`, and unsupported lockfiles, with a
  worked example for the `npm:yaml` CVE-2026-33532 advisory.
- Tests: scanner ecosystem-filter tests; patcher npm tests covering
  `_discover_npm_dir`, `_detect_unsupported_lockfile`,
  `_read_npm_lock_version` (v1/v2/v3 + scoped packages),
  `_ensure_npm_override`, plus end-to-end NOOP / DONE / overrides-fallback
  flows; verifier npm parser tests; `tests/security/test_security_cli.py`
  covering `_suggest_patches` ecosystem dispatch and the
  ecosystem-aware `_ensure_tools` preflight.
### Security
- `pyproject.toml`, `uv.lock`, `requirements.txt`: bumped `pytest` to `>=9.0.3`
  to remediate CVE-2025-71176. The dependency is now declared as a runtime
  pin in `pyproject.toml` so transitive consumers pick up the fixed version
  rather than resolving an older vulnerable release.
### Fixed
- `.pre-commit-config.yaml`: scoped the local `gitleaks` hook to `git
  --pre-commit --staged ...` (the gitleaks 8.30+ documented pre-commit
  invocation) instead of `detect --source .`. The previous form scanned the
  whole git history on every commit, which on this private repo re-flagged
  the 38 maintainer-local paths and private-doc references that the
  public-allowlist cutover intentionally preserved in private history but
  filtered out of the public mirror. Full-history scanning remains in
  `.github/workflows/lint.yml`, which runs against the (squashed, clean)
  public mirror where it correctly catches anything leaking into the
  public surface.
### Added
- Public release: split private metarepository tooling into a public surface
  consisting of the `acidbase` CLI (`patch`, `alerts`, `enable-alerts`,
  `enable-fixes`, `push`), the canonical CI / lint / secret-scan templates
  under `templates/`, and the cross-platform security-patching documentation
  in `docs/guidelines/security_patching.md`.
- `PUBLIC_ALLOWLIST.txt` enumerating every path allowed in the public mirror,
  consumed by both `git filter-repo` (when rewriting history) and the
  `public-allowlist` CI workflow (when enforcing PRs).
- `.github/workflows/public-allowlist.yml`: CI guard that fails any PR
  introducing a path outside `PUBLIC_ALLOWLIST.txt`, with diff-aware base
  resolution for `pull_request` and `push` events.
- `.github/CODEOWNERS`: requires repository-owner review for `.github/`,
  `templates/`, `.gitleaks.toml`, and `PUBLIC_ALLOWLIST.txt`.
- `.gitleaks.toml`: custom rules (`internal-private-doc-paths`,
  `internal-warp-md`, `internal-host-paths`) that trip when references to
  private-only artefacts or maintainer-local paths leak into the mirror.
- `LICENSE`: MIT license, replacing the previous proprietary license notice.
### Changed
- `README.md` rewritten for an external audience: focuses on the `acidbase`
  CLI and the CI baseline templates, drops the internal project portfolio
  and the visual-identity branding.
- `CONTRIBUTING.md` sanitized: links to internal style and project docs were
  removed; the standards section now references the public ruff config and
  the standard test/coverage commands.
- `pyproject.toml`: dropped the `pymysql` runtime dependency (only the
  internal `priority_manager` module needed it) and rewrote the project
  description to describe the public surface.
- `src/acidbase/cli.py`: dropped the `priority` subcommand from the public
  CLI; the private project-priority workflow stays in the preservation
  repository and is no longer reachable from the public package.
- `docs/guidelines/security_patching.md`: replaced maintainer-specific
  examples (owner names, internal absolute paths, runbook references) with
  generic placeholders.
- `config/security_patch.toml`: replaced the maintainer's profile entries
  with placeholder examples so the file can ship as a usable template.
- `.env.example`: removed product-specific environment variables; kept only
  the placeholders the public CLI actually reads.
- `templates/README.md`: removed references to maintainer-local consumer
  scripts and to the internal `ci-baseline.md` rationale doc.
### Notes / clarifications
- The public repository's history was squashed to a single `Initial public release` commit because `git filter-repo --paths-from-file` (while removing private paths from every commit) leaves the *content* of historical revisions of retained files intact, and that content still held maintainer-local paths and references to private-only docs from earlier commits. Squashing was the safest and cleanest way to guarantee no commit on any reachable ref ever contains an internal marker. The full pre-split commit lineage (with `WARP.md`, `docs/projects/`, `priority_manager.py`, `migration_log/`, etc.) is preserved at https://github.com/jurdabos/acidbase-private.
- Cutover steps (recorded for future audit):
  - `https://github.com/jurdabos/acidbase-private` created and populated with a pre-split mirror of the original `jurdabos/acidbase` history.
  - Prep commits authored locally (allowlist + sanitized docs + LICENSE + workflow fixes), then pushed to `jurdabos/acidbase`.
  - The repo was re-cloned as a bare mirror, `git filter-repo --paths-from-file PUBLIC_ALLOWLIST.txt` removed every non-allowlisted path, and the result was checked out into a worktree, squashed to one orphan commit (`Initial public release`, authored as Blai), and pushed to a fresh bare repo.
  - Validation on a private `jurdabos/acidbase-staging` repo: gitleaks detect = 0 leaks; `lint` and `public-allowlist` CI workflows both green; pytest = 83 passed.
  - The squashed bare was force-mirror-pushed to `jurdabos/acidbase`; visibility was then flipped to public via `gh repo edit --visibility public --accept-visibility-change-consequences`.
  - Branch protection was applied to `main`: required status checks (`ruff (check + format)`, `gitleaks (CLI, MIT)`, `Enforce PUBLIC_ALLOWLIST.txt`), no force pushes, no deletions, linear history required, conversation resolution required.
- Local checkout was reconfigured for the new two-repo workflow:
  - `origin` -> `https://github.com/jurdabos/acidbase-private.git` (full content lives here)
  - `public` -> `https://github.com/jurdabos/acidbase.git` (public mirror, allowlist-enforced)
- The private repository remains the maintainer's working copy for project-ledger content, internal style guidance, and the `priority_manager` workflow. The public mirror is downstream-consumable only; future public-safe changes can be cherry-picked or rebuilt as a follow-up squashed release.
- Staging repo `jurdabos/acidbase-staging` is still on GitHub; deleting it requires `gh auth refresh -h github.com -s delete_repo` followed by `gh repo delete jurdabos/acidbase-staging --yes`. Safe to remove once the public release is confirmed stable.
