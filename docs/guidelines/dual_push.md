# Dual-publish workflow for `acidbase push`

`uv run acidbase push` can publish a single private commit to the working
private remote AND to a public mirror in one invocation. The public side is
generated as a **sanitized projection** of the private working tree: only
allowlisted paths are included, every UTF-8 file's contents pass through a
configurable substitution pipeline, and the result is force-pushed as a
single orphan commit so no private history can ever leak.

When no dual-publish configuration is present, `acidbase push` continues to
behave exactly as before: a single `git push` to the upstream-tracked
branch. Existing consumer repos pick up nothing surprising.

## Mental model

```
                  ┌─────────────────────────┐
                  │  acidbase push          │
                  └────────────┬────────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       │ (single mode)                                 │ (dual mode)
       ▼                                               ▼
   bare `git push`                            (1) commit privately
                                              (2) build sanitized projection
                                                  from PUBLIC_ALLOWLIST.txt
                                                  + [public_substitutions]
                                              (3) gitleaks --no-git over the
                                                  projection
                                              (4) Q&A: private / public /
                                                  both / none
                                              (5) push: private remote +
                                                  orphan force-push of the
                                                  projection
```

## Configuration

Dual mode is opt-in via a `[tool.acidbase.push]` table in `pyproject.toml`.
The acidbase repo itself opts in like this:

```toml
[tool.acidbase.push]
private_remote = "origin"
public_remote = "public"
allowlist_file = "PUBLIC_ALLOWLIST.txt"
gitleaks_config = ".gitleaks.toml"

# Substitutions applied to every UTF-8 file copied into the public
# projection. Patterns are Python regex; replacements are literal.
# Rules apply in declaration order — place SPECIFIC patterns BEFORE
# broader ones so the specific replacement wins.
[[tool.acidbase.push.public_substitutions]]
pattern = 'C:[\\/]+acidvuca[\\/]+acidbase'
replacement = "<REAL_A6E_FOLDER>"
[[tool.acidbase.push.public_substitutions]]
pattern = 'C:[\\/]+acidvuca'
replacement = "<REAL_A6A_FOLDER>"
# ... (continues for <REAL_WSL_HOME>, <REAL_TANUL_FOLDER>, <REAL_LIFEAT_FOLDER>, etc.)
```

| Key | Default when the table is present | Meaning |
| --- | --- | --- |
| `private_remote` | `"origin"` | Git remote for the private repo. |
| `public_remote` | `"public"` | Git remote for the public mirror. |
| `allowlist_file` | `"PUBLIC_ALLOWLIST.txt"` when on disk, else unset | Path enumerating files allowed in the public projection. |
| `gitleaks_config` | `".gitleaks.toml"` when on disk, else unset | Gitleaks rules scanned against the sanitized projection. |
| `public_substitutions` | `[]` | Ordered list of `{pattern, replacement}` rules applied to every UTF-8 file in the projection. |

If the table is **absent**, `acidbase push` runs in single mode. If the
table is present but at least one of `private_remote` / `public_remote`
does not exist locally, the command prints a yellow warning and falls
back to bare `git push` for that invocation — it does **not** block work.

## Placeholder naming convention

Sanitized replacements use the `<REAL_*>` ALL_CAPS convention (e.g.
`<REAL_A6A_FOLDER>`, `<REAL_WSL_HOME>`, `<REAL_TANUL_FOLDER>`). This is a
written convention, not machine-enforced — but new substitutions should
follow it. The benefits:

- **Greppable.** Any `<REAL_*>` token in public content is instantly
  visible as "this was sanitized." `grep -r '<REAL_' build/public-projection/`
  shows every translated marker at a glance.
- **Self-documenting.** The token name encodes what was substituted, so a
  reader sees `<REAL_WSL_HOME>` and understands which private artefact
  the path used to point at.
- **Audit-friendly.** Scanning a freshly built projection for `<REAL_*>`
  produces a high-signal list of every internal marker the pipeline
  touched on this run.

## How the projection is built

In dual mode, after the commit step, `acidbase push`:

1. Reads `PUBLIC_ALLOWLIST.txt` and compiles each entry into an anchored
   regex (matching the public CI's `awk` pipeline in
   `.github/workflows/public-allowlist.yml`).
2. Lists every tracked file via `git ls-files`.
3. For each tracked file:
   - If the path is **not** allowlisted → silently skip (it stays
     private-only).
   - If the path **is** allowlisted → attempt a UTF-8 decode, apply every
     `public_substitutions` rule, and write the result into a temp
     directory. Files that fail UTF-8 decode (images, archives, etc.)
     are copied byte-for-byte and skip substitutions.
4. Returns the temp directory; the gitleaks scan and the public push both
   target it.

The projection is a flat filesystem tree — **not** a git repo. The public
push step initializes a fresh `.git/` inside it just before the
force-push (see "Public push mechanics" below).

## Public pre-flight gate

In dual mode, `acidbase push` runs **one** binary gate after building the
projection:

```sh
gitleaks detect --no-git --source <projection-dir> --config <gitleaks_config> --redact --no-banner
```

`--no-git` is critical: it tells gitleaks to scan the filesystem as a
flat directory and ignore git history entirely. This makes the scan
reflect exactly what would land on the public mirror, with no spillover
from private commits.

The gate passes when gitleaks exits zero. Missing inputs (no
`gitleaks_config`, no `gitleaks` binary on `PATH`) count as **not safe** —
the user can still pick the public destination via `--to public`/`--to
both`, but the prompt will not recommend it by default.

The allowlist itself isn't a binary gate anymore: non-allowlisted files
just don't appear in the projection. The pre-flight summary shows
included/excluded counts so the user can verify nothing important got
dropped.

## Interactive Q&A

When stdin and stdout are both TTYs and no destination flag is supplied,
the command renders a preflight summary and asks:

```
⑥ Public preflight (dual mode):
   Public remote:  public
   Projection:     C:\Users\…\AppData\Local\Temp\acidbase-public-projection-…
   Included:       50 file(s)
     + .env.example
     + .gitattributes
     + .github/CODEOWNERS
     ... (+47 more)
   Excluded:       16 file(s) (private-only)
     - <internal-only-doc>.md
     - src/acidbase/priority_manager.py
     ... (+14 more)
   Gitleaks:       ✓ no leaks detected
Push destination [1=private / 2=both / 3=public / 4=none] [2]:
```

When the public side is not safe, the prompt only exposes `private` and
`none`; opting into `public`/`both` then requires re-running with
`--to public` or `--to both` explicitly.

## Non-interactive flags

For automation or to skip the prompt:

| Flag | Effect |
| --- | --- |
| `--to private` | Push only to `private_remote`. |
| `--to public` | Push only to `public_remote`. Useful for backfilling after a partial failure. |
| `--to both` | Push to both, private first. |
| `--to none` | Commit, but do not push. |
| `--yes` / `-y` | Accept the preflight-derived default (`both` when safe, otherwise `private`). |
| `--no-prompt` | Skip the prompt and default to `private` unless `--to` is supplied. |
| `--public-message <msg>` | Override the public-projection commit message. Default: inherited from the most recent private commit message, sanitized through `public_substitutions`. |
| `--keep-projection` | Materialize the projection at `build/public-projection/` (wiped at entry, kept at exit) for inspection. Default: discard via tempdir. |

Validation:

* `--to <value> --yes` is rejected (mutually exclusive — `--to` already
  selects the destination).
* `--yes --no-prompt` is rejected (mutually exclusive).
* `--to <value> --no-prompt` is allowed but `--no-prompt` is reported as
  redundant.

## Public push mechanics

For the public destination, `acidbase push` does **not** run a regular
`git push public`. The projection has no git history of its own, and the
public mirror's `main` is a single orphan commit by design (see the
public release audit in `CHANGELOG.md`). The publishing flow is:

1. `git init -q -b main` inside the projection directory.
2. `git config user.name "Blai"` and `git config user.email
   "balazs.torda@iu-study.org"` — the public mirror is a distinct
   release artefact and always carries the maintainer identity,
   regardless of whatever the local source repo's `user.*` is.
3. `git add -A` followed by `git commit -q --no-verify -m <message>`.
   The message is either `--public-message` (sanitized through
   `public_substitutions`) or the most recent private commit message at
   `HEAD` (also sanitized), with a generic `chore: publish sanitized
   snapshot` fallback.
4. `git remote add public <url>` (URL read from `git remote get-url
   <public_remote>` on the source repo).
5. `git push --force public HEAD:main`.

Result: the public mirror's `main` is replaced by a single fresh commit
that contains exactly the sanitized projection. No private history is
reachable from the public refs.

## Push ordering and partial-failure semantics

For `--to both`, the command pushes **private first, then public**. The
return codes (mapped to the process exit code by the CLI wrapper) are:

| Exit code | Meaning |
| --- | --- |
| `0` | Full success, or `--to none`. |
| `1` | No push landed (single push failed, or private failed before public was attempted). |
| `0` (with warning) | Partial success: private succeeded but public failed. The command exits zero so automation does not retry the already-landed private push. |

When a partial failure occurs, the command prints a yellow hint:

```
⚠ Private push succeeded but public push failed. To backfill, run:
    uv run acidbase push --to public --no-prompt
  once the issue is resolved.
```

## Backfilling the public mirror

If you want to publish a series of internal commits to the public mirror
in one go (for example, after preparing a public release), run:

```sh
uv run acidbase push --to public --no-prompt
```

This skips the prompt, builds the sanitized projection from the current
`HEAD`, and force-pushes it as a fresh orphan commit. The private remote
is left untouched.

## Inspecting the projection

To see exactly what would land on public without pushing anything:

```sh
uv run acidbase push --to none --keep-projection
```

This commits locally (if there's anything to commit), builds the
projection, and leaves it at `build/public-projection/` for inspection.
You can then run the strict ruleset against it manually:

```sh
gitleaks detect --no-git --source build/public-projection/ --config .gitleaks.toml --no-banner --verbose
grep -r '<REAL_' build/public-projection/   # see what got sanitized
```

## Single-mode behaviour

For repos that omit `[tool.acidbase.push]`:

* `acidbase push` stages and commits with hook-aware retries. Storage policy
  remains the responsibility of the consuming repository.
* The final step is a bare `git push` to the upstream-tracked branch —
  exactly today's behaviour.
* The destination Q&A, projection build, and gitleaks pre-flight are
  skipped entirely.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Remotes: dual mode requested … but at least one remote is missing locally` | `[tool.acidbase.push]` configured but `git remote` doesn't include the configured names | Run `git remote add <name> <url>` for the missing remote(s), or remove the table. |
| `Build: ✗ no allowlist_file configured` | Table omits `allowlist_file` and `PUBLIC_ALLOWLIST.txt` is not at the project root | Add an `allowlist_file` entry or place `PUBLIC_ALLOWLIST.txt` at the root. |
| `Gitleaks: ⚠ gitleaks executable not on PATH` | `gitleaks` isn't installed in the current shell | `winget install -e --id Gitleaks.Gitleaks` (Windows) or your platform equivalent. |
| `Gitleaks: ✗ leaks or errors detected` | The sanitized projection still contains a marker your `public_substitutions` didn't cover, OR the relevant rule in `.gitleaks.toml` is too aggressive | Run `--keep-projection` and inspect `build/public-projection/`; either add a substitution (with a `<REAL_*>` replacement) that scrubs the marker, or relax the gitleaks rule if the substring is benign in public content. |
| Public push reports `non-fast-forward` | Someone pushed to public outside the projection flow | Force-push from the projection is the documented mechanism; the projection is always the source of truth for public. Investigate the divergent commit before re-publishing. |
