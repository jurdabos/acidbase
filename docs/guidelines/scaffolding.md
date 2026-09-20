# Scaffolding and command ownership

Acidbase provides a small shared layer for repositories whose actual workflows
differ. A child project should import stable mechanics and define its own
meaning for project lifecycle commands. This keeps a command name consistent
without smuggling one framework's assumptions into every repository.

## The shared contract

Acidbase owns five reusable surfaces:

- `acidbase.cli_utils.group` supplies non-truncating Rich help and UTF-8-safe
  command dispatch.
- `acidbase.push.push_command` supplies the common Git commit-and-push
  workflow.
- `acidbase scaffold` plans and applies the canonical CLI, CI, lint, and
  secret-scan baseline.
- `acidbase.versioning.bump_command` supplies the common static
  project-version workflow.
- `acidbase.workflow.ProjectRunner` supplies strict project-root discovery,
  executable lookup, argv-only command composition, project-local working
  directories, and subprocess exit-code propagation.

The child repository owns the commands whose inputs, generated files, or tools
depend on that project. Its command inventory should stay ASCII-ordered because
it is an index. Steps inside a command remain in procedural order.

| Command | Ownership and inclusion rule |
| --- | --- |
| `bump` | Acidbase-owned and imported unchanged for uv projects with a static `[project].version`. |
| `clean` | Project-owned. Remove only an explicit inventory of reproducible output and caches. |
| `css-dev` | Project-owned. Include only when the project has a separate CSS build pipeline. |
| `dev` | Project-owned. Start the project's actual preview, watcher, or development server. |
| `doctor` | Project-owned checks built from shared discovery helpers; verify only tools and configuration the project requires. |
| `format` | Project-owned. Add with `format-check`, using identical scope and configuration. |
| `format-check` | Project-owned, read-only counterpart to `format`. |
| `install` | Project-owned orchestration of the package managers and external-tool checks the repository really uses. |
| `lint` | Project-owned aggregation of relevant static checks. |
| `migrate` | Project-owned. Include only when a versioned data or configuration schema exists. |
| `push` | Acidbase-owned and imported unchanged. |
| `render` | Project-owned. Include when the repository produces a document, site, or other rendered artifact. |
| `test` | Project-owned aggregation of deterministic checks and any appropriate smoke tests. |
| `type-check` | Project-owned. Include when substantive typed code makes it useful. |

`command` is deliberately absent. It does not name a stable behaviour, so it
should enter the contract only after a concrete, repeated meaning emerges.
Framework-specific commands remain in the project that needs them. For
example, a Tailwind watcher, a FastAPI development server, npm installation,
and Alembic migrations belong in a web application, not in acidbase.

## Plan-first adoption

The target must already be an initialized Python repository containing
`pyproject.toml`. Run the command without `--apply` first:

```powershell
uv run acidbase scaffold C:\path\to\project
```

The file report has four states:

- `add`: the path is missing and can be created.
- `extend`: `pyproject.toml` lacks ruff configuration, so the canonical ruff
  tables can be appended without rewriting its existing content.
- `keep`: the file already matches the baseline, or the project already owns
  the relevant configuration.
- `preserve`: a local file differs from the template and will remain untouched.

Apply exactly that plan with:

```powershell
uv run acidbase scaffold C:\path\to\project --apply
```

The apply phase rechecks every destination before writing. It refuses symbolic
link traversal, path escape, and a `pyproject.toml` changed after planning. New
content is staged beside its destination and atomically installed. Divergent
local CI, secret-scan, hook, and CLI files are always preserved for manual
comparison.

Ordinary adoption does not invent a CLI when `[project.scripts]` has no
acidbase-style entry point. To create an installable CLI as one explicit,
coupled operation, inspect the wired plan:

```powershell
uv run acidbase scaffold C:\path\to\project --wire-cli
```

The wired plan adds the following only when it can do so without reinterpreting
local build policy:

- the canonical acidbase Git dependency;
- `[project.scripts]` pointing the project command to `<package>.cli:main`;
- `src/<package>/__init__.py` and `src/<package>/cli.py` for a new src layout,
  or the equivalent files in an established flat package;
- Hatchling build metadata and explicit wheel package discovery.

Apply and materialize the new entry point with:

```powershell
uv run acidbase scaffold C:\path\to\project --wire-cli --apply
Set-Location C:\path\to\project
uv lock
uv sync --frozen
uv run <project-command> --help
```

`--command-name NAME` selects a command name different from `[project].name`.
The wiring operation refuses to replace an existing command, add a parallel
CLI beside an established project interface, reinterpret a non-Hatch build
backend, or change an existing Hatch package inventory.

Without `--wire-cli`, scaffolding deliberately does not choose a dependency
source, build backend, or executable name. The report identifies missing
project-owned wiring:

- declare `acidbase` as a dependency;
- map the desired executable under `[project.scripts]` to
  `<package>.cli:main`.

If `[project.scripts]` already exposes another CLI shape, acidbase treats that
interface as locally owned and does not create a parallel `src/<package>/cli.py`.
The report records this decision so a Typer application, framework CLI, or
other established entry point remains authoritative.

Repository-creation wrappers may invoke `acidbase scaffold ... --wire-cli
--apply` and then lock and synchronize the child. Existing repositories can
keep their own interface or opt into the same wiring after reviewing the plan.

## Child command pattern

The generated `cli.py` mounts the shared `bump` and `push` commands. A child
command can use `ProjectRunner` for external processes while retaining its own
semantics:

```python
import click

from acidbase.workflow import ProjectRunner


@cli.command("render")
def render_cmd() -> None:
    """Render this project's declared output."""
    ProjectRunner.discover(__file__).run("quarto", "render")
```

Arguments remain separate argv tokens and no shell is involved. If Quarto is
missing, discovery fails with a named tool error; if rendering fails, its exit
code becomes the CLI exit code.
