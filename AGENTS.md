# AGENTS.md — Ground Rules for home-warden

This file defines the standards for all contributors (human or AI) working on this
codebase. Every change must comply with these rules before it is considered complete.

Bash / shell conventions below are adapted from
[repository-helpers AGENTS.md](https://github.com/the-hcma/repository-helpers/blob/main/AGENTS.md)
(Language & Runtime, Formatting & Style, Linting, Shell Script Conventions).

---

## Project

Systemd-managed **nginx** reverse proxy + certbot runner for home services.

- Config and unit templates live in this repo; the nginx process runs as an
  unprivileged user with sockets inherited from systemd (`NGINX=`).
- Target runtime: Ubuntu 26, nginx 1.28.3.
- Do not commit private keys, live certs, or host-specific secrets.
- Design details: [PLAN.md](./PLAN.md).

---

## Session Startup

- At the **start of every agent session**, before acting from assumed conventions, read this `AGENTS.md` in full, then read every `alwaysApply: true` rule under `.cursor/rules/*.mdc` (plus any whose `globs` match files you will touch) — `AGENTS.md` and `.cursor/rules/` together are the contract. `CLAUDE.md` (a `@AGENTS.md` import) and `.github/copilot-instructions.md` are thin shims so Claude Code and Copilot reach the same guidance.
Before creating any branch or writing code, initialize the session from the
repository root using [repository-helpers](https://github.com/the-hcma/repository-helpers):

```bash
~/work/ai/repository-helpers/scripts/dev/start-development --refresh
~/work/ai/repository-helpers/scripts/dev/start-development --worktree <stack-name> --no-interactive
```

- **`--refresh`** (first): syncs `main` (marker-aware; this repo is `gh-stack`),
  prunes merged worktrees and branches, pulls latest `main`, then exits.
- **plain / `--worktree`** (second): repeats sync/cleanup, then creates or resumes
  a worktree under `.worktrees/<stack-name>-wt`.
- AI agents must always pass **`--no-interactive`** and an explicit **`--worktree`** name.
- Do not manually create worktrees — `start-development` is the single entry point
  for new work.

---

## Language & Runtime

- Primary artifacts: nginx config, systemd units, Bash install/ops scripts under `scripts/`.
- Target **bash ≥ 5.x** (every script declares `#!/usr/bin/env bash` and uses `set -euo pipefail`).
- **No `.sh` extension.** The shebang declares the interpreter.
- **Language policy**: Bash stays the default for install/ops scripts under
  `scripts/` — prefer it unless a task genuinely needs something Bash can't
  do well. **Python is allowed** (e.g. the service-catalog renderer work in
  [#45](https://github.com/the-hcma/home-warden/issues/45), the private-CA
  tooling in [#49](https://github.com/the-hcma/home-warden/issues/49), the
  Gixy-Next security lint in
  [#50](https://github.com/the-hcma/home-warden/issues/50)) — this
  supersedes the earlier "Milestone 1 stays pure Bash" restriction.
  **TypeScript** is reserved for a future web UI, not install/ops paths.
  The first Python code landing in this repo must also add its own
  linting/formatting conventions here (mirroring the Bash section below),
  plus any CI wiring (`scripts/ci-shellcheck` is Bash-only today) — not
  assumed to inherit the Bash rules as-is.
- External tools as needed: `nginx`, `systemctl`, `git`, `gh`, `openssl`, `certbot`.
- **Remote timeouts and bounded retries:** `.cursor/rules/remote-timeouts-retries.mdc`
  (`alwaysApply`, org rule — template sync
  [repository-helpers#570](https://github.com/the-hcma/repository-helpers/issues/570)).
  Every `curl` **must** set `--max-time` *and* `--connect-timeout`
  (`scripts/healthcheck` sets `--max-time` only today — add `--connect-timeout`);
  `certbot` calls **must** run under a bounded wrapper (`scripts/cert-renewer`
  still needs one); any retry is capped/budgeted, backed off with jitter,
  transient-only, and never blindly re-issues a certificate.

---

## Formatting & Style

- **No automated formatter.** Consistency is enforced by conventions below and by `shellcheck`.
- Indentation: **2 spaces**. Never tabs.
- Line length: soft limit of **100 characters**; hard limit of **120**. Comments may exceed
  only when a long URL would otherwise be broken.
- Function definitions use the `name() {` form (no `function` keyword).
- Opening `{` stays on the same line as the function name or control keyword.
- Always quote variable expansions: `"$var"`, `"${array[@]}"`.
- Prefer `[[` over `[` for conditionals.
- Use `$(...)` for command substitution, never backticks.
- Prefer **long-form flags** (e.g. `--follow=name` not `-f`) when a long form exists.

---

## Linting

- **`shellcheck`** is mandatory for scripts under `scripts/` (and tests when present).
- Zero findings at the `info` level (`shellcheck -S info`) is the bar.
- No `# shellcheck disable=` suppressions unless unavoidable; every suppression needs a
  comment explaining why.
- Key rules that are always errors:
  - **SC2155** — never combine `local`/`readonly` with a command substitution assignment;
    declare separately to preserve the exit code.
  - **SC2015** — never use `A && B || C` as a substitute for `if/then/else`.
  - **SC2086** — always double-quote expansions unless word-splitting is intentional.

---

## Shell Script Conventions

- **`readonly`** for every script-level variable assigned once. Declare and assign on
  separate lines to avoid SC2155:

  ```bash
  var="$(some_command)"
  readonly var
  ```

- **Non-exported variables must be lowercase.** Uppercase is reserved for exported
  environment variables. Script-level constants, loop variables, and function locals use
  `snake_case`.
- **Use `local` for all function-scoped variables.** Prefer `local -r` for parameters or
  literal assignments that will not change. For command substitutions, declare separately:

  ```bash
  my_func() {
    local -r mode="${1:-default}"
    local result
    result="$(some_command)"
  }
  ```

- Prefer `readonly` for **script-level** constants and `local -r` for **function-local**
  constants (`readonly` inside a function leaks globally).
- **Never declare `local` / `local -r` inside a loop body.** Hoist declarations to the top
  of the function.
- Do not use `A && B || C` as an if-then-else substitute (SC2015).

---

## Python Conventions

Python is allowed per the Language & Runtime policy above (service-catalog
tooling in [#45](https://github.com/the-hcma/home-warden/issues/45)/[#54](https://github.com/the-hcma/home-warden/issues/54)/[#57](https://github.com/the-hcma/home-warden/issues/57),
private-CA tooling in [#49](https://github.com/the-hcma/home-warden/issues/49),
the Gixy-Next security lint in [#50](https://github.com/the-hcma/home-warden/issues/50)).
These conventions are established here as required by that policy's "first
Python code" clause.

Follows [the-hcma/domesti-bot](https://github.com/the-hcma/domesti-bot)'s
established Python conventions rather than inventing a second, divergent
set for the org — this repo's needs are a small subset of domesti-bot's, so
adopt the shape, not its full scale (no browser-launching, LAN-banner, or
device-manager machinery here).

- **Package layout**: importable code lives under `app/` (plus `config/`
  for the server entrypoint), matching domesti-bot — not loose scripts
  under `scripts/`. `scripts/` keeps its existing role (thin, no-extension
  Bash entry points) but a Python one now just shells out via `uv run`
  (e.g. `exec uv run catalog-health-check "$@"`) rather than being the
  implementation itself.
- **`uv`** is the dependency manager — `pyproject.toml` + `uv.lock`, both
  committed. Target **Python ≥ 3.12** (`.python-version` pins the exact
  dev version). `uv sync --group dev` installs everything, including test
  and lint tooling.
- **FastAPI + uvicorn** for any HTTP surface (e.g. the-hcma/home-warden#57's
  catalog-health endpoint) — `app/api/app.py`'s `create_app()` factory,
  routes as `APIRouter`s under `app/api/*_routes.py`, one process serving
  all of them rather than a service per endpoint.
- **Type hints** on function signatures, enforced via **`pyright`**
  (`basic` mode, `pyrightconfig.json`) in CI — matching domesti-bot.
- **`ruff`** (`[tool.ruff]` in `pyproject.toml`: `line-length = 120`,
  `target-version = "py312"`, `format.quote-style = "double"`,
  `lint.select = ["E", "F", "I"]`) is mandatory for both linting and
  formatting — mirrors domesti-bot's config verbatim. Zero findings is the
  bar, matching shellcheck's `-S info` bar for Bash. A `# noqa: <code>`
  suppression needs a comment explaining why, same rule as Bash's
  `# shellcheck disable=`.
- **`pytest`** (`tests/python/`, `test_*.py`) — not stdlib `unittest`,
  matching domesti-bot. **`httpx2`** (not `httpx`) + FastAPI's
  `TestClient` for route tests — Starlette's `testclient` does `import
  httpx2 as httpx` internally and prefers it (using plain `httpx` there
  is the deprecated path); `httpx2` is the only HTTP-client package
  actually in `uv.lock`.
  Mock/stub any real network or subprocess call (Cloudflare API,
  `openssl`, `certbot`); tests must not depend on live infrastructure or
  credentials.
- **Remote timeouts and bounded retries** apply identically to Python as
  to Bash — see the rule cited in Language & Runtime above. Every
  `urllib.request`/`socket` call sets an explicit timeout; no unbounded
  retry loop.
- CI wiring lives under `.github/ci/` (`setup-python`, `ruff`, `pytest`),
  mirroring both domesti-bot's own `.github/ci/*` scripts and this repo's
  existing `.github/ci/secret-scan` — see
  [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

---

## Development

```bash
# Config syntax (when nginx is installed):
nginx -t -c "$PWD/nginx/nginx.conf"

# Host install (prompts for sudo; validates nginx -t before start):
./scripts/setup-service

# Org practices:
~/work/ai/repository-helpers/scripts/github-repo-lint --repo the-hcma/home-warden --suggest
```

---

## Commits, Stacking & Pull Requests

- This project uses **GitHub Stacked PRs (`gh stack`)**
  (`.github/stacking-tool` = `gh-stack`). Canonical skill:
  [repository-helpers gh-stack](https://github.com/the-hcma/repository-helpers/blob/main/.cursor/skills/gh-stack/SKILL.md).
- **Worktree-per-stack.** Every new stack is created via
  `start-development --worktree <name> --no-interactive`.
- Never work directly on `main`. Prefer
  `~/work/ai/repository-helpers/scripts/dev/submit-stack` (dispatches via the
  stacking marker), or `gh stack init` / `gh stack add` / `gh stack submit`.
- Keep each branch focused on one logical change.
- **Do not** use Graphite (`gt`) or the `merge-it` label in this repo.
- Merge path: **GitHub native merge queue** on `main` (squash). Stacked PRs must be
  landed via the GitHub UI stack merge (CLI `--auto` is blocked for stacks).
- Follow **Conventional Commits**: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
- PR descriptions must include **Summary** and **Test plan** at minimum.

---

## Repository Practices

Run from [repository-helpers](https://github.com/the-hcma/repository-helpers):

```bash
scripts/github-repo-lint --repo the-hcma/home-warden --suggest
```

---

## CI Checks (all must pass)

CI lives in `.github/workflows/ci.yml`:

- Guard (gtmq / CodeRabbit / push-dedup)
- Secret scan (`.github/ci/secret-scan`)
- Validate (required files + optional `nginx -t`)
- Python (`.github/ci/ruff` + `.github/ci/pytest` + `.github/ci/pyright`, via `uv`)

No PR may be merged with a failing CI check.

---

## Pre-Commit Checklist

- [ ] `bash -n` / `shellcheck -S info` on changed Bash scripts under `scripts/`
- [ ] `uv run ruff check app config tests scripts` / `uv run ruff format
      --check app config tests scripts`, `uv run pytest`, and `uv run
      pyright` pass on changed Python
- [ ] `nginx -t` when config changed (local nginx 1.28.x preferred)
- [ ] No certs, keys, or secrets in the diff
- [ ] Commit message follows Conventional Commits
- [ ] Unit templates keep `@@REPO_DIR@@` / `@@OWNER@@` placeholders until setup expands them
