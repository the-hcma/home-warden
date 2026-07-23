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
- No Node.js helpers and no Python scripting for install/ops paths unless CI and
  AGENTS are updated deliberately (Milestone 1 stays pure Bash).
- External tools as needed: `nginx`, `systemctl`, `git`, `gh`, `openssl`, `certbot`.

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

No PR may be merged with a failing CI check.

---

## Pre-Commit Checklist

- [ ] `bash -n` / `shellcheck -S info` on changed scripts under `scripts/`
- [ ] `nginx -t` when config changed (local nginx 1.28.x preferred)
- [ ] No certs, keys, or secrets in the diff
- [ ] Commit message follows Conventional Commits
- [ ] Unit templates keep `@@REPO_DIR@@` / `@@OWNER@@` placeholders until setup expands them
