# AGENTS.md — Ground Rules for home-warden

This file defines the standards for all contributors (human or AI) working on this
codebase. Every change must comply with these rules before it is considered complete.

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

- **`--refresh`** (first): syncs `main` with Graphite (`gt sync`), prunes merged
  worktrees and branches, pulls latest `main`, then exits.
- **plain / `--worktree`** (second): repeats sync/cleanup, then creates or resumes
  a worktree under `.worktrees/<stack-name>-wt`.
- AI agents must always pass **`--no-interactive`** and an explicit **`--worktree`** name.
- Do not manually create worktrees or run `gt sync` separately — `start-development`
  is the single entry point for new work.

---

## Language & Runtime

- Primary artifacts: nginx config, systemd units, Bash install/ops scripts.
- Prefer POSIX-friendly Bash with `set -euo pipefail` in scripts under `scripts/`.
- No Python/Node package manager required for v1; do not add one without updating CI.

---

## Development

```bash
# Config syntax (when nginx is installed):
nginx -t -c "$PWD/nginx/nginx.conf"

# Org practices:
~/work/ai/repository-helpers/scripts/github-repo-lint --repo the-hcma/home-warden --suggest
```

---

## Commits, Stacking & Pull Requests

- This project uses **Graphite (`gt`)** for branch stacking
  (`.github/stacking-tool` = `graphite`).
- **Worktree-per-stack.** Every new stack is created via
  `start-development --worktree <name> --no-interactive`.
- Never work directly on `main`. Create stacked branches with
  `gt create <stack>/<description> -m "feat: ..."`.
- Keep each branch focused on one logical change.
- Submit with `gt submit --no-interactive --publish`.
- To merge, add the `merge-it` label: `gh pr edit <number> --add-label merge-it`.
  Never use `gh pr merge` directly.
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

- [ ] `nginx -t` when config changed (local nginx 1.28.x preferred)
- [ ] No certs, keys, or secrets in the diff
- [ ] Commit message follows Conventional Commits
- [ ] Unit templates keep `@@REPO_DIR@@` / `@@OWNER@@` placeholders until setup expands them
