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

## Nginx Security Lint (Gixy-Next)

[Gixy-Next](https://gixy.io) (PyPI: `Gixy-Next`, the maintained fork of
Yandex's unmaintained `gixy`) statically analyzes nginx config for security
misconfigurations (SSRF via unescaped `proxy_pass` variables, `server_tokens`
version disclosure, ReDoS-prone regexes, `add_header`/`Content-Type`
footguns, …) that `nginx -t` does not catch — `nginx -t` only validates
syntax. See [#50](https://github.com/the-hcma/home-warden/issues/50).

- **Dependency**: pinned in a dedicated `lint` uv dependency group (not
  `dev`) — it's an nginx-specific static analyzer, not part of this repo's
  general Python lint/format/type-check chain. `uv sync --group lint`
  installs it (in addition to the default `dev` group).
- **Entry point**: `scripts/nginx-security-lint` — shells out to
  `uv run --group lint gixy`, defaulting to this repo's own
  `nginx/nginx.conf` (the CI-only syntax fixture). Point `HOME_NGINX_CONF`
  at `thehcma/home`'s `nginx/server/nginx.conf` to lint the actually-served
  config on the service host.
- **Severity handling: fail-closed.** Unlike an advisory-only lint, a
  Gixy-Next finding at or above `GIXY_LEVEL` (default `LOW`, i.e. every
  finding) **blocks** — the same way a failed `nginx -t` blocks
  `scripts/setup-service`/`scripts/nginx-test-and-reload` and CI. This was
  a deliberate choice made once the ruleset's false-positive rate against
  this repo's actual conf was known to be zero (the two findings it did
  raise here — `server_tokens` disclosure, `add_header Content-Type`
  instead of `default_type` — were real, fixed outright, not suppressed).
  Revisit to advisory-only if a future finding on the real served config
  turns out to be a persistent false positive with no clean fix.
- **CI wiring**: `.github/ci/nginx-security-lint`, run as its own
  `nginx-security-lint` job in `.github/workflows/ci.yml` (parallel to
  `python-static`/`python-test`, not folded into either — it has its own
  uv dependency group and a materially different failure mode).
- **`GIXY_SKIPS`**: comma-separated Gixy-Next test names to pass through
  to `--skips`, for a narrow, *documented* exception only — not a way to
  silence a finding without a reason. Empty by default (this repo's own
  `nginx/nginx.conf` fixture runs with zero skips, zero findings). The one
  place this repo does set it is `.github/ci/catalog-render-validate` (see
  the Service Catalog Renderer section below), which accepts exactly two
  findings against the renderer's realistic output: `proxy_buffering_off`
  (inherent to websocket support — a persistent connection can't be
  buffered) and `proxy_pass_normalized` (every `proxy_pass` the renderer
  emits has a fixed, catalog-declared path behind a whole-vhost
  `location /` — the schema's documented behavior, not an accident).

---

## Service Catalog Renderer

`app/catalog_render.py` (CLI: `render-catalog`, wrapper:
`scripts/render-catalog`) renders a `services.json` catalog into nginx
config via [crossplane](https://github.com/nginxinc/crossplane), so the
catalog — not hand-edited nginx — is the source of truth for served
vhosts. See [#54](https://github.com/the-hcma/home-warden/issues/54).

- **Scope**: emits only `http {}` (maps + one `server` per proxy/static
  service) and, when the catalog has any, `stream {}` — not a full
  standalone `nginx.conf`. `worker_processes`/`events`/`pid`/`error_log`
  live in the served config's own skeleton (outside this repo), which
  `include`s the rendered output.
- **Shared template settings** (`RenderContext`: `client_max_body_size`,
  `server_tokens_off`, `ssl_protocols`) are deliberately *not* part of the
  catalog schema — a catalog entry describes what to serve, `RenderContext`
  describes how every vhost is secured/tuned. `server_tokens_off` defaults
  to `True` (the Gixy-Next `version_disclosure` fix from the Nginx
  Security Lint section above, applied once at the `http` level here).
- **`default_server`**: the first service in the catalog gets
  `listen 443 ssl default_server;` — with multiple https vhosts and no
  explicit default, nginx silently falls back to definition order anyway;
  this makes that choice an explicit, documented renderer property
  instead of an accident of catalog ordering (also resolves Gixy-Next's
  `default_server_flag`).
- **Validation**: `.github/ci/catalog-render-validate` renders a
  dedicated CI-only fixture catalog (not `services.json.example`, whose
  paths are intentionally fake per `.cursor/rules/no-private-infra.mdc`)
  with real generated self-signed certs/CA/CRL, wraps it in a minimal
  skeleton, and runs both `nginx -t` and `scripts/nginx-security-lint`
  (with the two `GIXY_SKIPS` above) against the assembled config. Wired as
  its own `catalog-render-validate` CI job.

---

## Local DNS (PowerDNS)

home-warden runs the local authoritative PowerDNS tooling (`pdns-server` +
`pdns-recursor`, per PLAN.md's "Vision beyond v1") that `thehcma/home`
previously hand-rolled — this repo owns the converter/runtime tooling, not
the served zone data (which stays in `thehcma/home` under `dns/`, the same
split this repo already uses for nginx's own served config). See
[#108](https://github.com/the-hcma/home-warden/issues/108) and the design
work in `thehcma/home#16` (private repo) it relocates.

- **Converter**: `app/dns_tinydns_convert.py` (CLI: `dns-tinydns-convert`,
  wrapper: `scripts/dns-tinydns-convert`) is a one-off migration tool —
  parses tinydns-format zone data (exactly the record types SOA `Z`, NS
  `&` with optional glue A, A+PTR `=`, A-only `+`, TXT `'`, CNAME `C`, and
  SRV via the generic `:` record type `33`; fails loudly on anything
  else) and renders PowerDNS's GeoIP-backend `zones.yml` + a matching
  `pdns.conf`. TXT record `content` always includes literal surrounding
  quotes — confirmed by actually running a converted record through a
  real `pdns_server` (see Validation below), not assumed from docs.
- **Design ported from `thehcma/home#16`**: `launch=geoip` backend, no
  MaxMind/geo expansions (plain `records:` only), and the authoritative
  server listens on **loopback:853 only** — the (separately maintained)
  recursor is what answers the real `:53`, forwarding queries for these
  zones to loopback:853. DNSSEC and geo-routing are explicitly out of
  scope, matching #16.
- **Validation — two tiers**, per this repo's "validate by actually
  running it" standard (mirrors Service Catalog Renderer's `nginx -t`,
  not just schema checks):
  - `app/dns_zone_validate.py`'s `validate_via_sqlite_backend` is
    backend-independent: it loads parsed records into an ephemeral
    `pdns_server` (gsqlite3 backend, via `pdnsutil zone load`) and
    dig-verifies every record. Runs anywhere `pdns_server`/`pdnsutil`/
    `sqlite3`/`dig` are installed, including local dev on macOS via
    `brew install pdns` — proves the *record data* is DNS-correct, not
    the exact GeoIP-YAML shape (Homebrew's `pdns` bottle doesn't ship the
    `geoip` module).
  - `.github/ci/dns-catalog-validate` is the real acceptance test for the
    GeoIP YAML shape itself: installs the actual `pdns-server` +
    `pdns-backend-geoip` Ubuntu packages, converts a CI-only tinydns
    fixture, runs the genuinely-generated `zones.yml`/`pdns.conf` through
    a real `pdns_server`, and `dig`-verifies every record type. Wired as
    its own `dns-catalog-validate` CI job.
- **Dedicated account**: already handled by the distro. Debian/Ubuntu's
  `pdns-server` package creates its own `pdns` system account (via
  `adduser` in its postinst) and runs `pdns.service` as that account by
  default — home-warden does not author a privilege-separation unit for
  pdns the way it did for nginx (whose socket-activation trick solves a
  problem the distro packaging already solves here).
- **Reload-on-edit**: `scripts/pdns-test-and-reload` (triggered by
  `etc/systemd/home-warden-pdns-reload.path`) runs a lightweight, offline
  `dns-zones-yaml-check` syntax/shape gate
  (`app.dns_tinydns_convert.validate_zones_yaml_syntax` — catches a typo,
  not a deeper semantic mistake) before `pdns_control reload` — not
  `systemctl reload pdns.service`, which the distro-packaged unit doesn't
  implement at all. This ordering (syntax gate before reload, never the
  reverse, with an unknown `PDNS_SERVICE` unit failing loudly rather than
  silently skipping) is pinned by the `pdns-reload-gate-test` CI job
  against stub `systemctl`/`pdns_control` binaries. `scripts/setup-service`
  installs and enables these reload units automatically, opt-in via
  `PDNS_ZONES_YAML` (skipped, not an error, when unset and the default
  `~/home/dns/zones.yml` doesn't exist either) — see
  docs/dns-tinydns-migration.md.
- Full usage, packages, install/reload steps, the record-mapping
  reference table, and the validation workflow:
  [docs/dns-tinydns-migration.md](./docs/dns-tinydns-migration.md).

---

## Service Registration Orchestration

`app/catalog_register.py` (CLI: `catalog-register`, wrapper:
`scripts/catalog-register --service <name>`) drives one already-catalogued
service's local DNS, external DNS, cert, and final nginx-render validation
in the order a new service actually needs, wiring together
[#108](https://github.com/the-hcma/home-warden/issues/108)'s local DNS,
[#109](https://github.com/the-hcma/home-warden/issues/109)'s Cloudflare
sync, `scripts/cert-renewer`, and `app.catalog_crud`'s existing
validate/preview pipeline. See
[#110](https://github.com/the-hcma/home-warden/issues/110).

- **Staging order — internal name, then upstream, then external name**:
  1. `local_dns` — **verify only** that `upstream.host` (the private/local
     name nginx's own `proxy_pass` depends on — distinct from
     `server_name`, the public name) already resolves via the local
     PowerDNS zone (#108). A missing record fails with "add it by hand and
     reload first" — this module never creates one; whatever stands up the
     backend owns registering its own local name. Skipped for `static`-kind
     services (no upstream) and for a literal IP `upstream.host` (no DNS
     needed). Also skipped, not failed, when this host has no local
     PowerDNS reachable at all (mirrors `#108`'s own opt-in design).
  2. `upstream` — verify the backend itself is actually reachable
     (`app.catalog_checks.check_upstream`, reused as-is) before touching
     anything public.
  3. `external_dns` — create/update the public Cloudflare record for
     `server_name` (`app.catalog_checks.sync_dns_record`, reused as-is).
  4. `cert` — ensure `server_name` is listed in `conf/certbot-domains`
     (appended if missing), then invokes `scripts/cert-renewer`
     **unchanged** — that script already handles DNS-01 propagation wait
     (`DNS_CLOUDFLARE_PROPAGATION_SECONDS`) internally, so this step adds
     no propagation-wait logic of its own.
  5. `nginx` — final `nginx -t` + Gixy-Next validation against the full
     catalog via `app.catalog_crud.render_preview` — the **same**
     validate/preview pipeline the web UI's own catalog edits already use
     (`#69`), not a separate implementation. This module stops at
     `services.json`/preview validation; it does not deploy the rendered
     config to the live served nginx.conf or trigger a reload — that gap
     exists for every catalog edit today, not something specific to this
     flow, and stays out of scope here.
- **Fail-fast, not auto-healing**: each step is a precondition check for
  the next. A failure stops the pipeline immediately and reports what to
  fix by hand — this is provisioning, matching this repo's established
  "fail loud and stop" posture (`scripts/cert-renewer`,
  `scripts/pdns-test-and-reload`), not a retry-until-it-works loop.
- **Confirm-first**: `apply=False` (the CLI default, no `--apply` flag) is
  a full dry-run preview of every step — nothing changes. Re-run with
  `--apply` once the plan looks right. Mirrors
  `app.catalog_checks.sync_dns_record`'s own `dry_run` parameter rather
  than an interactive y/n prompt, consistent with every other Python CLI
  in this repo.
- `app.catalog_checks.check_local_dns` (the `local_dns` step's check) is
  also wired into `run_all`/`catalog-health-check`/`GET /health/catalog`
  as a fourth read-only dimension alongside `cert`/`dns`/`upstream` — the
  same function this module uses as a precondition also gives #57's
  ongoing health checks local-DNS coverage for internal-only services, per
  #108's own "depended on by #57" note.

---

## Web UI

home-warden's first-party admin web UI
([#55](https://github.com/the-hcma/home-warden/issues/55), scaffolded in
[#67](https://github.com/the-hcma/home-warden/issues/67)) follows
[the-hcma/domesti-bot](https://github.com/the-hcma/domesti-bot)'s `web/`
conventions as its structural/governance model — this repo's needs are a
small subset of domesti-bot's, so adopt the shape, not its full scale.

- **Layout**: TypeScript sources live under `web/src/`, bundled by a single
  `web/build.mjs` esbuild call — no Vite/Webpack/Rollup, and **no frontend
  framework** (React/Vue/Svelte/etc.). The first concrete proposal to add
  one must call this out explicitly and update this section as part of
  the same PR, matching domesti-bot's own rule. Output goes to
  `app/api/static/dist/main.js` (stable filename; no content-hashing yet)
  — served by the existing FastAPI app (`app/api/app.py`) via a
  `StaticFiles` mount at `/static/`, with `GET /` reading
  `app/api/static/index.html` from disk on every request (so local edits
  show up without a restart). `app/api/static/dist/` is gitignored (build
  output only); `app/api/static/` itself (HTML, future icons) is tracked.
- **Toolchain**: `pnpm` (pinned via `web/package.json`'s `packageManager`
  field, currently `pnpm@10.33.4`) + `esbuild` (bundling) + `typescript`
  (`tsc --noEmit` only — esbuild does the actual emit). `engines.node`
  requires `>=20`; Node is a **build-time-only** dependency, never a
  runtime one — the FastAPI/uvicorn server has zero Node dependency.
  `web/tsconfig.json` is strict: `strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `isolatedModules`,
  `noImplicitOverride`, `noFallthroughCasesInSwitch`,
  `forceConsistentCasingInFileNames`.
- **Day to day** (from `web/`): `pnpm install`, `pnpm run typecheck`,
  `pnpm run build` (one-shot) / `pnpm run watch` (rebuild on change, dev
  only), `pnpm run check` (typecheck + build, mirrors CI).
- **CI**: `.github/ci/web-build` runs `pnpm install --frozen-lockfile` +
  `pnpm run typecheck` + `pnpm run build`, then asserts
  `app/api/static/dist/main.js` exists (catches a silent esbuild
  misconfiguration in CI instead of a mysterious 404 in production).
  Wired as its own `web-build` job in `.github/workflows/ci.yml`, using
  `actions/setup-node` + the shared
  `the-hcma/repository-helpers/actions/setup-pnpm-corepack` action (same
  as domesti-bot's own `web-build` job).
- **Dependabot**: a dedicated `npm` / `/web` entry in
  `.github/dependabot.yml`, grouped by package (`typescript`, `esbuild`)
  to reduce PR noise — separate from the existing `github-actions` entry.
- **Auth and transport**: PAM-backed login lands in #68 via the
  `python-pam` dependency (plus a direct `six` pin because that package's
  published metadata omits it), a short-lived signed session cookie
  (`HttpOnly`, `Secure`, `SameSite=Strict`) stored by FastAPI/Starlette,
  and a persistent signing secret in
  `$XDG_CONFIG_HOME/home-warden/session-secret` (default
  `~/.config/home-warden/session-secret`). The backend stays loopback-only;
  nginx remains the only supported TLS/public entrypoint.
- **Operator config**: the web UI is opt-in through
  `$XDG_CONFIG_HOME/home-warden/config.toml` (default
  `~/.config/home-warden/config.toml`), read with stdlib `tomllib`.
  Today this file carries only `fqdn = "warden.example.com"`; missing,
  empty, or malformed TOML disables the self-catalog web-ui vhost instead
  of crashing startup. Existing env-var settings in
  `app/catalog_health_settings.py` are intentionally still env-driven
  until a later migration issue lands.

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
- Python (`.github/ci/python-static` [ruff + pyright] + `.github/ci/pytest`, via `uv`)
- Nginx security lint (`.github/ci/nginx-security-lint` — Gixy-Next, see above)
- Catalog render validate (`.github/ci/catalog-render-validate` — renders a
  fixture catalog, runs `nginx -t` + Gixy-Next against it, see above)
- DNS catalog validate (`.github/ci/dns-catalog-validate` — converts a
  tinydns fixture, runs the real `pdns-backend-geoip` + `dig` against it,
  see Local DNS above)
- pdns reload gate test (`.github/ci/pdns-reload-gate-test` — runs
  `scripts/pdns-test-and-reload` against stub `systemctl`/`pdns_control`
  binaries to pin its fail-closed ordering, see Local DNS above)
- Web (`.github/ci/web-build` — pnpm typecheck + esbuild build, see Web UI above)

No PR may be merged with a failing CI check.

---

## Pre-Commit Checklist

- [ ] `bash -n` / `shellcheck -S info` on changed Bash scripts under `scripts/`
- [ ] `uv run ruff check app config tests scripts` / `uv run ruff format
      --check app config tests scripts`, `uv run pytest`, and `uv run
      pyright` pass on changed Python
- [ ] `nginx -t` when config changed (local nginx 1.28.x preferred)
- [ ] `./scripts/nginx-security-lint` clean when `nginx/nginx.conf` (or
      `HOME_NGINX_CONF`) changed
- [ ] `uv run render-catalog` output still round-trips through
      `crossplane.parse()` clean when `app/catalog_render.py` changed
- [ ] `uv run pytest tests/python/test_dns_zone_validate.py -v` shows the
      real-`pdns_server` tests actually ran (not skipped) when
      `app/dns_tinydns_convert.py` or `app/dns_zone_validate.py` changed
      (install PowerDNS locally — `brew install pdns` on macOS — if they
      show as skipped)
- [ ] `pnpm run check` (typecheck + build) clean from `web/` when
      `web/` changed
- [ ] No certs, keys, or secrets in the diff
- [ ] Commit message follows Conventional Commits
- [ ] Unit templates keep `@@REPO_DIR@@` / `@@OWNER@@` placeholders until setup expands them
