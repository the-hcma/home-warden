# home-warden

[![CI](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Unprivileged **nginx** front door for home services: systemd binds ports **80/443**,
hands the sockets to nginx via `NGINX=` fd inheritance, and a certbot timer renews
TLS. Target: **Ubuntu 26**, nginx **1.28.3**.

> Status: **live** on the designated host — socket-activated nginx, automatic
> config-watch reload, DNS-01 cert renewal, and healthcheck email alerting are
> all running. See [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md)
> for how it works and [PLAN.md](./PLAN.md) for the original design.

## Why

Sibling apps (bunnify, domesti-bot, …) run as systemd **user** linger services on
high ports. Exposing them on the public Internet needs a reverse proxy with TLS.
home-warden owns that role without keeping a root nginx process.

The longer-term goal: a one-stop front door for all home services, local and
remotely reachable — nginx + TLS termination (live today), public cert
management (live today), and eventually DNS itself. See
[PLAN.md](./PLAN.md#vision-beyond-v1).

## What it does

- **Socket-activated nginx** (`home-warden.socket` + `home-warden.service`) —
  binds 80/443 as root, runs workers as an unprivileged user; distro nginx
  masked so nothing else competes for the ports.
- **Automatic config-watch reload** (`home-warden-reload.path`) — edits to the
  home nginx conf trigger `nginx -t` then a reload; bad syntax never reaches
  live workers.
- **Cert renewal** (`home-warden-certbot.timer`, daily) — DNS-01 via
  Cloudflare, `scripts/cert-renewer`, reloads nginx after a successful renew.
- **Healthcheck email alarms** (`home-warden-healthcheck.timer`, every minute)
  — probes the live service and HTTPS endpoint; emails on failure and
  recovery.
- **Host-pinned by design** — every mutating script refuses to run anywhere
  but the one host it's been explicitly confirmed on
  (`scripts/lib/host-guard`); see
  [Designated host](./docs/host-prerequisites.md#designated-host).

## Docs

| Doc | Purpose |
| --- | --- |
| [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md) | How socket activation works; security posture and known gaps |
| [docs/host-prerequisites.md](./docs/host-prerequisites.md) | Ubuntu 26 host install, day-2 ops, unit reference |
| [PLAN.md](./PLAN.md) | Original design rationale, phases, open questions |
| [AGENTS.md](./AGENTS.md) | Contributor / agent ground rules |
| [services.json.example](./services.json.example) | Service-catalog schema reference ([#45](https://github.com/the-hcma/home-warden/issues/45), design in progress — no renderer yet) |

## Install (service host)

```bash
# Config source of truth: thehcma/home → nginx/server/nginx.conf
# Optional: HOME_NGINX_CONF=/path/to/nginx/server/nginx.conf
./scripts/bootstrap                # verify prerequisites
./scripts/bootstrap --fix-packages # optional: sudo apt-get install -y missing packages
./scripts/bootstrap --fix          # optional: scratch, dhparam, staging certs
./scripts/setup-service            # nginx -t, install units, start service
systemctl status home-warden.socket home-warden.service
```

## Quick status

```bash
./scripts/setup-service --status
systemctl status home-warden.socket home-warden.service \
  home-warden-certbot.timer home-warden-reload.path \
  home-warden-healthcheck.timer --no-pager
systemctl list-timers home-warden-certbot.timer home-warden-healthcheck.timer
```

## Development

```bash
~/work/ai/repository-helpers/scripts/dev/start-development --refresh
~/work/ai/repository-helpers/scripts/dev/start-development --worktree <stack> --no-interactive
```

Stacking is **`gh-stack`**; merges land via **GitHub’s merge queue**
(`gh pr merge --auto --squash`). See [AGENTS.md](./AGENTS.md).

CI validates tracked files and runs `nginx -t`.

## License

MIT — see [LICENSE](./LICENSE).
