# home-warden

[![CI](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Unprivileged **nginx** front door for home services: systemd binds ports **80/443**,
hands the sockets to nginx via `NGINX=` fd inheritance, and a certbot timer renews
TLS. Target: **Ubuntu 26**, nginx **1.28.3**.

> Status: Milestone 1 in progress — system socket activation + setup-service.
> See [PLAN.md](./PLAN.md) and [issue #2](https://github.com/the-hcma/home-warden/issues/2).

## Why

Sibling apps (bunnify, domesti-bot, …) run as systemd **user** linger services on
high ports. Exposing them on the public Internet needs a reverse proxy with TLS.
home-warden owns that role without keeping a root nginx process.

## Docs

| Doc | Purpose |
| --- | --- |
| [PLAN.md](./PLAN.md) | Architecture, unit sketches, phases, risks |
| [AGENTS.md](./AGENTS.md) | Contributor / agent ground rules |
| [docs/host-prerequisites.md](./docs/host-prerequisites.md) | Ubuntu 26 host install / proof steps |

## Install (service host)

```bash
# Config source of truth: thehcma/home → nginx/server/nginx.conf
./scripts/setup-service
nginx -p "$HOME/scratch/home-warden/" -t -c /path/to/home/nginx/server/nginx.conf
sudo systemctl start home-warden.service
systemctl status home-warden.socket home-warden.service
```

## Quick status

```bash
systemctl status home-warden.socket home-warden.service
# Certbot timer arrives in a later milestone:
# systemctl list-timers home-warden-certbot.timer
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
