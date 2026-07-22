# home-warden

[![CI](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/home-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Unprivileged **nginx** front door for home services: systemd binds ports **80/443**,
hands the sockets to nginx via `NGINX=` fd inheritance, and a certbot timer renews
TLS. Target: **Ubuntu 26**, nginx **1.28.3**.

> Status: planning / bootstrap. See [PLAN.md](./PLAN.md).

## Why

Sibling apps (bunnify, domesti-bot, …) run as systemd **user** linger services on
high ports. Exposing them on the public Internet needs a reverse proxy with TLS.
home-warden owns that role without keeping a root nginx process.

## Docs

| Doc | Purpose |
| --- | --- |
| [PLAN.md](./PLAN.md) | Architecture, unit sketches, phases, risks |
| [AGENTS.md](./AGENTS.md) | Contributor / agent ground rules |

## Quick status

```bash
# After install (phase 2+):
systemctl status home-warden.socket home-warden.service
systemctl list-timers home-warden-certbot.timer
```

## Development

```bash
~/work/ai/repository-helpers/scripts/dev/start-development --refresh
~/work/ai/repository-helpers/scripts/dev/start-development --worktree <stack> --no-interactive
```

CI validates tracked files and runs `nginx -t` when nginx is available (or skips
gracefully in environments without the package).

## License

MIT — see [LICENSE](./LICENSE).
