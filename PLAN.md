# home-warden — Implementation Plan

## Overview

Run **nginx as an unprivileged user** on Ubuntu 26 (nginx **1.28.3**), with
systemd binding privileged ports **80/443** and handing already-open fds to
nginx via its undocumented `NGINX=` socket-inheritance mechanism. A companion
certbot oneshot + timer renews certificates and reloads nginx.

This is the reverse-proxy / TLS front door for sibling home services
(bunnify, domesti-bot, my-tracks, fpdf, …). Unlike those siblings’ **user linger**
units, privileged-port socket activation lives in the **system** manager, with
the service dropping to the unprivileged owner.

**Target host:** Ubuntu 26 · nginx 1.28.3 · systemd socket activation.

---

## Goals

| Goal | Approach |
| --- | --- |
| Bind 80/443 without running nginx as root | System `.socket` units → inherit fds in service |
| Process runs as the home user | `User=` / `Group=` on the system `.service` |
| Cert renewal without a long-lived root agent | `home-warden-certbot.service` + `.timer` |
| Config owned by the user | Tree under this repo; pid/temp/logs under `~/scratch/home-warden/` |
| Install story like siblings | `scripts/setup-service` (system units via sudo) + host guards |

Non-goals for v1: shipping a full site catalog, multi-host HA, or replacing
sibling apps’ own listen ports (they stay on high ports; nginx proxies to them).

---

## Architecture

```
Internet
   │
   ▼
systemd (root) ── home-warden.socket
   ListenStream=80
   ListenStream=443
   │
   │  (pass fds 3, 4; Environment=NGINX=3:4;)
   ▼
home-warden.service   User=<owner>
   /usr/sbin/nginx -c …/nginx.conf -g 'daemon off;'
   │
   ├─► proxy_pass http://127.0.0.1:8001  (bunnify)
   ├─► proxy_pass http://127.0.0.1:8003  (domesti-bot)
   └─► … other upstreams
   │
home-warden-certbot.timer
   └─► oneshot: certbot renew → deploy-hook reload nginx
```

### Why not user linger alone?

User systemd cannot bind ports &lt; 1024 without capabilities. A **system**
`.socket` also cannot activate a **user** `.service`. So the front door is
system socket + system service as `User=`; sibling apps remain linger user units
on high ports.

### nginx socket inheritance

Stock nginx does not honor `LISTEN_FDS`. It reuses the internal reload socket
map via:

```ini
Environment=NGINX=3:4;
```

`listen 80;` / `listen 443 ssl;` in config must match the bound addresses.
Documented by [systemd.io Daemon Socket Activation](https://systemd.io/DAEMON_SOCKET_ACTIVATION/).
Treat `NGINX=` as stable-in-practice but undocumented; dual-stack and reload
must be tested on Ubuntu 26 / 1.28.3 before calling the design done.

---

## Repository layout (planned)

```
home-warden/
├── PLAN.md                 # this document
├── README.md
├── AGENTS.md
├── LICENSE
├── nginx/
│   ├── nginx.conf          # main config (user paths for pid, temp, logs)
│   ├── conf.d/             # per-vhost / upstream snippets
│   └── snippets/           # ssl params, security headers, …
├── webroot/                # ACME http-01 challenge root
├── etc/systemd/
│   ├── home-warden.socket
│   ├── home-warden.service
│   ├── home-warden-certbot.service
│   └── home-warden-certbot.timer
└── scripts/
    ├── setup-service       # install system units (sudo), enable linger N/A
    ├── nginx-test          # nginx -t wrapper for CI / pre-reload
    └── on-deploy           # optional: validate config, signal restart
```

Live certs and private keys stay **outside** git (`~/scratch/home-warden/certs/`
or Let’s Encrypt live paths readable by the service user).

---

## Unit sketches

### `home-warden.socket`

```ini
[Unit]
Description=home-warden nginx sockets (80/443)

[Socket]
ListenStream=80
ListenStream=443
BindIPv6Only=ipv6-only
FreeBind=true

[Install]
WantedBy=sockets.target
```

Exact `ListenStream=` / dual-stack pairing must be validated so `NGINX=3:4;`
lines up with `listen` directives (IPv4 + IPv6 may need four fds).

### `home-warden.service`

```ini
[Unit]
Description=home-warden nginx (unprivileged)
Requires=home-warden.socket
After=network.target home-warden.socket

[Service]
Type=simple
User=@@OWNER@@
Group=@@OWNER@@
Environment=NGINX=3:4;
ExecStart=/usr/sbin/nginx -c @@REPO_DIR@@/nginx/nginx.conf -g 'daemon off;'
ExecReload=/usr/sbin/nginx -s reload
Restart=on-failure
RestartSec=5
# pid / temp paths must be writable by User= (set in nginx.conf)

[Install]
WantedBy=multi-user.target
```

### Certbot

- Challenge: **webroot** at `@@REPO_DIR@@/webroot` (or dns-01 via existing
  Cloudflare tooling when HTTP-01 is awkward).
- `home-warden-certbot.service`: oneshot `certbot renew --webroot …`
- Deploy hook: `systemctl reload home-warden.service`
- `home-warden-certbot.timer`: daily (or twice-daily) with Persistent=true

Certbot may need limited sudo or membership in a group that can `reload` the
system unit; prefer a dedicated sudoers drop-in over running the timer as root
longer than necessary.

---

## Implementation phases

| # | Phase | Deliverable |
| --- | --- | --- |
| 0 | Repo bootstrap | This plan, org practices scaffolding, CI smoke; **gh-stack** + GitHub MQ |
| 1 | Minimal nginx.conf | User-writable pid/temp/log paths; `nginx -t` in CI |
| 2 | Systemd units + setup-service | Install to `/etc/systemd/system/`, host guards |
| 3 | Socket-activation proof | Bind 80/443 on a lab host; confirm `NGINX=` fds |
| 4 | TLS + certbot timer | First cert, renew dry-run, reload hook |
| 5 | Upstream catalog | conf.d entries for sibling services |
| 6 | Docs | README install, ops runbook, failure modes |

---

## Risks & open questions

1. **`NGINX=` undocumented** — confirm behavior on nginx 1.28.3 under Ubuntu 26,
   especially after `nginx -s reload` and after socket unit restart.
2. **IPv4 vs IPv6 fd count** — may need `NGINX=3:4:5:6;` and matching listens.
3. **Conflict with distro `nginx.service`** — disable/mask package units on the
   service host so only home-warden owns 80/443.
4. **Cert permissions** — private keys must be readable by the service user
   without world-read.
5. **Alternate design** — `AmbientCapabilities=CAP_NET_BIND_SERVICE` on a user
   linger unit avoids socket activation; keep as fallback if `NGINX=` proves
   fragile.

---

## Success criteria

- [ ] `systemctl status home-warden.socket` active; nginx process uid ≠ 0
- [ ] HTTPS terminates for at least one vhost; HTTP→HTTPS redirect works
- [ ] `certbot renew --dry-run` succeeds; timer armed
- [ ] Sibling upstream(s) reachable through the proxy
- [ ] `scripts/setup-service` idempotent on the designated service host
- [ ] `github-repo-lint` clean for `the-hcma/home-warden` (GitHub MQ path)
