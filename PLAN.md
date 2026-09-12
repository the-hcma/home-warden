# home-warden — Implementation Plan

> This is the **original design doc**, kept for its rationale and open
> questions. For an accurate, current description of the running system, see
> [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md);
> for install/ops, see [docs/host-prerequisites.md](./docs/host-prerequisites.md).
> Several sections below (repository layout, unit sketches, certbot challenge
> type) describe the pre-implementation plan, not the shipped system — see the
> inline notes.

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

### Vision beyond v1

home-warden's scope is meant to grow into the **one-stop front door for all
home services** — local and remotely reachable: nginx reverse-proxy/TLS
termination (live today), public certificate management (live today, DNS-01
via Cloudflare), and **eventually DNS** itself, so the same project that
terminates traffic and issues certs also owns the records that route to it.
The phases and non-goals below describe what's shipped and deliberately
deferred so far, not a ceiling on the project.

---

## Goals

| Goal | Approach |
| --- | --- |
| Bind 80/443 without running nginx as root | System `.socket` units → inherit fds in service |
| Process runs as the home user | `User=` / `Group=` on the system `.service` |
| Cert renewal without a long-lived root agent | `home-warden-certbot.service` + `.timer` |
| Config owned by the user | Served conf lives in `thehcma/home`; pid/temp/logs under `~/scratch/home-warden/` |
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
   /usr/sbin/nginx -p ~/scratch/home-warden/ -c …/nginx.conf -g 'daemon off;'
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
Treat `NGINX=` as stable-in-practice but undocumented. Reload is validated in
production (daily, via config-watch and cert renewal — see
[docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md#reload-kill--hup-never-nginx--s-reload)
for the one real gotcha); dual-stack (four fds) remains unvalidated.

---

## Repository layout

> The tree below was the pre-implementation plan. It shipped differently:
> the *served* nginx config lives in the separate, private `thehcma/home`
> repo, not under `nginx/` here — `nginx/nginx.conf` in this repo is a
> CI-only syntax smoke-test fixture (`.github/workflows/ci.yml` runs
> `nginx -t` against it). `conf.d/`, `snippets/`, and `webroot/` were part of
> this original plan but never used (certs use DNS-01, not HTTP-01/webroot;
> the real conf tree lives in `thehcma/home`) — removed as part of the
> [docs cleanup](https://github.com/the-hcma/home-warden/issues/9). `etc/systemd/`
> holds all seven unit templates plus a `.path` unit for config-watch reload.
> See the actual [`etc/systemd/`](./etc/systemd/) and [`scripts/`](./scripts/)
> directories for the current, authoritative layout.

Live certs and private keys stay **outside** git (`~/conf/home-warden/certs/`
or Let’s Encrypt live paths readable by the service user). Scratch
(`~/scratch/home-warden/`) is ephemeral runtime only.

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

> This was the original sketch — it shipped with one correction, called out
> below. See [`etc/systemd/home-warden.service`](./etc/systemd/home-warden.service)
> for the real, current unit.

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
ExecStart=/usr/sbin/nginx -p @@SCRATCH_DIR@@/ -c @@HOME_NGINX_CONF@@ -g 'daemon off;'
# NOT `nginx -s reload`: that helper spawns a new, short-lived process that
# inherits Environment=NGINX=3:4; but was never handed the actual socket fds
# by systemd, so it fails with getsockname() EBADF. Signal the running
# master directly instead.
ExecReload=/usr/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5
# pid / temp paths must be writable by User= (set via -p, not in nginx.conf)

[Install]
WantedBy=multi-user.target
```

### Certbot

> Shipped as **DNS-01 via Cloudflare**, not the webroot/HTTP-01 sketch
> originally considered below — not every domain served here is reachable
> via an HTTP-01 challenge path. See
> [`scripts/cert-renewer`](./scripts/cert-renewer) and
> [docs/host-prerequisites.md](./docs/host-prerequisites.md#certificates).

- Challenge: **DNS-01 via Cloudflare** (`python3-certbot-dns-cloudflare`,
  token in gitignored `conf/cloudflare.ini`).
- `home-warden-certbot.service`: oneshot, `scripts/cert-renewer` (per-domain
  `certbot renew` / `certonly`).
- Deploy hook: `ExecStartPost=-+systemctl try-reload-or-restart home-warden.service`
  on the oneshot unit itself (`+` runs as root regardless of the unit's own
  `User=`, `-` ignores failure) — no passwordless sudo needed for the timer.
- `home-warden-certbot.timer`: daily at 04:30, `Persistent=true`.

---

## Implementation phases

| # | Phase | Deliverable | Status |
| --- | --- | --- | --- |
| 0 | Repo bootstrap | This plan, org practices scaffolding, CI smoke; **gh-stack** + GitHub MQ | ✅ done |
| 1 | Minimal nginx.conf | User-writable pid/temp/log paths; `nginx -t` in CI | ✅ done |
| 2 | Systemd units + setup-service | Install to `/etc/systemd/system/`, host guards | ✅ done |
| 3 | Socket-activation proof | Bind 80/443 on a lab host; confirm `NGINX=` fds | ✅ done — live on the designated host |
| 4 | TLS + certbot timer | First cert, renew dry-run, reload hook | ✅ done — DNS-01/Cloudflare, daily timer |
| 5 | Upstream catalog | conf.d entries for sibling services | Moved to `thehcma/home` (the actual served conf lives there, not in this repo) |
| 6 | Docs | README install, ops runbook, failure modes | ✅ done — see docs/host-prerequisites.md and docs/architecture-socket-activation.md |

---

## Risks & open questions

1. **`NGINX=` undocumented** — ✅ confirmed working on nginx 1.28.3 / Ubuntu 26
   in production. The one real gotcha (`nginx -s reload` fails; must signal
   the master via `kill -HUP`) is documented in
   [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md#reload-kill--hup-never-nginx--s-reload).
2. **IPv4 vs IPv6 fd count** — still open. IPv4-only today
   (`NGINX=3:4;`, two fds); dual-stack (`NGINX=3:4:5:6;`) is unvalidated.
3. **Conflict with distro `nginx.service`** — ✅ resolved; `setup-service`
   disables and masks it.
4. **Cert permissions** — ✅ resolved for the steady-state case; but see the
   pid-ownership footgun in
   [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md#reload-kill--hup-never-nginx--s-reload)
   for a related root-vs-owner issue that did bite in production
   ([#39](https://github.com/the-hcma/home-warden/pull/39)).
5. **Alternate design** — not pursued; socket activation has been stable in
   production. `AmbientCapabilities=CAP_NET_BIND_SERVICE` on a user linger
   unit remains a documented fallback if `NGINX=` ever proves fragile across
   an nginx upgrade — see
   [docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md#known-gaps--risks) gap 13.

For the fuller, currently-tracked list of security trade-offs (not just the
five above), see
[docs/architecture-socket-activation.md](./docs/architecture-socket-activation.md#known-gaps--risks).

---

## Success criteria

- [x] `systemctl status home-warden.socket` active; nginx process uid ≠ 0
- [x] HTTPS terminates for at least one vhost; HTTP→HTTPS redirect works
- [x] `certbot renew --dry-run` succeeds; timer armed
- [x] Sibling upstream(s) reachable through the proxy
- [x] `scripts/setup-service` idempotent on the designated service host
- [x] `github-repo-lint` clean for `the-hcma/home-warden` (GitHub MQ path)
