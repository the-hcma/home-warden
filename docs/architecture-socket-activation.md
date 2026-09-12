# Architecture: socket-activated nginx

How home-warden's front door actually works, and where the security trade-offs
are. `docs/host-prerequisites.md` covers *installing and operating* it; this
doc covers *why it's built this way* and *what it does and doesn't protect
against*. See also [PLAN.md](../PLAN.md) for the original design rationale.

Status: live on the designated host — socket activation, DNS-01 cert
renewal, config-watch reload, and healthcheck alerting are all running.
Originally proposed in [#9](https://github.com/the-hcma/home-warden/issues/9),
following on from Milestone 1 ([#2](https://github.com/the-hcma/home-warden/issues/2)).

## Runtime model

```text
Internet
   │
   ▼
systemd (root) ── home-warden.socket
   ListenStream=0.0.0.0:80
   ListenStream=0.0.0.0:443
   (Accept=no, FreeBind=true)
   │
   │  fds 3, 4 passed on activation; Environment=NGINX=3:4;
   ▼
home-warden.service   User=<owner>  Group=<owner>
   nginx -p ~/scratch/home-warden/ -c <thehcma/home nginx.conf> -g 'daemon off;'
   │
   ├─► proxy_pass → sibling app upstreams (bunnify, domesti-bot, …)
   └─► workers serve TLS from ~/conf/home-warden/certs/live/<name>/
```

- **`home-warden.socket`** is a *system* unit — it binds `0.0.0.0:80` and
  `0.0.0.0:443` (`Accept=no`: nginx accepts connections itself, not systemd
  per-connection; `FreeBind=true`: bind is allowed before the address is
  fully local, useful on boot).
- **`home-warden.service`** is also a *system* unit, but drops to `User=`/
  `Group=` (the operator's own unprivileged account) before `exec`ing nginx.
  `Requires=`/`After=home-warden.socket` ties its lifecycle to the socket.
- **Fd handoff**: stock nginx does not speak systemd's `LISTEN_FDS` protocol.
  Instead it reuses its internal *reload* socket-inheritance mechanism via the
  undocumented `Environment=NGINX=3:4;` — fd 3 maps to the first `listen` in
  the conf, fd 4 to the second. The conf's listen order (`listen 80;` then
  `listen 443 ssl;`) must match, or nginx binds the wrong protocol to the
  wrong fd. IPv4-only today (two fds); dual-stack would need four
  (`NGINX=3:4:5:6;`) and is still unvalidated (see
  [systemd.io Daemon Socket Activation](https://systemd.io/DAEMON_SOCKET_ACTIVATION/)).
- **Config source of truth** lives in a *separate* private repo,
  `thehcma/home`'s `nginx/server/nginx.conf`, passed via `-c`
  (`HOME_NGINX_CONF`). Runtime prefix `-p ~/scratch/home-warden/` supplies
  pid/temp/log paths; durable TLS material lives under
  `~/conf/home-warden/certs/`, outside both git trees.
- **Distro `nginx.service`** is disabled and masked by `setup-service` so it
  never competes for 80/443.
- **`ConditionHost`** (machine-id *or* hostname, injected by `setup-service`)
  pins every unit to the one designated host — see
  [Designated host](./host-prerequisites.md#designated-host). This is a
  systemd-level guard; `scripts/lib/host-guard` enforces the same pin a
  second time *inside* the scripts themselves, in a namespace deliberately
  distinct from repository-helpers' own generic per-machine pin (an
  unrelated dev-convenience mechanism for sibling repos) — see
  [#38](https://github.com/the-hcma/home-warden/issues/38) for the incident
  that motivated keeping those two pins from ever being confused.

### Reload: `kill -HUP`, never `nginx -s reload`

`home-warden.service`'s `ExecReload=` is `/usr/bin/kill -s HUP $MAINPID`, not
the more obvious `nginx -s reload`. The `-s reload` helper spawns a *new*,
short-lived nginx process to signal the running master — that new process
inherits the same `Environment=NGINX=3:4;` but was never handed the actual
socket fds by systemd, so it calls `getsockname()` on fds that aren't open in
its own process and fails. Signalling the existing master's PID directly
avoids spawning that fd-less helper. The same reasoning applies to
`scripts/nginx-test-and-reload` (fired by `home-warden-reload.path` on every
config edit): it runs `nginx -t` (syntax-only, no fds needed) then
`systemctl reload home-warden.service`, never `nginx -s reload` directly.

A related footgun: `nginx -t` still opens the conf's `pid` file for writing
even in test mode. Three different callers run `nginx -t` as root
(`setup-service`'s validation, `on-deploy`'s `sudo -n nginx -t`, and
`home-warden-reload.service`'s whole-process-as-root run on every config
edit) against the exact pid path the unprivileged service writes on every
start — left root-owned, the next service start hits "permission denied"
and crash-loops. `scripts/lib/nginx-pid` repairs ownership after every such
call; see the PR that fixed this live crash-loop for the full mechanism:
[#39](https://github.com/the-hcma/home-warden/pull/39).

## Security posture: what we gain

- **Privileged bind without a root nginx process.** Only systemd needs
  `CAP_NET_BIND_SERVICE`-equivalent to open 80/443 (opening the socket is a
  one-time, root-owned action at unit start); nginx workers run the entire
  time as the unprivileged service owner.
- **No world-writable privileged ports from a user linger unit.** Sibling
  apps run as systemd *user* linger services on high ports; user systemd
  cannot bind `<1024` at all, and a *system* socket cannot activate a *user*
  service — hence the front door has to be system socket + system service
  with a `User=` drop, not a linger unit like its siblings.
- **Host pin.** `ConditionHost` (systemd-level) plus `scripts/lib/host-guard`
  (script-level) both reduce the chance of an accidental start, cert
  renewal, or reload on the wrong machine — including from generic
  dev-tooling that has no idea this repo manages its own privileged
  deployment (the exact failure mode in #38).
- **`NoNewPrivileges=true`** on `home-warden.service` — the process (and
  anything it execs) can never gain privileges beyond what it started with,
  even via a setuid binary.

## Known gaps / risks

Documented explicitly rather than left implicit. None of these are
hypothetical scenarios invented for this doc — they're the trade-offs of the
current design, tracked here so a future change (or a future agent) doesn't
have to rediscover them.

1. **Shared unprivileged identity.** nginx runs as the same uid that owns
   sibling linger apps and home files, not a dedicated `nginx` role account.
   A worker compromise (RCE, a bad module, conf injection) is a compromise of
   that whole user, not an isolated service account.
2. **TLS private keys readable by that uid.** Every `certs/live/*/privkey.pem`
   under `~/conf/home-warden/certs/` must be readable by the service user.
   One process compromise exposes every vhost's private key on the box.
3. **Writable config path.** `-c` points at a conf tree the service user can
   typically edit directly. A conf write is arbitrary `proxy_pass`, TLS, and
   request-routing control — and `home-warden-reload.path` will pick up and
   apply that edit automatically (by design, for legitimate edits; the same
   mechanism has no way to distinguish an operator's edit from an attacker's).
4. **Undocumented `NGINX=` fd map.** Not a security boundary by itself, but
   version skew or a silent semantic change on a future nginx upgrade is an
   availability risk (and a "is this process actually listening on the
   socket I think it is?" question worth re-verifying after any nginx
   version bump). Dual-stack (four fds) remains unvalidated.
5. **Inherited listening fds survive a compromise.** Dropping root at
   `exec` time does not revoke the already-open 80/443 fds handed to the
   process — a compromised master or worker can still `accept()` on those
   ports as the service user for as long as the process lives.
6. **Systemd sandboxing.** ✅ `home-warden.service` now sets
   `ProtectSystem=strict` + `ProtectHome=true` (with the three paths it
   actually needs reopened via `ReadOnlyPaths=`/`ReadWritePaths=`),
   `PrivateTmp=true`, `RestrictAddressFamilies=`, and an empty
   `CapabilityBoundingSet=`, on top of `NoNewPrivileges=true`
   ([#42](https://github.com/the-hcma/home-warden/issues/42)).
   `SystemCallFilter=` is deliberately deferred to a follow-up: it's the one
   directive most likely to manifest as a mysterious runtime failure rather
   than a clean refusal to start, so it needs its own isolated rollout and
   live validation rather than landing bundled with the lower-risk
   directives above.
7. **`FreeBind=true`.** Allows the socket to bind before the address is
   fully configured/local — broader than the default bind behavior, needed
   for reliable boot-time binding, not narrowed further today.
8. **Logging / disk-fill surface.** `StandardOutput=`/`StandardError=append:`
   into scratch logs, plus nginx's own access/error logs, are all on the
   request path — no rotation or size cap configured by home-warden itself;
   disk fill or log injection from network-controlled input is possible.
9. **`:80` is a real listener.** Cleartext HTTP is bound and expected to
   redirect to HTTPS; ensure the home conf never serves anything sensitive
   over that cleartext listener before the redirect, and that HSTS is only
   enabled once real (non-staging) certs are live.
10. **Trust boundary with `thehcma/home`.** The actual served config is a
    *separate, private* repository this one doesn't control. A wrong
    `HOME_NGINX_CONF`, or a malicious/erroneous commit in that tree, is a
    full front-door compromise — home-warden's own review process and CI
    have no visibility into that repo's changes.
11. **DNS-01 / Cloudflare as a single point of control.** Cert renewal
    (`scripts/cert-renewer`, live via `home-warden-certbot.timer`) uses
    DNS-01 against Cloudflare, authenticated by an API token in
    `conf/cloudflare.ini` (gitignored, `chmod 600`, readable by the service
    owner). Whoever holds that token can create arbitrary DNS-validated
    certificates for every domain it covers — treat it with the same care as
    a private key. (Earlier design notes considered webroot/HTTP-01 as an
    alternative; DNS-01 is what's actually implemented, since the domains
    aren't all reachable via HTTP-01 challenge paths.)
12. **`HOME_WARDEN_SKIP_HOST_GUARD=1` escape hatch.** Documented for manual
    testing only, but it exists — if ever set in a unit, timer, or automated
    context, it silently removes the one guard preventing mutating scripts
    from running on the wrong host.
13. **Alternate design not chosen.** `AmbientCapabilities=CAP_NET_BIND_SERVICE`
    on a *user* linger unit would avoid socket-fd mapping entirely, at the
    cost of putting bind capability directly on a long-lived service process
    instead of a one-time root socket-open. Socket activation was preferred
    to keep the long-lived nginx process capability-free; revisit if the
    `NGINX=` fd map ever proves too fragile across nginx versions.

## Non-goals for this doc

- A full CIS-style nginx hardening checklist — link out to one later if
  useful; this doc stays scoped to the socket-activation design itself.
- Implementing the systemd sandboxing directives listed in gap #6 — tracked
  here as a known gap, not yet a scheduled deliverable.

## References

- Units: [`etc/systemd/home-warden.socket`](../etc/systemd/home-warden.socket),
  [`etc/systemd/home-warden.service`](../etc/systemd/home-warden.service)
- [systemd.io: Socket Activation](https://systemd.io/DAEMON_SOCKET_ACTIVATION/)
- [PLAN.md](../PLAN.md) — original design rationale and open questions
- [docs/host-prerequisites.md](./host-prerequisites.md) — install and day-2 ops
