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
home-warden.service   User=home-warden  Group=home-warden
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
  `Group=` (the dedicated `home-warden` system account, gap #14) before
  `exec`ing nginx.
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
even in test mode. Four different callers run `nginx -t` as root
(`setup-service`'s validation, `on-deploy`'s `sudo -n nginx -t`,
`home-warden-reload.service`'s whole-process-as-root run on every config
edit, and the web UI preview path's
`sudo -n /usr/local/sbin/home-warden-nginx-test-candidate` helper) when they
need to validate a config that would otherwise try to bind privileged ports.
That preview helper reads its fixed candidate-conf path from the root-owned
`/usr/local/etc/home-warden-preview-conf-path` marker and sources the same
host-guard logic as the rest of home-warden, so the unprivileged API and the
privileged validator stay pinned to one shared config path + designated-host
decision.
The first three hit the exact pid path the
unprivileged service writes on every start — left root-owned, the next
service start hits "permission denied" and crash-loops. `scripts/lib/nginx-pid`
repairs ownership after every such call; see the PR that fixed this live
crash-loop for the full mechanism:
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

1. **Shared unprivileged identity.** ✅ nginx now runs as a dedicated
   `home-warden` system account (no home, no shell, owns nothing) instead of
   the operator's uid, so a worker compromise no longer reaches sibling
   linger apps or the operator's files
   ([#43](https://github.com/the-hcma/home-warden/issues/43); see gap #14).
2. **TLS private keys readable by that uid.** Partly mitigated: keys stay
   owned by the operator, and `home-warden` reads them only through group
   membership (`chmod 640`), with no write access to the certs tree and no
   access to `certs/accounts/` (the ACME account key). A process compromise
   still exposes every vhost's private key nginx serves — inherent to one
   nginx serving all vhosts.
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
   `ProtectSystem=strict` + `ProtectHome=tmpfs` (with the paths it actually
   needs bound back in via `BindReadOnlyPaths=`/`BindPaths=`),
   `PrivateTmp=true`, `RestrictAddressFamilies=`, and an empty
   `CapabilityBoundingSet=`, on top of `NoNewPrivileges=true`
   ([#42](https://github.com/the-hcma/home-warden/issues/42)).
   The first rollout used `ProtectHome=true` + `ReadOnlyPaths=`, which
   masks `/home` with a mode-000 directory: the unprivileged, capability-free
   service user could not traverse it to reach the reopened paths, and
   nginx crash-looped on `open() nginx.conf failed (13: Permission denied)`
   while `setup-service` still reported success. The bind-mount form fixes
   that, `setup-service` now fails unless the service stays up past one
   `RestartSec`, and `StartLimitBurst=` stops an endless restart loop.
   Beyond the conf dir, `CONF_DIR`, and `SCRATCH_DIR`, `setup-service`
   scans `nginx -T` for `root`/`alias`/`include`/`ssl_*` paths under a
   home directory and binds those read-only too — so adding such a path to
   the served conf needs a `setup-service` re-run, not just the
   conf-watch reload.
   `SystemCallFilter=` is deliberately deferred to a follow-up: it's the one
   directive most likely to manifest as a mysterious runtime failure rather
   than a clean refusal to start, so it needs its own isolated rollout and
   live validation rather than landing bundled with the lower-risk
   directives above.
7. **`FreeBind=true`.** Allows the socket to bind before the address is
   fully configured/local — broader than the default bind behavior, needed
   for reliable boot-time binding, not narrowed further today.
8. **Logging / disk-fill surface.** ✅ `setup-service` now installs
   `/etc/logrotate.d/home-warden` (`etc/logrotate/home-warden`): daily,
   capped at 100M, 14 rotations kept, `copytruncate`
   ([#44](https://github.com/the-hcma/home-warden/issues/44)). `copytruncate`
   trades a small window of possible lost writes (between the copy and the
   truncate) for not needing a signal-and-reopen path through a privileged
   `postrotate` hook — an acceptable trade for these logs.
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
14. **Direction for gaps #1/#2: a dedicated account, not a switched
    execution model.** [#43](https://github.com/the-hcma/home-warden/issues/43)
    tracks giving nginx a role account instead of the operator's own uid.
    - **Why pdns never needed this (see AGENTS.md's Local DNS section):**
      853 is still `<1024`, so `pdns-server` needs the same privileged-bind
      answer nginx does — Debian's `pdns-server` package solves it with
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` on its own systemd unit,
      letting the `pdns` account bind without ever being root. That
      solution shipped for free with the package; home-warden's nginx unit
      is *not* the distro's own unit (the "Runtime model" section above
      notes it's masked so it never competes for 80/443), so nothing
      shipped a bind solution for it — socket activation is home-warden's
      home-grown answer to the same problem pdns's packaging already
      solved. The two aren't parallel cases because one already has an
      off-the-shelf fix and the other doesn't, not because pdns's port
      happens to be unprivileged (it isn't).
    - **Rejected: adopt the distro package's own `nginx.service` and
      execution model.** Stock nginx's model is a *root* master process for
      the service's entire lifetime, forking unprivileged workers — the
      opposite of what gap #1's mitigation above (**"privileged bind
      without a root nginx process"**) buys today. Trading that away for a
      free account isn't a good trade, and it's a real migration (the
      `NGINX=` fd map, the `kill -HUP` reload path, `thehcma/home`'s conf
      assumptions, `ConditionHost`/host-guard, the Gixy-Next CI job) against
      a design that's already live in production — not a quick fix.
      Socket activation stays exactly as-is either way.
    - **Considered and rejected: reuse `www-data`, the account nginx
      defaults to.** `www-data` (uid 33) ships from Debian/Ubuntu's
      `base-passwd` package, present on essentially any Debian-derived
      host regardless of whether nginx is ever installed — nginx's own
      `nginx.conf` just names it (`user www-data;`) as the account its
      workers already drop to. Reusing it on `home-warden.service` would
      cost no new `useradd` step, but unlike `pdns-server`'s account
      (created specifically for pdns), `www-data` is a *shared*, generic
      account other packages (PHP-FPM, etc.) may also default to — it only
      shrinks gap #1's shared-identity exposure rather than closing it,
      which undercuts the point of #43 on a host already investing this
      much in isolation (systemd sandboxing above,
      `ConditionHost`/host-guard, Gixy-Next lint).
    - **Chosen direction: a dedicated `home-warden` system account.**
      `scripts/setup-service` gains an idempotent
      `sudo useradd --system --no-create-home home-warden` step (skipped
      once the account already exists), alongside its existing one-time
      root-level provisioning (masking distro nginx, installing units).
      `home-warden.service` then sets `User=home-warden`/`Group=home-warden`
      instead of the operator's own account, with `certs/live/*/privkey.pem`
      kept owned by the operator and made group-readable by `home-warden`
      (`chmod 640` plus group membership) rather than handing the service
      account write access to the certs tree at all — closing gap #1 fully,
      not just shrinking it.
    - **As implemented:** `setup-service` creates the `home-warden` group
      and system account (`--no-create-home`, shell `/usr/sbin/nologin`)
      and adds the operator to that group. Everything stays owned by the
      operator; the group gets read on `certs/live` + `certs/archive` and
      write (setgid) on exactly the scratch paths nginx writes (`logs/`,
      the `*_temp` dirs, the access/error logs and pid file).
      `cert-renewer`, still running as the operator, hands new lineages
      back to the group after every run (`SERVICE_GROUP`). The unit's
      `ProtectHome=tmpfs` bind mounts (gap #6) are what let an account
      with no access to the operator's mode-750 home still reach those
      paths. `SERVICE_USER=<operator>` re-renders the old identity as a
      rollback; see
      [host-prerequisites.md](./host-prerequisites.md#dedicated-service-account).

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
