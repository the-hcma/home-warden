# Host prerequisites — Milestone 1 (socket-activated nginx)

Target: **Ubuntu 26**, **nginx 1.28.3**, systemd **259+** (machine-id `ConditionHost`).

> This doc covers install and day-2 ops. For how socket activation actually
> works and its security trade-offs, see
> [architecture-socket-activation.md](./architecture-socket-activation.md).

## One-shot install

`scripts/setup-service` owns the full bring-up: designated-host check, sudo prompt,
package/conf checks, scratch layout, **`sudo nginx -t`**, optional `scripts/on-deploy`,
unit install, mask distro nginx, enable socket + certbot/healthcheck timers + conf
watch, and start the service (refuses to start if validation fails).

home-warden only ever acts on the one host it has been explicitly pinned to (see
[Designated host](#designated-host) below). On the intended host, for the first
install:

```bash
# Optional: set conf path if not at ~/home/nginx/server/nginx.conf
# export HOME_NGINX_CONF=/path/to/nginx/server/nginx.conf
./scripts/setup-service --confirm-host   # or omit and answer the interactive prompt
```

Subsequent runs on the same host need no flag:

```bash
./scripts/setup-service
```

## Designated host

`scripts/lib/host-guard` refuses every mutating action (setup-service, on-deploy,
cert-renewer, healthcheck alerts, the conf-watch reload) unless the current host
matches the one pinned in `~/.config/home-warden-host` / `~/.config/home-warden-machine-id`.
These are host-local files, **never committed to the repo** (see
`.cursor/rules/no-private-infra.mdc`) — nothing pins home-warden to a real hostname
in tracked files.

- First run on the intended host: `./scripts/setup-service --confirm-host` (or answer
  `y` at the interactive prompt) records that host as the pin.
- Moving to different hardware: `./scripts/setup-service --repin-host` on the new host.
- Everywhere else (a dev laptop, a CI runner, a session-init hook that happens to run
  `scripts/on-deploy`), these scripts print a refusal and exit non-zero instead of
  touching live state.
- `./scripts/setup-service --status` reports the current pin and whether this host
  matches it, without mutating anything.
- `HOME_WARDEN_SKIP_HOST_GUARD=1` bypasses the check — manual testing only, never set
  it in a unit or timer.

## Optional preflight

```bash
./scripts/bootstrap                # report only
./scripts/bootstrap --fix          # create scratch, dhparam, staging certs, modules symlink
./scripts/bootstrap --fix-packages # confirm [y/N], then sudo apt-get install -y missing packages
```

## Logs

```bash
tail --follow=name --retry ~/scratch/home-warden/home-warden.log
tail --follow=name --retry ~/scratch/home-warden/logs/error.log
tail --follow=name --retry ~/scratch/home-warden/logs/access.log
tail --follow=name --retry ~/scratch/home-warden/cert-renewer.log
tail --follow=name --retry ~/scratch/home-warden/nginx-test-and-reload.log
tail --follow=name --retry ~/scratch/home-warden/healthcheck.log
```

`setup-service` installs `/etc/logrotate.d/home-warden` (from
`etc/logrotate/home-warden`): daily, capped at 100M, 14 rotations kept,
`copytruncate` (no reopen signal needed — see
[docs/architecture-socket-activation.md](./architecture-socket-activation.md)
for why). Runs via the distro's standard `logrotate.timer`/cron, no
home-warden-specific timer needed.

## Layout on the host

| Path | Role |
| --- | --- |
| Clone of this repository | Units, scripts, local `conf/` |
| Nginx config path | Pointed at by `HOME_NGINX_CONF` (default `~/home/nginx/server/nginx.conf`) |

## Service catalog (design in progress — not yet consumed by anything)

[#45](https://github.com/the-hcma/home-warden/issues/45) is designing a
structured (JSON) catalog of the services home-warden fronts, so the nginx
vhost list can eventually be generated instead of hand-maintained. Schema
reference: [`services.json.example`](../services.json.example) at this
repo's root. The **operator's real catalog** follows the same private,
XDG-backed pattern already used for domesti-bot's local rules:

```text
~/.config/home-warden  ──symlink──►  ~/.local/share/config/home-warden
                                      (private the-hcma/config clone)
```

See `thehcma/config`'s own README for the full first-time-setup steps
(clone to `~/.local/share/config`, symlink `~/.config/home-warden` into it).
Nothing in home-warden reads this file yet — no renderer exists until #45's
open design questions (where it renders from/to, commit- vs. deploy-time)
are settled.

## Packages (pre-install)

```bash
sudo apt-get install -y nginx nginx-common libnginx-mod-stream openssl \
  certbot python3-certbot-dns-cloudflare logrotate
```

The package list lives in one place, `scripts/bootstrap`'s `apt_packages` array — this
table mirrors it:

| Package | Why |
| --- | --- |
| `nginx` | binary + unit we mask in favor of home-warden |
| `nginx-common` | shared bits / modules layout |
| `libnginx-mod-stream` | `stream { }` (e.g. MQTT) |
| `openssl` | dhparam / staging certs (`bootstrap --fix`) |
| `certbot` | `scripts/cert-renewer` |
| `python3-certbot-dns-cloudflare` | DNS-01 plugin used by the renewer |
| `logrotate` | rotates `SCRATCH_DIR`'s logs (`etc/logrotate/home-warden`) |

`./scripts/bootstrap --fix-packages` checks and, after a `[y/N]` confirm, installs any
that are missing. `setup-service` also verifies nginx/certbot packages are present and
aborts with an install hint if not — `--fix-packages` is the faster path to close that gap.

## Scratch runtime (`nginx -p`)

Default: `~/scratch/home-warden/` (pid, logs, temp dirs, modules symlink). Created by
`setup-service` / `on-deploy`. Safe to wipe — durable TLS material lives under `CONF_DIR`.

## Certificates

Durable certbot state and nginx TLS files live under `~/conf/home-warden/` (override with
`CONF_DIR` / `CERTBOT_CONFIG_DIR`):

```text
~/conf/home-warden/certs/live/<server_name>/{fullchain.pem,privkey.pem}
~/conf/home-warden/dhparam.pem
```

Local (gitignored) configuration — copy from examples under `conf/` **in the
primary clone** (first path from `git worktree list`):

| Example | Runtime file |
| --- | --- |
| `conf/certbot-domains.example` | `conf/certbot-domains` |
| `conf/cloudflare.ini.example` | `conf/cloudflare.ini` |

In a linked worktree, symlink those files from primary (also auto-run by
`cert-renewer`):

```bash
./scripts/link-runtime-conf
```

Optional env overrides: copy [`etc/home-warden-certbot.env.example`](../etc/home-warden-certbot.env.example)
to `~/.config/home-warden-certbot.env` (`chmod 600`) and set `CERTBOT_EMAIL` to a real
Let's Encrypt contact.

```bash
# Manual / first issuance (after conf/ is filled):
CERTBOT_EMAIL=you@example.com ./scripts/cert-renewer --dry-run
CERTBOT_EMAIL=you@example.com ./scripts/cert-renewer
./scripts/cert-checker --verbose

# Timer (enabled by setup-service):
systemctl list-timers home-warden-certbot.timer
sudo systemctl start home-warden-certbot.service   # oneshot trial
```

## Healthcheck email alarms

Minute timer probes `home-warden.service` and a local HTTPS request (`curl` to
`127.0.0.1:443` with `HEALTHCHECK_HOST` as SNI/Host). Emails on first failure,
re-alerts at most every `HEALTHCHECK_RESEND_SEC` (default 1800) while still down,
and sends a recovery message when healthy again.

Copy [`etc/home-warden-healthcheck.env.example`](../etc/home-warden-healthcheck.env.example)
to `~/.config/home-warden-healthcheck.env` (`chmod 600`). Set a real
`HEALTHCHECK_EMAIL_TO` and `HEALTHCHECK_HOST` **only in that local file** (never in
the repo). Without `HEALTHCHECK_EMAIL_TO`, the probe still runs and logs; mail is
skipped.

```bash
# Manual probe:
./scripts/healthcheck --verbose
./scripts/healthcheck --check-only   # exit 1 when unhealthy

# Timer (enabled by setup-service):
systemctl list-timers home-warden-healthcheck.timer
sudo systemctl start home-warden-healthcheck.service
```

Requires local MTA (`sendmail` or `mail`). Install if needed:

```bash
# e.g. postfix or mailutils — host-specific; not installed by setup-service
```

```bash
openssl dhparam -out ~/conf/home-warden/dhparam.pem 2048
```

## Operating units (status, start, stop)

All units are **system** units installed by `setup-service` (need `sudo` for
start/stop/reload where noted). Quick status:

```bash
./scripts/setup-service --status
systemctl status home-warden.socket home-warden.service \
  home-warden-certbot.timer home-warden-reload.path \
  home-warden-healthcheck.timer --no-pager
```

| Unit | Role | Typical ops |
| --- | --- | --- |
| `home-warden.socket` | Binds 80/443; passes fds to the service | `systemctl status/restart home-warden.socket` |
| `home-warden.service` | nginx (`-p` scratch, `-c` home conf) | `sudo systemctl reload\|restart home-warden.service` |
| `home-warden-certbot.timer` | Daily 04:30 → cert renewer | `systemctl list-timers home-warden-certbot.timer`; `sudo systemctl start home-warden-certbot.service` for a one-shot run |
| `home-warden-certbot.service` | Oneshot renewer (no `[Install]`) | Activated by the timer or manual `start` |
| `home-warden-reload.path` | Watches nginx conf file + directory | Enabled by setup-service; `systemctl status home-warden-reload.path` |
| `home-warden-reload.service` | Oneshot: `nginx -t` then reload (no `[Install]`) | Activated only by the path unit |
| `home-warden-healthcheck.timer` | Every minute → healthcheck | `systemctl list-timers home-warden-healthcheck.timer`; `sudo systemctl start home-warden-healthcheck.service` |
| `home-warden-healthcheck.service` | Oneshot probe + optional email (no `[Install]`) | Activated by the timer or manual `start` |

`setup-service` also installs a root-owned
`/usr/local/sbin/home-warden-nginx-test-candidate` helper,
`/usr/local/libexec/home-warden/host-guard`, the matching
`/etc/sudoers.d/home-warden-web-ui-nginx-test` rule, and the root-owned
`/usr/local/etc/home-warden-preview-conf-path` marker that records the one
preview candidate path the helper is allowed to test. The web UI backend may
only run that exact command via `sudo -n`; both the backend and the helper
read the candidate path from the same marker file, so changing `SCRATCH_DIR`
means re-running `setup-service` to refresh that single source of truth.
Until `setup-service` installs or refreshes those files on the designated
host, the UI can still render diffs but `nginx -t` remains unavailable and
Apply stays blocked.

Logs (also listed above):

| Unit / script | Log |
| --- | --- |
| `home-warden.service` | `~/scratch/home-warden/home-warden.log` (+ nginx `logs/`) |
| cert renewer | `~/scratch/home-warden/cert-renewer.log` |
| config reload oneshot | `~/scratch/home-warden/nginx-test-and-reload.log` |
| healthcheck | `~/scratch/home-warden/healthcheck.log` |

## Config watch → nginx -t → reload

**Why:** so edits to the home nginx conf are applied without a manual
`systemctl reload`, and bad syntax never takes workers down.

**How it triggers (automatic):** `home-warden-reload.path` watches both
`HOME_NGINX_CONF` and its parent directory (`PathModified=`). Typical editor
saves (rename into place) and in-place edits (`sed -i`) both fire the path unit.
Systemd debounces bursts into one activation.

**What runs:** `home-warden-reload.service` executes
`scripts/nginx-test-and-reload` as root:

1. `nginx -t` against the conf + scratch prefix  
2. On success → `systemctl reload home-warden.service` (restart fallback)  
3. On `-t` failure → **no reload** (fail closed; last good workers keep serving)

```bash
systemctl status home-warden-reload.path
# Edit ~/home/nginx/server/nginx.conf (valid) → expect an entry in:
tail --follow=name --retry ~/scratch/home-warden/nginx-test-and-reload.log
# Break syntax on purpose → log shows FAIL; live traffic keeps the last good conf
# Manual dry-run of the helper (no path unit):
HOME_NGINX_CONF=/path/to/nginx.conf ./scripts/nginx-test-and-reload
```

Editor save storms / temp files in the conf directory may trigger extra runs;
`-t` still prevents applying a broken conf.

## Notes

- Units are **system** (not user linger): systemd binds 80/443 and passes fds via `Environment=NGINX=3:4;`.
- `ConditionHost` pins the units to the designated host (machine-id **or** hostname); see
  [Designated host](#designated-host) for the same guard applied inside the scripts themselves.
- IPv4-only listens in Milestone 1; dual-stack fd mapping is a follow-up.
- Certbot runs as the service owner; reload of `home-warden.service` is done via a privileged `ExecStartPost` on the oneshot unit (no passwordless sudo required for the timer).
