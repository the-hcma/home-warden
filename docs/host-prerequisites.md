# Host prerequisites — Milestone 1 (socket-activated nginx)

Target: **Ubuntu 26**, **nginx 1.28.3**, systemd **259+** (machine-id `ConditionHost`).

## One-shot install

`scripts/setup-service` owns the full bring-up: sudo prompt, package/conf checks,
scratch layout, **`sudo nginx -t`**, optional `scripts/on-deploy`, unit install, mask
distro nginx, enable socket + certbot timer, and start the service (refuses to start if
validation fails).

```bash
# Optional: set conf path if not at ~/home/nginx/server/nginx.conf
# export HOME_NGINX_CONF=/path/to/nginx/server/nginx.conf
./scripts/setup-service
```

## Optional preflight

```bash
./scripts/bootstrap           # report only
./scripts/bootstrap --fix     # create scratch, dhparam, staging certs, modules symlink
```

## Logs

```bash
tail --follow=name --retry ~/scratch/home-warden/home-warden.log
tail --follow=name --retry ~/scratch/home-warden/logs/error.log
tail --follow=name --retry ~/scratch/home-warden/logs/access.log
tail --follow=name --retry ~/scratch/home-warden/cert-renewer.log
tail --follow=name --retry ~/scratch/home-warden/nginx-test-and-reload.log
```

## Layout on the host

| Path | Role |
| --- | --- |
| Clone of this repository | Units, scripts, local `conf/` |
| Nginx config path | Pointed at by `HOME_NGINX_CONF` (default `~/home/nginx/server/nginx.conf`) |

## Packages (pre-install)

```bash
sudo apt-get install -y nginx libnginx-mod-stream
# Optional: openssl for generating dhparam / staging certs
# For TLS renew:
sudo apt-get install -y certbot python3-certbot-dns-cloudflare
```

`setup-service` verifies nginx packages are present and aborts with an install hint if not.

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

```bash
openssl dhparam -out ~/conf/home-warden/dhparam.pem 2048
```

## Operating units (status, start, stop)

All units are **system** units installed by `setup-service` (need `sudo` for
start/stop/reload where noted). Quick status:

```bash
./scripts/setup-service --status
systemctl status home-warden.socket home-warden.service \
  home-warden-certbot.timer home-warden-reload.path --no-pager
```

| Unit | Role | Typical ops |
| --- | --- | --- |
| `home-warden.socket` | Binds 80/443; passes fds to the service | `systemctl status/restart home-warden.socket` |
| `home-warden.service` | nginx (`-p` scratch, `-c` home conf) | `sudo systemctl reload\|restart home-warden.service` |
| `home-warden-certbot.timer` | Daily 04:30 → cert renewer | `systemctl list-timers home-warden-certbot.timer`; `sudo systemctl start home-warden-certbot.service` for a one-shot run |
| `home-warden-certbot.service` | Oneshot renewer (no `[Install]`) | Activated by the timer or manual `start` |
| `home-warden-reload.path` | Watches nginx conf file + directory | Enabled by setup-service; `systemctl status home-warden-reload.path` |
| `home-warden-reload.service` | Oneshot: `nginx -t` then reload (no `[Install]`) | Activated only by the path unit |

Logs (also listed above):

| Unit / script | Log |
| --- | --- |
| `home-warden.service` | `~/scratch/home-warden/home-warden.log` (+ nginx `logs/`) |
| cert renewer | `~/scratch/home-warden/cert-renewer.log` |
| config reload oneshot | `~/scratch/home-warden/nginx-test-and-reload.log` |

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
- `ConditionHost` pins the units to the designated host (machine-id **or** hostname).
- IPv4-only listens in Milestone 1; dual-stack fd mapping is a follow-up.
- Certbot runs as the service owner; reload of `home-warden.service` is done via a privileged `ExecStartPost` on the oneshot unit (no passwordless sudo required for the timer).
