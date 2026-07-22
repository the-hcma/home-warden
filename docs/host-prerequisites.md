# Host prerequisites — Milestone 1 (socket-activated nginx)

Target: **Ubuntu 26**, **nginx 1.28.3**, systemd **259+** (machine-id `ConditionHost`).

## One-shot install

`scripts/setup-service` owns the full bring-up: sudo prompt, package/conf checks,
scratch layout, **`sudo nginx -t`**, optional `scripts/on-deploy`, unit install, mask
distro nginx, enable socket, and start the service (refuses to start if validation fails).

```bash
# Optional: set conf path if not at ~/home/nginx/server/nginx.conf
# export HOME_NGINX_CONF=/home/house_meister/home/nginx/server/nginx.conf
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
```

## Clones

| Path | Repo |
| --- | --- |
| `~/work/ai/home-warden` | `the-hcma/home-warden` (this project) |
| `~/home` or `/home/house_meister/home` | `thehcma/home` — config at `nginx/server/nginx.conf` |

## Packages (pre-install)

```bash
sudo apt-get install -y nginx libnginx-mod-stream
# Optional: openssl for generating dhparam / staging certs
```

`setup-service` verifies these packages are present and aborts with an install hint if not.

## Scratch runtime (`nginx -p`)

Default: `~/scratch/home-warden/` (pid, logs, temp dirs, modules symlink). Created by
`setup-service` / `on-deploy`.

## Certificates

Live certs for nginx live under:

```text
~/scratch/home-warden/certs/live/<server_name>/{fullchain.pem,privkey.pem}
```

Renew / obtain (DNS-01 Cloudflare) — scripts in **this** repo (not `thehcma/home`):

```bash
# credentials: ~/cloudflare.conf (or CLOUDFLARE_CREDENTIALS=…)
./scripts/cert-renewer
./scripts/cert-checker -v
```

Domain list: [`etc/certbot-domains`](../etc/certbot-domains).

```bash
openssl dhparam -out ~/scratch/home-warden/dhparam.pem 2048
```

## Notes

- Units are **system** (not user linger): systemd binds 80/443 and passes fds via `Environment=NGINX=3:4;`.
- `ConditionHost` pins the units to the designated host (machine-id **or** hostname).
- IPv4-only listens in Milestone 1; dual-stack fd mapping is a follow-up.
- Config watch / certbot timer systemd units are a follow-up milestone.
