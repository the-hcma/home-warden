# Host prerequisites — Milestone 1 (socket-activated nginx)

Target: **Ubuntu 26**, **nginx 1.28.3**, systemd **259+** (machine-id `ConditionHost`).

## Clones

| Path | Repo |
| --- | --- |
| `~/work/ai/home-warden` | `the-hcma/home-warden` (this project) |
| `~/home` or `/home/house_meister/home` | `thehcma/home` — config at `nginx/server/nginx.conf` |

## Packages

```bash
sudo apt-get install -y nginx libnginx-mod-stream
# Optional: openssl for generating dhparam / staging certs
```

Mask the distro unit so it does not fight for 80/443 (`scripts/setup-service` does this):

```bash
sudo systemctl disable --now nginx.service
sudo systemctl mask nginx.service
```

## Scratch runtime (`nginx -p`)

Default: `~/scratch/home-warden/` (pid, logs, temp dirs). Created by `setup-service`.

The **home** `nginx.conf` uses paths relative to this prefix (`logs/…`) plus absolute cert/download paths documented there.

## Certificates

Legacy paths used `/stash/nginx/certificates/tmp/live/<name>/`. On `tron`, stage readable certs for the service user, e.g.:

```text
~/scratch/home-warden/certs/live/<server_name>/{fullchain.pem,privkey.pem}
```

Generate `dhparam` once if missing:

```bash
openssl dhparam -out ~/scratch/home-warden/dhparam.pem 2048
```

## Install units

From a home-warden worktree/checkout:

```bash
./scripts/setup-service
# or:
HOME_NGINX_CONF=/home/house_meister/home/nginx/server/nginx.conf ./scripts/setup-service
```

Then:

```bash
sudo nginx -p "$HOME/scratch/home-warden/" -t -c /home/house_meister/home/nginx/server/nginx.conf
sudo systemctl start home-warden.service
systemctl status home-warden.socket home-warden.service
ps -o user,pid,cmd -C nginx
```

`nginx -t` as a normal user fails on bind(80/443); use `sudo` for the test, or test after the socket is active and fds are inherited.

## Notes

- Units are **system** (not user linger): systemd binds 80/443 and passes fds via `Environment=NGINX=3:4;`.
- `ConditionHost` pins the units to the designated host (machine-id **or** hostname).
- IPv4-only listens in Milestone 1; dual-stack fd mapping is a follow-up.
- Config watch / certbot timer are out of scope for Milestone 1 (separate issues).
