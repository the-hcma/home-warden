# Moving the front door to a replacement host

How to move nginx, certificates, DNS and the client CA from the current host to a replacement without an outage, and how to go back. The epic is [#191](https://github.com/the-hcma/home-warden/issues/191). Hostnames and addresses are placeholders here, per `.cursor/rules/no-private-infra.mdc`.

Stages 0 to 3 change nothing live (the certificate reissue in stage 1 is on the replacement only, and counts against Let's Encrypt's duplicate-certificate limit). Do not start a stage until the previous stage's exit criterion holds. Every rollback below is a single action, and is only as fast as the DNS TTLs you lowered in stage 4.

## Tools

| Tool | Stage | What it answers |
| --- | --- | --- |
| `scripts/cutover-preflight` | 1 | Can this host take over? Read-only (its `--certbot-dry-run` is opt-in, see stage 1). |
| `scripts/cutover-verify --old A --new B` | 2, 5 | Does the replacement serve each vhost the way the current host does? |
| `scripts/dns-parity --old A --new B` | 3, 5 | Does the replacement DNS server answer every `zones.yml` record the way the current one does? |
| `scripts/dns-sync --target <new> --old-target <old>` | 4, 5 | Moves the catalog's Cloudflare records (one address type per name), saving a snapshot first, and lists records outside the catalog still pointing at the old host (exit 1 if any). |
| `scripts/dns-sync --restore <snapshot>` | rollback | Puts the snapshotted records back (content, proxied flag, TTL). Exit 1 if it left anything for you: a name that had no record, or several. |
| `scripts/cutover-assess` | 1 to 3 | Temporary shell version of the first three, for a host without `uv`. Removed once these have been used. |

## What is host-local

Nothing below is in git. Each must exist on the replacement host before stage 1 ends.

| Item | How it gets there |
| --- | --- |
| Host pin | `./scripts/setup-service --confirm-host` on the replacement. The current host keeps its own pin until it is decommissioned. |
| Served nginx config | The served-config repo, at `HOME_NGINX_CONF`. |
| `conf/cloudflare.ini`, `conf/certbot-domains` | Copy, mode `0600` for the token. |
| Certificate lineages | Reissued by `scripts/cert-renewer` on the replacement (DNS-01 works from any host). Mind Let's Encrypt's duplicate-certificate limit: reissue once, not repeatedly. |
| `~/.config/home-warden/` (`config.toml`, `session-secret`, `services.json`, SMTP config) | Copy. A new `session-secret` only logs web UI sessions out. |
| `zones.yml` and the recursor config | The served-config repo. The recursor's `forward_zones` stay hand-maintained. |
| Client CA store | `scripts/client-pki backup` on the current host, `restore` on the replacement, at stage 5 only. The key is not encrypted at rest ([#184](https://github.com/the-hcma/home-warden/issues/184)), so move the archive over a trusted channel and delete it after. |

## Two hosts at once

During the overlap, both hosts have the units installed. Decide per unit:

| Unit | Current host | Replacement |
| --- | --- | --- |
| `home-warden.socket`/`.service` | serving | installed, not receiving traffic until stage 5 |
| `home-warden-certbot.timer` | on | on (each renews its own lineages; both add DNS-01 challenge TXT records, which is fine) |
| `home-warden-healthcheck.timer` | on | on, so both mail on their own failure |
| `home-warden-catalog-heal.timer` | on | **off** until stage 5d; it never applies DNS, but two alert senders are noise. `setup-service` enables it whenever `services.json` exists, so run `sudo systemctl disable --now home-warden-catalog-heal.timer` after every `setup-service` run on the replacement |
| `home-warden-client-pki-crl.timer` | on (CA lives here) | off until the CA is restored there |
| `catalog-heal --apply-dns` by hand | never during the overlap | only after stage 5 |

Only one host may write the **A/AAAA/CNAME records** at a time (the `dns-sync` and `catalog-heal --apply-dns` writers). The certbot challenge records don't count.

## Stage 0: CI green on main

Exit: green.

## Stage 1: readiness on the replacement (no traffic)

1. Install the prerequisites in [host-prerequisites.md](./host-prerequisites.md) and put the items from the table above in place, except the client CA. Follow that doc's certificates section for the order of first issuance and `setup-service`: the validation in `setup-service` needs the certificates the served conf names.
2. `./scripts/setup-service --confirm-host` pins the replacement. Then disable `home-warden-catalog-heal.timer` (see the overlap table).
3. `./scripts/cutover-preflight`.
4. Fix every `FAIL`. A `FAIL` on an upstream means the app isn't reachable from this host: either the app moves too, or the served conf points at an address that is routable from both hosts. A `WARN` for a vhost missing from the catalog is informational: the catalog-driven checks won't cover it.
5. Optional, once the host is pinned: `./scripts/cutover-preflight --certbot-dry-run`. It runs `cert-renewer --dry-run`, which today moves an incomplete lineage (certificates copied in without their renewal config) aside before its dry run ([#199](https://github.com/the-hcma/home-warden/issues/199)). Don't use it on a host whose certificates you just copied in until that is fixed.

Exit: no `FAIL`.

## Stage 2: shadow nginx

```bash
./scripts/cutover-verify --old <old-ipv4> --new <new-ipv4> [--old6 <old-ipv6> --new6 <new-ipv6>] [--host <vhost-not-in-catalog>]
```

`cutover-verify` compares `GET /` on each vhost: the `:80` status and redirect, the HTTPS status and security headers it lists, the TLS version, issuer and SANs, whether the certificate verifies, and `Server` version disclosure. Certificate serial and `notAfter` are shown, never flagged. It does not compare other paths, cookies, content types or bodies, so spot-check one or two real pages per vhost by hand. An address that can't be reached is a difference even if both are down.

Websocket vhosts in the catalog get an Upgrade probe automatically.

For `client_cert: required` vhosts, the mTLS accept/reject check can't be done yet: the client CA is restored on the replacement only at stage 5a, so until then the replacement rejects every client certificate. Verify those vhosts without a client certificate now (both must refuse), and run the accept and revoked checks right after 5a: `--client-cert`/`--client-key` with a throwaway certificate from `scripts/client-pki` (both hosts accept), then with a revoked one after `revoke` and a reload (both reject).

Exit: no unexpected differences over IPv4 and IPv6.

## Stage 3: shadow DNS

On the replacement, `pdns-server` and `pdns-recursor` are installed and loaded from the same `zones.yml` ([dns-tinydns-migration.md](./dns-tinydns-migration.md)). Compare both the recursors (the path clients use) and, on each host, the authoritative server:

```bash
./scripts/dns-parity --old <old-recursor> --new <new-recursor> \
  --probe <a-public-name> --probe <a-name-that-must-be-nxdomain>
```

Compare like with like: two recursors, or two authoritative servers, not one of each (the AA flag and TTLs differ). The authoritative servers listen on loopback:853, so to compare them, tunnel both to your machine and point the tool at the tunnels. Pointing `--old` at `127.0.0.1:853` on the replacement would compare the replacement with itself.

```bash
ssh -N -L 8853:127.0.0.1:853 <old-host> &
ssh -N -L 9853:127.0.0.1:853 <new-host> &
./scripts/dns-parity --old 127.0.0.1:8853 --new 127.0.0.1:9853
```

Also on the replacement: `getent ahosts <upstream.host>` for each internal upstream (the host resolver, [#139](https://github.com/the-hcma/home-warden/issues/139)), and compare each zone's SOA serial, which `dns-parity` reports.

Exit: no differences.

## Stage 4: dry-run the switch

1. `./scripts/dns-sync --target <new> --old-target <old> --dry-run`. Records listed as not in the catalog still point at the old host and need their own move.
2. Know the limits of `dns-sync` before relying on it. It writes one address type per name (`--target` decides A or AAAA), so a name that has both an A and an AAAA record fails with a "different type" error and must be moved by hand, and `--restore` reports such a name as left for you. It sets `proxied` from `--proxied` (default off), so an orange-cloud name loses its proxy unless you pass `--proxied`; the snapshot does record the old flag and a restore puts it back. List which names these apply to now.
3. Lower the TTLs of the records involved in Cloudflare and wait out the old TTL.
4. Rehearse the rollback on one throwaway name that is a catalog entry: `./scripts/dns-sync --target <new> --service <name>`, then `./scripts/dns-sync --restore <snapshot>` (the snapshot path is printed). Always pass `--service` here, or the rehearsal moves every record. A record the sync created (none existed before) is left for you and makes `--restore` exit 1; delete it by hand.

Exit: rollback rehearsed, time recorded.

## Stage 5: cutover, in order

After each step, check what the public names now resolve to (`dig +short <vhost>`, and from a client outside your network if you can), run `catalog-health-check`, and run `cutover-verify` with both sides set to the address clients now reach. That last run is a smoke test, not a comparison: it reports the status codes it sees on its `ok` lines, so read them, because identical 502s on both sides still compare equal. Wait 15 minutes clean before the next step.

| Step | Action | Rollback |
| --- | --- | --- |
| a | If the CA host changes: `client-pki backup` on the current host, `restore` on the replacement, `client-pki check`, rerun `setup-service`. Enable `home-warden-client-pki-crl.timer` there. | The current host keeps its store untouched until stage 6. Revocations made on the replacement after this step must be replayed on the current host before pointing back. |
| b | Move Cloudflare records: `./scripts/dns-sync --target <new> --old-target <old>` (writes a snapshot first; see the limits in stage 4), or the router's 80/443 forwards. Move by hand any name the tool can't. | `./scripts/dns-sync --restore <snapshot>`, plus whatever you moved by hand, or restore the forwards. |
| c | Point clients' resolver address at the replacement DNS server (DHCP or the router). | Point it back. The current server still serves. |
| d | Stop the state-writing timers on the current host: `catalog-heal`, `home-warden-certbot`, `home-warden-client-pki-crl`. Enable `catalog-heal` on the replacement. | Re-enable them on the current host. |

## Stage 6: soak and decommission

Keep the current host up but idle for about a week. Watch `catalog-health-check`, the healthcheck mail, one certificate renewal and one CRL refresh on the replacement, and one `zones.yml` edit through the reload gate. Then:

1. Restore the TTLs lowered in stage 4.
2. Delete `scripts/cutover-assess`.
3. On the current host: `systemctl disable --now` the home-warden units, remove its CA copy, and unpin it.
4. Retire tinydns separately ([#175](https://github.com/the-hcma/home-warden/issues/175)).

## Questions the repo can't answer

- Are the upstream apps reachable from the replacement host, or do they move too?
- How do clients learn the replacement's resolver address?
- Does the router or firewall forward 80 and 443 to the replacement?
