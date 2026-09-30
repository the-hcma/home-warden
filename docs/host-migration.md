# Moving the front door to a replacement host

How to move nginx, certificates, DNS and the client CA from the current host to a replacement without an outage, and how to go back. The epic is [#191](https://github.com/the-hcma/home-warden/issues/191). Hostnames and addresses are placeholders here, per `.cursor/rules/no-private-infra.mdc`.

Stages 0 to 3 change nothing live. Do not start a stage until the previous stage's exit criterion holds. Every rollback below is a single action, and is only as fast as the DNS TTLs you lowered in stage 4.

## Tools

| Tool | Stage | What it answers |
| --- | --- | --- |
| `scripts/cutover-preflight` | 1 | Can this host take over? Read-only. |
| `scripts/cutover-verify --old A --new B` | 2, 5 | Does the replacement serve each vhost the way the current host does? |
| `scripts/dns-parity --old A --new B` | 3, 5 | Does the replacement DNS server answer every `zones.yml` record the way the current one does? |
| `scripts/dns-sync --target <new> --old-target <old>` | 4, 5 | Moves the Cloudflare records, saving a snapshot first, and lists records outside the catalog still pointing at the old host. |
| `scripts/dns-sync --restore <snapshot>` | rollback | Puts the snapshotted records back. |
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
| `home-warden-certbot.timer` | on | on (each renews its own lineages) |
| `home-warden-healthcheck.timer` | on | on, so both mail on their own failure |
| `home-warden-catalog-heal.timer` | on | **off** until stage 5d; it never applies DNS, but two alert senders are noise |
| `home-warden-client-pki-crl.timer` | on (CA lives here) | off until the CA is restored there |
| `catalog-heal --apply-dns` by hand | never during the overlap | only after stage 5 |

Only one host may write Cloudflare records at a time.

## Stage 0: CI green on main

Exit: green.

## Stage 1: readiness on the replacement (no traffic)

1. Install the prerequisites in [host-prerequisites.md](./host-prerequisites.md), then `./scripts/setup-service --confirm-host`.
2. Put the items from the table above in place, except the client CA.
3. `./scripts/cutover-preflight`. Add `--skip-certbot-dry-run` if you want to avoid Let's Encrypt staging for now.
4. Fix every `FAIL`. A `FAIL` on an upstream means the app isn't reachable from this host: either the app moves too, or the served conf points at an address that is routable from both hosts. A `WARN` for a vhost missing from the catalog is informational: the catalog-driven checks won't cover it.

Exit: no `FAIL`.

## Stage 2: shadow nginx

```bash
./scripts/cutover-verify --old <old-ipv4> --new <new-ipv4> [--old6 <old-ipv6> --new6 <new-ipv6>] [--host <vhost-not-in-catalog>]
```

Differences that are expected: certificate serial and `notAfter` (reported, never flagged). Everything else, including a missing security header or a different redirect, is a finding.

For each vhost with `client_cert: required`, run it again with a throwaway certificate from `scripts/client-pki` (`--client-cert`/`--client-key`), and then with a revoked one after `revoke` and a reload. Both hosts must accept the first and reject the second. The CA is restored on the replacement only at stage 5, so until then a parity difference here is expected for the accepted case.

Exit: no unexpected differences over IPv4 and IPv6.

## Stage 3: shadow DNS

On the replacement, `pdns-server` and `pdns-recursor` are installed and loaded from the same `zones.yml` ([dns-tinydns-migration.md](./dns-tinydns-migration.md)). Compare both the recursors (the path clients use) and, on each host, the authoritative server:

```bash
./scripts/dns-parity --old <old-recursor> --new <new-recursor> \
  --probe <a-public-name> --probe <a-name-that-must-be-nxdomain>
./scripts/dns-parity --old 127.0.0.1:853 --new <new-host>:853   # only if 853 is reachable; otherwise run it on each host
```

Also on the replacement: `getent ahosts <upstream.host>` for each internal upstream (the host resolver, [#139](https://github.com/the-hcma/home-warden/issues/139)), and compare each zone's SOA serial, which `dns-parity` reports.

Exit: no differences.

## Stage 4: dry-run the switch

1. `./scripts/dns-sync --target <new> --old-target <old> --dry-run`. Records listed as not in the catalog still point at the old host and need their own move.
2. Lower the TTLs of the records involved in Cloudflare and wait out the old TTL.
3. Rehearse the rollback on one throwaway name: sync it, then `dns-sync --restore` the snapshot. A record the sync created (none existed before) is reported by the restore but not deleted; remove it by hand.

Exit: rollback rehearsed, time recorded.

## Stage 5: cutover, in order

After each step, run `cutover-verify` against the public names (both `--old` and `--new` the same public address) and `catalog-health-check`. Wait 15 minutes clean before the next step.

| Step | Action | Rollback |
| --- | --- | --- |
| a | If the CA host changes: `client-pki backup` on the current host, `restore` on the replacement, `client-pki check`, rerun `setup-service`. Enable `home-warden-client-pki-crl.timer` there. | The current host keeps its store untouched until stage 6. Revocations made on the replacement after this step must be replayed on the current host before pointing back. |
| b | Move Cloudflare records: `./scripts/dns-sync --target <new> --old-target <old>` (writes a snapshot first), or the router's 80/443 forwards. | `./scripts/dns-sync --restore <snapshot>`, or restore the forwards. |
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
