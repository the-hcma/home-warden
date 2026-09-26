# tinydns → PowerDNS GeoIP migration

Converts `thehcma/home`'s tinydns-format `dns/data` into the PowerDNS
GeoIP-backend `zones.yml` + a matching `pdns.conf`, per
[the-hcma/home-warden#108](https://github.com/the-hcma/home-warden/issues/108)
(relocating the design from `thehcma/home#16`, a private repo). This doc
also covers installing `pdns-server`/`pdns-recursor` and the reload-on-edit
wiring.

**Dedicated account: already handled.** Debian/Ubuntu's `pdns-server`
package creates its own system account (`pdns`) via `adduser` in its
postinst script and runs `pdns.service` as that account by default (the
recursor runs as the same `pdns` user on Debian-likes too) — home-warden
does not need to author a privilege-separation unit the way it did for
nginx (whose socket-activation trick exists specifically to bind
privileged ports without running nginx as root; the distro's own pdns
packaging already solves the equivalent problem). See
[#43](https://github.com/the-hcma/home-warden/issues/43) for the same
question, still open, on nginx's own account.

## What it does

- Parses exactly the tinydns line types `thehcma/home#16` identified as
  actually used: SOA (`Z`), NS with optional glue A (`&`), A+PTR (`=`),
  A-only (`+`), TXT (`'`), CNAME (`C`), and SRV via the generic record
  line (`:` type `33`, octal-escaped wire rdata). Any other line type is
  a loud error, not a silently-dropped record.
- Buckets every record under the longest-matching zone apex, from the
  file's own `Z` (SOA) lines — the same apex-first, longest-match logic
  `app.catalog_checks.candidate_zone_names` uses for Cloudflare zone
  lookups, but against a closed set already known from the file.
- Renders `zones.yml` (PowerDNS GeoIP-backend zone YAML — `launch=geoip`,
  no MaxMind/geo expansions, plain `records:` only) and `pdns.conf`
  (pointing the authoritative server at **loopback:853 only** — the
  recursor, unchanged, is what answers the real `:53` and forwards
  queries for these zones to loopback:853).

## Usage

```bash
./scripts/dns-tinydns-convert path/to/dns/data --outdir /path/to/output
# writes /path/to/output/zones.yml and /path/to/output/pdns.conf
```

Run once against `thehcma/home`'s real `dns/data` to bootstrap the
initial `zones.yml`; from then on, edit `zones.yml` directly (it becomes
the source of truth, replacing `dns/data`) — don't re-run the converter
against a stale tinydns file.

## Validating a conversion (or a later hand-edit) for real

Per this repo's "validate by actually running it" standard — a generator
that only produces syntactically-plausible YAML isn't enough:

- **Local dev** (any machine with PowerDNS installed, including macOS via
  `brew install pdns`): `app.dns_zone_validate.validate_via_sqlite_backend`
  loads the parsed records into an ephemeral `pdns_server` (via
  `pdnsutil zone load`, gsqlite3 backend) and `dig`-verifies every record.
  This proves the *record data* is DNS-correct on any backend — it does
  not exercise the real GeoIP YAML file, since Homebrew's `pdns` bottle
  doesn't ship the `geoip` module.
- **CI / real acceptance test**: `.github/ci/dns-catalog-validate`
  installs the actual Ubuntu `pdns-server` + `pdns-backend-geoip`
  packages, converts a fixture tinydns file, and runs the genuinely
  generated `zones.yml`/`pdns.conf` through a real `pdns_server`,
  `dig`-verifying every record type. This is the authoritative check for
  the GeoIP YAML shape itself.

Before trusting a migration or a hand-edit against the real host's zone
data, run the equivalent of the CI check locally if PowerDNS with the
`geoip` backend module is available (e.g. on an Ubuntu box), or at least
the sqlite-backend check above to catch record-level mistakes.

## Record mapping reference

| tinydns prefix | Meaning | Converted to |
| --- | --- | --- |
| `Z` | SOA | `soa:` (single value) — also sets the zone's default `ttl:` |
| `&` | NS (+ optional glue A) | `ns:` on the owner; `a:` on the nameserver name if an IP is given |
| `=` | A + PTR | `a:` on the forward name; `ptr:` on the synthesized reverse name |
| `+` | A only | `a:` |
| `'` | TXT | `txt:` — content includes literal surrounding quotes (PowerDNS's own convention; confirmed by running a converted record through a real server, not assumed) |
| `C` | CNAME | `cname:` (single value) |
| `:` type `33` | SRV | `srv:` — `"priority weight port target."` |

Known, deliberate non-goals (per `thehcma/home#16`): geo-routing/MaxMind,
DNSSEC, any tinydns line type not in the table above.

## Packages (Ubuntu/Debian)

```bash
sudo apt-get install pdns-server pdns-backend-geoip pdns-recursor
```

No MaxMind/GeoLite database is needed — `render_pdns_conf` emits
`geoip-database-files=` empty, and this repo's design deliberately never
uses geo expansions (plain `records:` only). `dns/recursor.conf` (in
`thehcma/home`) stays hand-maintained; it must forward every zone in
`zones.yml` to loopback:853. The reload-on-edit path below checks that on
every run and names any zone it's missing.

`pdns-server` does not pull in `pdns-backend-geoip`, and its stock
`/etc/powerdns/pdns.conf` binds `0.0.0.0:53`, which crash-loops against the
recursor and `systemd-resolved` on the same host. `apt` restarts pdns as
part of installing the backend, so expect that restart to fail until the
generated `pdns.conf` replaces the stock one:

```bash
sudo cp -a /etc/powerdns/pdns.conf /etc/powerdns/pdns.conf.dist
sudo install -o root -g pdns -m 640 <outdir>/pdns.conf /etc/powerdns/pdns.conf
```

Point `geoip-zones-file=` in that copy at the live `zones.yml` (the
converter writes the path of the file it just generated).

Recursor pitfalls found on the designated host (#128), for the
hand-maintained `recursor.conf`:

- **DNSSEC.** Recursor ≥ 4.5 validates whenever a client sets the AD or DO
  bit (`dig` and glibc's `trust-ad` both set AD). A forwarded zone under a
  TLD the root proves nonexistent (a made-up internal TLD) then comes back
  bogus, i.e. `SERVFAIL`. Add a negative trust anchor per such zone
  (`dnssec.negative_trustanchors` in YAML config, `rec_control add-nta` at
  runtime). Zones under a real, unsigned parent, and RFC 1918 reverse zones,
  are unaffected.
- **Old-style `forward-zones=`.** `;` separates extra forwarders for the
  *same* zone, not a fallback list: `a=127.0.0.1:853;1.1.1.1` also sends
  zone `a` to 1.1.1.1. Pdns-recursor 5.x can print the YAML equivalent of
  an old-style file with `rec_control show-yaml <file>`, which makes this
  visible.

## Install and reload-on-edit wiring

`scripts/setup-service` installs and enables the reload units
(`etc/systemd/home-warden-pdns-reload.path`/`.service`) automatically,
the same way it already manages `home-warden-reload.path` for nginx —
opt-in via `PDNS_ZONES_YAML`:

```bash
PDNS_ZONES_YAML=/path/to/thehcma/home/dns/zones.yml ./scripts/setup-service
```

When `zones.yml` lives under `/home`, `setup-service` also installs a
`pdns.service` drop-in (`/etc/systemd/system/pdns.service.d/home-warden.conf`:
`ProtectHome=tmpfs` plus a read-only bind of the `zones.yml` directory),
because the distro unit's `ProtectHome=true` otherwise hides the file from
pdns entirely. It restarts pdns only when the drop-in changes. It refuses a
directory that isn't a specific, non-hidden path under `/home/<user>/` (the
same allowlist as nginx's sandbox binds), and fails unless the `pdns`
account can search the directory and read the file, through world bits or
through a group it belongs to (e.g. `chgrp pdns` plus `g+r`). It also fails
on a `PDNS_ZONES_YAML` that goes through a symlink, since pdns can't follow
one out of its sandbox — point it at the real path. If `zones.yml` later
moves out of `/home`, the next `setup-service` run removes the drop-in.

Skipped (with a message, not an error) when `PDNS_ZONES_YAML` is unset and
the default `~/home/dns/zones.yml` doesn't exist either — installing
`pdns-server` itself and populating `zones.yml` both stay manual steps
(see Packages above); this wiring only covers the reload-on-edit path once
those are in place. `./scripts/setup-service --status` reports the
resolved `zones.yml` path and the `pdns_reload_path` unit's
enabled/active state alongside everything else it already tracks.

From then on, editing `zones.yml` triggers
`scripts/pdns-test-and-reload`: a lightweight, offline
`dns-zones-yaml-check` syntax/shape gate (see that script and
`app.dns_tinydns_convert.validate_zones_yaml_syntax` — it catches a typo
or a renamed key, not a deeper semantic mistake like the list-vs-dict
records shape bug this repo's own CI once caught), then
[`pdns_control reload`](https://doc.powerdns.com/authoritative/backends/geoip.html)
— the documented way to make the GeoIP backend pick up a rewritten YAML
file without a full restart. Note this calls `pdns_control reload`
directly, **not** `systemctl reload pdns.service` — the distro-packaged
unit doesn't implement systemd's reload verb at all ("Job type reload is
not applicable for unit pdns.service").

The reload unit runs as root (for `pdns_control`), but the syntax gate is a
`uv run` in this repo, so the script drops to `OWNER` (the operator) via
`runuser` for that step. `uv` is looked up in the operator's
`~/.local/bin` (the astral.sh installer default) before the system `PATH`.
After `pdns_control reload`, it runs `pdns_control purge`, since reload
keeps pdns's packet and negative caches.

When `pdns-recursor.service` is installed and active, the same run then:

1. runs `rec_control reload-zones`, which rereads `forward_zones` from the
   recursor's config, so a zone just added there takes effect without a
   restart;
2. wipes the recursor's cache for each zone in `zones.yml`
   (`rec_control wipe-cache <zone>$`), so a removed record stops answering
   immediately instead of after its TTL;
3. asks the recursor (on `127.0.0.1`, with the AD bit set) for each zone's
   SOA and compares it with the authoritative server's, and exits 3 if any
   zone doesn't match. A zone that also exists publicly would otherwise
   pass by resolving upstream. For each such zone it logs the exact fix: the
   `forward_zones` entry to add for `NXDOMAIN` or a different SOA, or a
   negative trust anchor for a DNSSEC `SERVFAIL` (see Recursor pitfalls
   above).

So adding a new zone apex to `zones.yml` fails the reload unit until the
recursor forwards it. Add the zone to the recursor's config, then touch
`zones.yml` to rerun the check. `PDNS_RECURSOR_SERVICE`,
`PDNS_RECURSOR_ADDRESS` and `PDNS_AUTH_FORWARDER` override the unit name,
the probe address and the suggested forwarder. A host with no recursor
installed skips these steps.

Logs: `~/scratch/home-warden/pdns-test-and-reload.log`.

## Host resolver

nginx resolves `upstream.host` through the host's own resolver, not by
asking PowerDNS directly. On a stock Ubuntu host that's `systemd-resolved`,
which forwards everything to the DHCP-provided LAN resolvers and never
consults the local recursor. A name that exists only in `zones.yml` then
answers on loopback:853 but can't be resolved on the host itself (#139).

`check_local_dns` (used by `catalog-register`, `catalog-heal` and
`catalog-health-check`) catches this: once the authoritative server has the
record, it also resolves the name via `getent ahosts` and fails with
"local PowerDNS has … but this host cannot resolve it" if that doesn't work.

To fix it, route the local zones to the recursor on `127.0.0.1` with a
`systemd-resolved` drop-in, one `~` routing domain per zone apex in
`zones.yml`:

```ini
# /etc/systemd/resolved.conf.d/home-warden-local-zones.conf
[Resolve]
DNS=127.0.0.1
Domains=~<your-zone> ~<reverse-zone>.in-addr.arpa
```

Then run `sudo systemctl restart systemd-resolved` and confirm with
`resolvectl query <name>.<your-zone>`. The `~` prefix makes these routing
domains, so queries under them are sent to the recursor rather than the LAN
resolvers.

## Spot-checking a live install

```bash
dig @127.0.0.1 -p 853 <name>.<your-zone> A      # loopback auth server directly
dig @<lan-ip> <name>.<your-zone> A              # via the recursor, the real path
dig @127.0.0.1 -p 853 <ptr-name>.in-addr.arpa PTR
dig @127.0.0.1 -p 853 _kerberos.<your-zone> TXT
dig @127.0.0.1 -p 853 _ldap._tcp.<your-zone> SRV
```

Substitute the real internal zone name(s) from `thehcma/home` (private
repo) — deliberately not written out here, per
`.cursor/rules/no-private-infra.mdc`.

## Dropping the tinydns backend after cutover

Once the GeoIP backend has been running cleanly for a while, `pdns-backend-tinydns`
/ `tinydns-data` can be removed from the host — keep them installed until
that's actually confirmed, per `thehcma/home#16`'s own acceptance
criteria.
