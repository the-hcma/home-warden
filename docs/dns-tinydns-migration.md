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
`thehcma/home`) stays hand-maintained and unchanged; it already forwards
these zones' queries to loopback:853.

## Install and reload-on-edit wiring

`scripts/setup-service` installs and enables the reload units
(`etc/systemd/home-warden-pdns-reload.path`/`.service`) automatically,
the same way it already manages `home-warden-reload.path` for nginx —
opt-in via `PDNS_ZONES_YAML`:

```bash
PDNS_ZONES_YAML=/path/to/thehcma/home/dns/zones.yml ./scripts/setup-service
```

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

Logs: `~/scratch/home-warden/pdns-test-and-reload.log`.

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
