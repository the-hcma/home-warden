# tinydns → PowerDNS GeoIP migration

Converts `thehcma/home`'s tinydns-format `dns/data` into the PowerDNS
GeoIP-backend `zones.yml` + a matching `pdns.conf`, per
[the-hcma/home-warden#108](https://github.com/the-hcma/home-warden/issues/108)
(relocating the design from `thehcma/home#16`, a private repo). This doc
covers the converter itself; running `pdns-server`/`pdns-recursor` as
systemd units under a dedicated account lands as a follow-up once #108's
own systemd-wiring half is scoped (see that issue for the current split).

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
