# tinydns → PowerDNS GeoIP migration

Converts `thehcma/home`'s tinydns-format `dns/data` into the PowerDNS GeoIP-backend `zones.yml` + a matching `pdns.conf`, per [the-hcma/home-warden#108](https://github.com/the-hcma/home-warden/issues/108) (relocating the design from `thehcma/home#16`, a private repo). This doc also covers installing `pdns-server`/`pdns-recursor` and the reload-on-edit wiring.

**Dedicated account: already handled.** Debian/Ubuntu's `pdns-server` package creates its own system account (`pdns`) via `adduser` in its postinst script and runs `pdns.service` as that account by default (the recursor runs as the same `pdns` user on Debian-likes too) — home-warden does not need to author a privilege-separation unit the way it did for nginx (whose socket-activation trick exists specifically to bind privileged ports without running nginx as root; the distro's own pdns packaging already solves the equivalent problem). See [#43](https://github.com/the-hcma/home-warden/issues/43) for the same question, still open, on nginx's own account.

## What it does

- Parses exactly the tinydns line types `thehcma/home#16` identified as actually used: SOA (`Z`), NS with optional glue A (`&`), A+PTR (`=`), A-only (`+`), TXT (`'`), CNAME (`C`), and SRV via the generic record line (`:` type `33`, octal-escaped wire rdata). Any other line type is skipped and reported, never silently dropped.
- Buckets every record under the longest-matching zone apex, from the file's own `Z` (SOA) lines — the same apex-first, longest-match logic `app.catalog_checks.candidate_zone_names` uses for Cloudflare zone lookups, but against a closed set already known from the file.
- Renders `zones.yml` (PowerDNS GeoIP-backend zone YAML — `launch=geoip`, no MaxMind/geo expansions, plain `records:` only) and `pdns.conf` (pointing the authoritative server at **loopback:853 only** — the recursor, unchanged, is what answers the real `:53` and forwards queries for these zones to loopback:853).

## Usage

```bash
./scripts/dns-tinydns-convert path/to/dns/data --outdir /path/to/output
# writes /path/to/output/zones.yml and /path/to/output/pdns.conf
```

## Which file is the source of truth

The migration has two phases, and the generated `zones.yml` header doesn't assume either one ([#169](https://github.com/the-hcma/home-warden/issues/169)).

**Phase 1: `data` is the source of truth.** Use this while tinydns still serves the zones anywhere. Edit `data`, run the converter, and let the reload unit pick up the regenerated `zones.yml`. Don't hand-edit `zones.yml`: the next conversion overwrites it, as its header says. The generated file can be gitignored in the served-config repo in this phase. Make the changes the converter's warning block asks for in `data`.

**Phase 2: `zones.yml` is the source of truth.** Edit `zones.yml`, check it against the last committed copy, and commit:

```bash
dns-zones-yaml-check --previous <(git show HEAD:dns/zones.yml) dns/zones.yml
```

The reload unit runs the same gate, without `--previous`, before every reload.

**Switching from phase 1 to phase 2:**

1. Convert once more and work through the warning block until only findings you accept are left. Nothing marked "blocks reload" can stay.
2. Delete the generated header lines from `zones.yml`.
3. Stop gitignoring `zones.yml`, and commit it.
4. Once every DNS server serves from `zones.yml` (see [Serving the same zones from several DNS servers](#serving-the-same-zones-from-several-dns-servers)), delete `data` and stop running the converter. From then on it is only an import tool.

## Validating a conversion (or a later hand-edit) for real

Per this repo's "validate by actually running it" standard — a generator that only produces syntactically-plausible YAML isn't enough:

- **Local dev** (any machine with PowerDNS installed, including macOS via `brew install pdns`): `app.dns_zone_validate.validate_via_sqlite_backend` loads the parsed records into an ephemeral `pdns_server` (via `pdnsutil zone load`, gsqlite3 backend) and `dig`-verifies every record. This proves the *record data* is DNS-correct on any backend — it does not exercise the real GeoIP YAML file, since Homebrew's `pdns` bottle doesn't ship the `geoip` module.
- **CI / real acceptance test**: `.github/ci/dns-catalog-validate` installs the actual Ubuntu `pdns-server` + `pdns-backend-geoip` packages, converts a fixture tinydns file, and runs the genuinely generated `zones.yml`/`pdns.conf` through a real `pdns_server`, `dig`-verifying every record type. This is the authoritative check for the GeoIP YAML shape itself.

Before trusting a migration or a hand-edit against the real host's zone data, run the equivalent of the CI check locally if PowerDNS with the `geoip` backend module is available (e.g. on an Ubuntu box), or at least the sqlite-backend check above to catch record-level mistakes.

## Lint findings

The converter is best effort and imports everything it can. It skips, instead of failing the run: a line it can't parse, a record no `Z` line's zone contains, a zone whose `Z` line has no ttl, and a CNAME that shares its name with other records (it keeps the other records, and the first of two CNAMEs), so the `zones.yml` it writes never has a finding that blocks reload. It then lints the `zones.yml` it wrote (`app.dns_zones_lint`, [#169](https://github.com/the-hcma/home-warden/issues/169)) and prints every skip and finding in one warning block at the end, each with what to change. `dns-zones-yaml-check` runs the same lint on a hand-edited `zones.yml`.

| Finding | Blocks reload |
| --- | --- |
| A CNAME sharing its name with other records, or two CNAMEs at one name (RFC 1034 section 3.6.2) | yes |
| The same record listed twice at one name | no |
| An A with no PTR, when its reverse zone is served here | no |
| A PTR whose target has no matching A, when the target's zone is served here | no |
| A name listed under a zone it isn't inside | no |
| A zone with no SOA at its apex, more than one, an SOA away from the apex, or an SOA missing a field | no |
| A zone whose records changed without its SOA serial going up (only with `--previous`) | no |

A CNAME conflict can therefore only reach the gate through a hand-edit of `zones.yml`. A finding that blocks reload makes `dns-zones-yaml-check` exit 2, so `scripts/pdns-test-and-reload` refuses the file and the server keeps what it last loaded. Everything else is served as written and only reported. For the serial check, pass the last-served copy, e.g. `dns-zones-yaml-check --previous <(git show HEAD:dns/zones.yml) dns/zones.yml`.

An address with several names needs only one PTR, so an A is not flagged as long as its reverse name has any PTR.

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

Known, deliberate non-goals (per `thehcma/home#16`): geo-routing/MaxMind, DNSSEC, any tinydns line type not in the table above.

## Packages (Ubuntu/Debian)

```bash
sudo apt-get install pdns-server pdns-backend-geoip pdns-recursor bind9-dnsutils
```

`bind9-dnsutils` provides `dig`, which the reload-on-edit path needs to verify the recursor (see below); without it, that path fails.

No MaxMind/GeoLite database is needed — `render_pdns_conf` emits `geoip-database-files=` empty, and this repo's design deliberately never uses geo expansions (plain `records:` only). `dns/recursor.conf` (in `thehcma/home`) stays hand-maintained; it must forward every zone in `zones.yml` to loopback:853. The reload-on-edit path below checks that on every run and names any zone it's missing.

`pdns-server` does not pull in `pdns-backend-geoip`, and its stock `/etc/powerdns/pdns.conf` binds `0.0.0.0:53`, which crash-loops against the recursor and `systemd-resolved` on the same host. `apt` restarts pdns as part of installing the backend, so expect that restart to fail until the generated `pdns.conf` replaces the stock one:

```bash
sudo cp -a /etc/powerdns/pdns.conf /etc/powerdns/pdns.conf.dist
sudo install -o root -g pdns -m 640 <outdir>/pdns.conf /etc/powerdns/pdns.conf
```

Point `geoip-zones-file=` in that copy at the live `zones.yml` (the converter writes the path of the file it just generated).

Recursor pitfalls found on the designated host (#128), for the hand-maintained `recursor.conf`:

- **DNSSEC.** Recursor ≥ 4.5 validates whenever a client sets the AD or DO bit (`dig` and glibc's `trust-ad` both set AD). A forwarded zone under a TLD the root proves nonexistent (a made-up internal TLD) then comes back bogus, i.e. `SERVFAIL`. Add a negative trust anchor per such zone (`dnssec.negative_trustanchors` in YAML config, `rec_control add-nta` at runtime). Zones under a real, unsigned parent, and RFC 1918 reverse zones, are unaffected.
- **Old-style `forward-zones=`.** `;` separates extra forwarders for the *same* zone, not a fallback list: `a=127.0.0.1:853;1.1.1.1` also sends zone `a` to 1.1.1.1. Pdns-recursor 5.x can print the YAML equivalent of an old-style file with `rec_control show-yaml <file>`, which makes this visible.

## Install and reload-on-edit wiring

`scripts/setup-service` installs and enables the reload units (`etc/systemd/home-warden-pdns-reload.path`/`.service`) automatically, the same way it already manages `home-warden-reload.path` for nginx — opt-in via `PDNS_ZONES_YAML`:

```bash
PDNS_ZONES_YAML=/path/to/thehcma/home/dns/zones.yml ./scripts/setup-service
```

When `zones.yml` lives under `/home`, `setup-service` also installs a `pdns.service` drop-in (`/etc/systemd/system/pdns.service.d/home-warden.conf`: `ProtectHome=tmpfs` plus a read-only bind of the `zones.yml` directory), because the distro unit's `ProtectHome=true` otherwise hides the file from pdns entirely. It restarts pdns only when the drop-in changes. It refuses a directory that isn't a specific, non-hidden path under `/home/<user>/` (the same allowlist as nginx's sandbox binds), and fails unless the `pdns` account can search the directory and read the file, through world bits or through a group it belongs to (e.g. `chgrp pdns` plus `g+r`). It also fails on a `PDNS_ZONES_YAML` that goes through a symlink, since pdns can't follow one out of its sandbox — point it at the real path. If `zones.yml` later moves out of `/home`, the next `setup-service` run removes the drop-in.

Skipped (with a message, not an error) when `PDNS_ZONES_YAML` is unset and the default `~/home/dns/zones.yml` doesn't exist either — installing `pdns-server` itself and populating `zones.yml` both stay manual steps (see Packages above); this wiring only covers the reload-on-edit path once those are in place. `./scripts/setup-service --status` reports the resolved `zones.yml` path and the `pdns_reload_path` unit's enabled/active state alongside everything else it already tracks.

From then on, editing `zones.yml` triggers `scripts/pdns-test-and-reload`: an offline `dns-zones-yaml-check` gate (see that script, `app.dns_tinydns_convert.validate_zones_yaml_syntax` for the shape check, and `app.dns_zones_lint` for the record lint described under [Lint findings](#lint-findings)), then [`pdns_control reload`](https://doc.powerdns.com/authoritative/backends/geoip.html) — the documented way to make the GeoIP backend pick up a rewritten YAML file without a full restart. Note this calls `pdns_control reload` directly, **not** `systemctl reload pdns.service` — the distro-packaged unit doesn't implement systemd's reload verb at all ("Job type reload is not applicable for unit pdns.service").

The reload unit runs as root (for `pdns_control`), but the syntax gate is a `uv run` in this repo, so the script drops to `OWNER` (the operator) via `runuser` for that step. `uv` is looked up in the operator's `~/.local/bin` (the astral.sh installer default) before the system `PATH`. After `pdns_control reload`, it runs `pdns_control rediscover`, then `pdns_control purge`. Reload rereads the YAML but not pdns's zone cache, the list of zones it is authoritative for, which pdns otherwise refreshes every `zone-cache-refresh-interval` seconds (default 300). Without `rediscover`, a new zone apex answers `REFUSED` and a removed one keeps answering until that refresh; both were confirmed on pdns 5.0.2 with the GeoIP backend (#145). The purge then drops the packet and negative caches, which reload also keeps, including a `REFUSED` cached before the rediscover.

When `pdns-recursor.service` is installed and active, the same run then:

1. runs `rec_control reload-zones`, which rereads `forward_zones` from the recursor's config, so a zone just added there takes effect without a restart;
2. wipes the recursor's cache for each zone in `zones.yml` (`rec_control wipe-cache <zone>$`), so a removed record stops answering immediately instead of after its TTL;
3. asks the recursor (on `127.0.0.1`, with the AD bit set) for each zone's SOA and compares it with the authoritative server's, and exits 3 if any zone doesn't match. A zone that also exists publicly would otherwise pass by resolving upstream. For each such zone it logs the exact fix: the `forward_zones` entry to add for `NXDOMAIN` or a different SOA, or a negative trust anchor for a DNSSEC `SERVFAIL` (see Recursor pitfalls above). A missing `dig` also exits 3, since the check can't run.

So adding a new zone apex to `zones.yml` fails the reload unit until the recursor forwards it. Add the zone to the recursor's config, then touch `zones.yml` to rerun the check. `PDNS_RECURSOR_SERVICE`, `PDNS_RECURSOR_ADDRESS` and `PDNS_AUTH_FORWARDER` override the unit name, the probe address and the suggested forwarder. A host with no recursor installed skips these steps.

Logs: `~/scratch/home-warden/pdns-test-and-reload.log`.

## Host resolver

nginx resolves `upstream.host` through the host's own resolver, not by asking PowerDNS directly. On a stock Ubuntu host that's `systemd-resolved`, which forwards everything to the DHCP-provided LAN resolvers and never consults the local recursor. A name that exists only in `zones.yml` then answers on loopback:853 but can't be resolved on the host itself (#139).

`check_local_dns` (used by `catalog-register`, `catalog-heal` and `catalog-health-check`) catches this: once the authoritative server has the record, it also resolves the name via `getent ahosts` and fails with "local PowerDNS has … but this host cannot resolve it" if that doesn't work.

To fix it, route the local zones to the recursor on `127.0.0.1` with a `systemd-resolved` drop-in, one `~` routing domain per zone apex in `zones.yml`. `setup-service` writes it for you when pdns wiring is on:

```bash
PDNS_HOST_RESOLVER=1 ./scripts/setup-service
```

It lists the zones from `zones.yml`, requires `systemd-resolved` and `pdns-recursor` to be active, and restarts `systemd-resolved` only when the drop-in changes. Re-run it with `PDNS_HOST_RESOLVER=1` after adding a zone apex. `PDNS_HOST_RESOLVER=0` removes the drop-in, but only one that starts with the `# GENERATED by home-warden` line. When the variable is unset, `setup-service` leaves an existing drop-in as it is, so a re-run that forgets the variable doesn't silently drop host-wide DNS routing. `PDNS_RECURSOR_ADDRESS` overrides the `127.0.0.1` it points at, and `PDNS_RECURSOR_SERVICE` the recursor unit it requires to be active.

The generated file, `/etc/systemd/resolved.conf.d/home-warden-local-zones.conf`, looks like this. You can write it by hand if you'd rather not opt in; drop the first line if `PDNS_HOST_RESOLVER=0` should leave your copy alone.

```ini
# GENERATED by home-warden scripts/setup-service -- do not edit.
[Resolve]
DNS=127.0.0.1
Domains=~<your-zone> ~<reverse-zone>.in-addr.arpa
```

Then run `sudo systemctl restart systemd-resolved` and confirm with `resolvectl query <name>.<your-zone>`. The `~` prefix makes these routing domains, so queries under them are sent to the recursor rather than the LAN resolvers.

## Spot-checking a live install

```bash
dig @127.0.0.1 -p 853 <name>.<your-zone> A      # loopback auth server directly
dig @<lan-ip> <name>.<your-zone> A              # via the recursor, the real path
dig @127.0.0.1 -p 853 <ptr-name>.in-addr.arpa PTR
dig @127.0.0.1 -p 853 _kerberos.<your-zone> TXT
dig @127.0.0.1 -p 853 _ldap._tcp.<your-zone> SRV
```

Substitute the real internal zone name(s) from `thehcma/home` (private repo) — deliberately not written out here, per `.cursor/rules/no-private-infra.mdc`.

## Serving the same zones from several DNS servers

Every DNS server that serves these zones runs its own copy of the setup this doc describes: `pdns-server` + `pdns-backend-geoip` on loopback:853 behind its own `pdns-recursor`, from its own copy of the same `zones.yml`, with the same reload gate (`setup-service` with `PDNS_ZONES_YAML`). There is no zone transfer, so each server keeps answering when the others are down.

- **Distribution**: each server pulls the served-config repo, and its reload unit checks and reloads `zones.yml` when the file changes. A file that fails the gate is refused on that server, which keeps serving what it last loaded.
- **Staleness**: a server that hasn't pulled yet serves the previous version. Compare each zone's SOA serial across servers (`dig @<server> <zone> SOA +short`) to spot one left behind. This only works if every change bumps the serial, which `dns-zones-yaml-check --previous` checks.
- **Validation**: before switching a server from tinydns, run the checks from [Validating a conversion](#validating-a-conversion-or-a-later-hand-edit-for-real) on that server's own OS and PowerDNS packages, and compare its answers against tinydns.

Rolling this out to the other servers and retiring tinydns is tracked in [#175](https://github.com/the-hcma/home-warden/issues/175).

## Dropping the tinydns backend after cutover

Once the GeoIP backend has been running cleanly for a while, `pdns-backend-tinydns` / `tinydns-data` can be removed from the host — keep them installed until that's actually confirmed, per `thehcma/home#16`'s own acceptance criteria.
