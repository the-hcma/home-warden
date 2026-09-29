# Private client-certificate CA

home-warden runs a small private certificate authority whose only job is to issue **mTLS client certificates**: a device presents one to nginx, and nginx lets it reach a gated vhost only if the certificate is valid, unrevoked, and (optionally) carries an allowed common name. This page explains what the CA is for, what it does and doesn't protect against, and where each piece of its lifecycle is tracked. The epic is [#49](https://github.com/the-hcma/home-warden/issues/49).

The CA is built on [`tiny-pki`](https://github.com/the-hcma/tiny-pki) (pinned to its PyPI release in `pyproject.toml`) and operated through `scripts/client-pki`, a thin wrapper that pins tiny-pki to home-warden's store. [Running the CA](#running-the-ca) covers where it lives, how its key is protected, backups, and CA rotation.

## Purpose

A client certificate is the **first gate** in front of a sensitive vhost, and the service's own authentication is the **second**:

1. **Device gate (nginx).** A vhost with `client_cert.mode: required` refuses any request that doesn't come with a valid, unrevoked certificate from this CA (and, with `allow_cn`, an allowed common name). nginx answers it with an error itself (400, or 403 for a CN outside `allow_cn`); the request is never proxied, so an unenrolled device can't reach the service's login page, its API, or anything else behind the vhost.
2. **Service authentication.** Only requests from enrolled devices get as far as the service, which then applies its own login (PAM for the admin web UI, whatever a self-hosted app uses).

An attacker therefore has to get hold of an enrolled device's certificate *before* a password is worth anything, and an unpatched login form isn't exposed to the internet at all.

- **First candidate: the admin web UI.** It already requires a PAM login; the certificate goes in front of it. The generated web-UI vhost doesn't expose a `client_cert` setting yet, so until [#161](https://github.com/the-hcma/home-warden/issues/161) wires one up the UI is protected by its login alone.
- **Then every service that shouldn't be reachable from an arbitrary device**, such as admin panels of self-hosted apps, set per catalog entry through the `client_cert` field (see [Catalog wiring](#catalog-wiring)).
- **`optional` is not a gate.** With `mode: optional` nginx lets requests without a certificate through; it's only useful when the backend itself checks the certificate nginx forwards. Gated vhosts use `required`.
- **Public TLS stays with Let's Encrypt.** Server certificates keep coming from `scripts/cert-renewer`. The private CA never signs a certificate a browser is expected to trust for a server.

## Threat model

| Threat | Does a client certificate help? |
| --- | --- |
| A leaked, reused, or guessed password | Yes. Without an enrolled device nginx rejects the request before the login page loads, so the password alone gets nowhere. |
| Drive-by scanning and exploit attempts against admin endpoints | Yes. Unenrolled clients never reach the backend, so an unpatched admin app isn't exposed to the internet. |
| A lost or stolen device | Only after it's revoked. Revoking its serial and publishing the CRL closes the device gate. Until then, the device passes it, and the service's own login is what still stands in the way. |
| A compromised enrolled device (malware with access to the key) | No. The attacker holds a valid certificate. Revocation is the remedy once it's noticed. |
| A compromised host that holds the CA key | No. Whoever holds the key can issue any certificate. Where the key lives, and how it's protected and backed up, is [#158](https://github.com/the-hcma/home-warden/issues/158). |
| Someone reading the traffic | Not the client certificate's job. TLS already encrypts it, with the Let's Encrypt server certificate. |

## Scale and clients

This is a **household CA**: a handful of personal devices (phones, tablets, laptops) belonging to a few people.

- **One certificate per device**, never shared between devices. Losing one device then means revoking one certificate, not re-enrolling everything.
- **The common name names the person and the device**, for example `alice-phone` or `bob-laptop`. That makes the certificate inventory readable and lets a vhost's `allow_cn` list admit specific people or devices.
- Certificates are delivered to devices as password-protected PKCS#12 (`.p12`) files, which iOS, Android, macOS, and desktop browsers can all import.

## Lifecycle overview

| Stage | What happens | Tracked in |
| --- | --- | --- |
| CA setup | Create the CA once on the designated host, keep its key private, back it up encrypted, and rotate the CA itself before it expires. See [Running the CA](#running-the-ca). | [#158](https://github.com/the-hcma/home-warden/issues/158) |
| Enroll | Issue a certificate for a new device and export it as a `.p12`. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Rotate | Issue a replacement while the old certificate keeps working, install it on the device, then revoke the old serial. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Revoke | Revoke a lost or retired device's serial and publish a new CRL; nginx reloads automatically when the CRL changes. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Keep the CRL fresh | Republish the CRL on a timer before it expires (an expired CRL makes nginx reject every client), and alert on CA or CRL expiry. | [#160](https://github.com/the-hcma/home-warden/issues/160) |
| See and edit it | Web UI: CA status, certificate inventory, and `client_cert` editing per catalog entry. | [#161](https://github.com/the-hcma/home-warden/issues/161) |

Already in place on `main`: the nginx sandbox sees a republished CRL ([#148](https://github.com/the-hcma/home-warden/issues/148)), and nginx reloads when the CRL or CA file changes ([#151](https://github.com/the-hcma/home-warden/issues/151)).

## Running the CA

### Where issuing happens

**On the designated host**, the one `scripts/setup-service --confirm-host` pinned. The CA store lives there, in `conf/pki` under the repo checkout by default (`HOME_WARDEN_PKI_STORE` overrides it; `conf/` is gitignored, like `conf/cloudflare.ini`).

The alternative, keeping the CA key on an operator machine and copying only `ca.crt` and `crl.pem` to the host, would keep the key off the internet-facing machine, but every revoke and every CRL refresh would then need a manual sync, and a missed refresh makes nginx reject every client once the CRL expires. On the host, the CRL refresh timer ([#160](https://github.com/the-hcma/home-warden/issues/160)) and revocations take effect without anyone copying files. The cost is the threat-model row above: whoever compromises the host's operator account can issue certificates. The key protection below, and encrypting the key at rest once tiny-pki supports it, are what limit that.

### Creating the CA

```bash
./scripts/client-pki init --cn "Home client CA"
```

That creates the store with tiny-pki's layout. Point a catalog entry's `client_cert.ca_bundle` and `client_cert.crl` at `conf/pki/public/ca.crt` and `conf/pki/public/crl.pem`, then rerun `./scripts/setup-service` so the nginx sandbox binds `public/` and watches it for reloads.

### Key protection

| Path | Mode | Who can read it |
| --- | --- | --- |
| store root, `ca/`, `clients/`, `servers/`, `bundles/` | `0700` | the operator account only |
| `ca/ca.key`, leaf `*.key`, `ca/index.json`, `bundles/*` | `0600` | the operator account only |
| `public/` | `0755` | anyone, including `home-warden-nginx` through the sandbox's bind of that one directory |
| `public/ca.crt`, `public/crl.pem`, other certificates and CRLs | `0644` | readable, but only reachable through `public/` |

tiny-pki writes this layout itself. `scripts/client-pki` checks it before every command and refuses to run when anything is looser, for example a key made group-readable by a careless copy, listing each offending path. It also refuses a `public/` or public file that `home-warden-nginx` couldn't read (a directory tighter than `0755` or a file tighter than `0644`), since the vhost would then fail to load. nginx never sees `ca/`: the sandbox binds only `public/`, so the key isn't readable by `home-warden-nginx` even if a mode slips.

The key is **not encrypted at rest** yet: tiny-pki's store writes it in the clear, protected by these modes. Encryption at rest is [tiny-pki#150](https://github.com/the-hcma/tiny-pki/issues/150); home-warden will adopt it once it lands.

### Backup and restore

Back up the whole store (CA key, index, serial and CRL state, issued certificates) as a `gpg --symmetric` (AES-256) archive. The passphrase comes from a file readable only by you, never from the command line:

```bash
./scripts/client-pki backup --out ~/backups/client-pki-$(date +%F).tar.gpg --passphrase-file ~/.config/home-warden/pki-backup-passphrase
```

The backup takes a shared lock on the store, so it never captures a half-finished revoke, refuses to overwrite an existing file, writes the archive `0600`, and decrypts it again before reporting success. Copy it off the host to wherever your other backups go, and keep the passphrase somewhere other than the archive (a password manager). Take a new backup after every enroll or revoke; an old backup restores an old revocation list.

To restore, onto the same host or a replacement:

```bash
./scripts/client-pki restore --in client-pki-2026-09-28.tar.gpg --passphrase-file ~/.config/home-warden/pki-backup-passphrase
```

Restore refuses to write over a store that isn't empty (move it aside first), unpacks into a private staging directory, checks that the CA key matches the CA certificate, and only then moves it into place. Certificates issued before the backup keep working, revocations in it stay revoked, and new certificates continue the serial sequence. Rerun `./scripts/setup-service` afterwards so the sandbox binds and reload watch point at the restored `public/`.

### CA expiry and rotation

tiny-pki issues the CA for ten years by default (`init --days`). The client-certificate health check ([#160](https://github.com/the-hcma/home-warden/issues/160)) alerts well before it expires; `./scripts/client-pki check --kind ca` shows it by hand.

Rotating to a new CA without locking any device out:

1. **Create the new CA** in its own store: `HOME_WARDEN_PKI_STORE=conf/pki-next ./scripts/client-pki init --cn "Home client CA 2"`.
2. **Trust both.** Build a transition CA bundle holding both CA certificates and a transition CRL file holding **both CAs' CRLs**, in a key-free directory such as `conf/pki-transition/`. nginx rejects a client whose CA has no CRL in `ssl_crl` ("unable to get certificate CRL"), so the new CA's CRL is not optional. Write each file to a temporary name and `mv` it into place: nginx reuses a cached CA or CRL file across reloads while its inode and modification second are unchanged, so rewriting a file in place can leave nginx on the old contents.

   ```bash
   t=conf/pki-transition; mkdir -p "$t"
   cat conf/pki/public/ca.crt conf/pki-next/public/ca.crt >"$t/ca.crt.tmp" && mv "$t/ca.crt.tmp" "$t/ca.crt"
   cat conf/pki/public/crl.pem conf/pki-next/public/crl.pem >"$t/crl.pem.tmp" && mv "$t/crl.pem.tmp" "$t/crl.pem"
   ```

   Point every gated entry's `client_cert.ca_bundle` and `client_cert.crl` at those two files and rerun `./scripts/setup-service`.
3. **Re-enroll every device** from the new store, one certificate per device as usual.
4. **Keep the transition files current.** They're copies: rebuild them (step 2's commands) after any revoke in either store, and keep the window shorter than the CRL lifetime, since the refresh timer re-signs each store's own `public/crl.pem`, not the combined file.
5. **Drop the old CA** once every device has moved: point the entries back at the new store's `public/ca.crt` and `public/crl.pem`, rerun `./scripts/setup-service`, and retire the old store, keeping its last backup.

`tests/python/test_client_pki.py` runs this procedure against real nginx: both CAs' clients are accepted during the window, a revocation in the old CA takes effect, and dropping the old CA cuts off its clients.

## Catalog wiring

A catalog entry opts in with a `client_cert` object (schema reference: [`services.json.example`](../services.json.example)):

- `mode`: `off`, `optional`, or `required`; `required` is the one that gates a vhost.
- `ca_bundle`: the CA certificate nginx verifies clients against.
- `crl`: the CRL nginx checks for revoked serials.
- `verify_depth`: how many intermediate certificates to follow (`1` for this CA, which signs client certificates directly).
- `allow_cn`: optional list of common names; any other valid certificate gets a 403.

`ca_bundle` and `crl` point at the store's key-free `public/` directory (`public/ca.crt` and `public/crl.pem`), never at `ca/`, which holds the CA key. nginx runs as `home-warden-nginx` and can only read `public/`.

## Non-goals

- **Server certificates from the private CA**, including TLS to internal backends. Public vhosts use Let's Encrypt, and backend connections are out of scope for this CA.
- **Per-user self-service enrollment.** The operator issues and revokes every certificate.
- **A general-purpose PKI.** No intermediate CAs, no OCSP, no certificates for anything other than client authentication to home-warden's vhosts.
