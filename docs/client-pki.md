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
- **Laptops, desktops, and YubiKeys generate their own key** and send only a certificate signing request (CSR); the CA signs it, and the key never leaves the device, so the store holds no key for them (see [Enroll from a CSR](#enroll-a-laptop-or-yubikey-from-a-csr)).
- **Phones and tablets get a password-protected PKCS#12 (`.p12`) bundle** the CA builds, key included, since iOS and Android offer no way to make a CSR for browser client authentication outside MDM.

## Lifecycle overview

| Stage | What happens | Tracked in |
| --- | --- | --- |
| CA setup | Create the CA once on the designated host, keep its key private, back it up encrypted, and rotate the CA itself before it expires. See [Running the CA](#running-the-ca). | [#158](https://github.com/the-hcma/home-warden/issues/158) |
| Enroll | Issue a certificate for a new device: sign its CSR, or export a `.p12`. See [Managing devices](#managing-devices). | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Rotate | Issue a replacement while the old certificate keeps working, install it on the device, then revoke the old serial. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Revoke | Revoke a lost or retired device's serial and publish a new CRL; nginx reloads automatically when the CRL changes. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Keep the CRL fresh | Republish the CRL on a timer before it expires (an expired CRL makes nginx reject every client), and alert on CA or CRL expiry. See [Keeping the CRL fresh](#keeping-the-crl-fresh). | [#160](https://github.com/the-hcma/home-warden/issues/160) |
| See and edit it | Web UI: CA status, certificate inventory, and `client_cert` editing per catalog entry. | [#161](https://github.com/the-hcma/home-warden/issues/161) |

Already in place on `main`: the nginx sandbox sees a republished CRL ([#148](https://github.com/the-hcma/home-warden/issues/148)), and nginx reloads when the CRL or CA file changes ([#151](https://github.com/the-hcma/home-warden/issues/151)).

## Running the CA

### Where issuing happens

**On the designated host**, the one `scripts/setup-service --confirm-host` pinned. The CA store lives there, in `conf/pki` under the repo checkout by default (`HOME_WARDEN_PKI_STORE` overrides it; `conf/` is gitignored, like `conf/cloudflare.ini`).

The alternative, keeping the CA key on an operator machine and copying only `ca.crt` and `crl.pem` to the host, would keep the key off the internet-facing machine, but every revoke and every CRL refresh would then need a manual sync, and a missed refresh makes nginx reject every client once the CRL expires. On the host, the CRL refresh timer ([#160](https://github.com/the-hcma/home-warden/issues/160)) and revocations take effect without anyone copying files. The cost is the threat-model row above: whoever compromises the host's operator account can issue certificates. The key protection below, including encrypting the key at rest, is what limits that.

### Creating the CA

```bash
./scripts/client-pki init --cn "Home client CA"
```

That creates the store with tiny-pki's layout. Point a catalog entry's `client_cert.ca_bundle` and `client_cert.crl` at the absolute paths of `conf/pki/public/ca.crt` and `conf/pki/public/crl.pem` in the checkout, then rerun `./scripts/setup-service` so the nginx sandbox binds `public/`, watches it for reloads, and installs the CRL refresh timer.

### Key protection

| Path | Mode | Who can read it |
| --- | --- | --- |
| store root, `ca/`, `clients/`, `servers/`, `bundles/` | `0700` | the operator account only |
| `ca/ca.key`, leaf `*.key`, `ca/index.json`, `bundles/*` | `0600` | the operator account only |
| `public/` | `0755` | anyone, including `home-warden-nginx` through the sandbox's bind of that one directory |
| `public/ca.crt`, `public/crl.pem`, other certificates and CRLs | `0644` | readable, but only reachable through `public/` |

tiny-pki writes this layout itself. `scripts/client-pki` checks it before every command and refuses to run when anything is looser, for example a key made group-readable by a careless copy, listing each offending path. It also refuses a `public/` or public file that `home-warden-nginx` couldn't read (a directory tighter than `0755` or a file tighter than `0644`), since the vhost would then fail to load. nginx never sees `ca/`: the sandbox binds only `public/`, so the key isn't readable by `home-warden-nginx` even if a mode slips.

#### Encrypting the CA key at rest

`./scripts/client-pki init` encrypts `ca/ca.key` (tiny-pki's `--encrypt-key`, tiny-pki ≥ 1.0) unless you pass `--plaintext-key`. The secret must be at least 32 characters; generate one with `head -c 32 /dev/urandom | base64`. tiny-pki takes it from `--key-secret-file PATH`, `TINY_PKI_KEY_SECRET_FILE`, a systemd `tiny-pki-key` credential, or a terminal prompt, never from the command line. Commands that only read (`list`, `show`, `check`, `inspect`, so `GET /pki/status` and `catalog-health-check`) don't need it; anything that signs (`create`, `sign`, `revoke`, `crl`) does.

Where the secret lives, and why:

- **Interactive use** (enroll, rotate, revoke): you supply it, from a prompt or a `0600` file you keep somewhere other than the host, such as a password manager. The host doesn't have to hold it.
- **The unattended CRL refresh** (`home-warden-client-pki-crl.service`) is the only automated signer. Put the secret in a **root-owned, `0600` file**, `/etc/home-warden/client-pki-key-secret` (override with `CLIENT_PKI_KEY_SECRET_FILE` when running `setup-service`). `setup-service` then adds `LoadCredential=tiny-pki-key:<file>` to that one unit: systemd reads the file as root and hands the secret to the refresh as `$CREDENTIALS_DIRECTORY/tiny-pki-key`, which tiny-pki looks for itself. To keep it encrypted on disk too, use `systemd-creds encrypt` and `LoadCredentialEncrypted=` in a drop-in instead.
- **Effect on the threat model.** A copy of the store that loses its permissions (a backup, a disk image, a careless `cp`) no longer yields a key. A compromised operator account without root can't read the secret at rest either, since it lives root-only and reaches the CRL service as a credential. It does **not** stop an attacker with root, or one who can run code while the CRL refresh runs, and anyone who types the secret on a compromised host exposes it. Treat the host as holding the CA key for those cases.

If the key is encrypted and the secret file is missing, `setup-service` warns, and the refresh fails until it exists (the `client_cert` health check alerts as the CRL runs down).

##### Migrating an existing plaintext store

```bash
./scripts/client-pki backup --out ~/backups/client-pki-before-encrypt.tar.gpg --passphrase-file ~/.config/home-warden/pki-backup-passphrase
./scripts/client-pki encrypt-key --key-secret-file ~/.config/home-warden/pki-key-secret
sudo install --mode=0600 --owner=root -D ~/.config/home-warden/pki-key-secret /etc/home-warden/client-pki-key-secret
./scripts/setup-service
./scripts/client-pki crl --key-secret-file ~/.config/home-warden/pki-key-secret   # proves the secret works
```

Then remove the secret file from the operator's home if you keep the root copy plus your own off-host copy. `./scripts/client-pki decrypt-key` reverses it. Losing the secret loses the CA key (the backup holds the key encrypted too), so keep a copy off the host.

### Backup and restore

Back up the whole store (CA key, which stays encrypted inside the archive when the store encrypts it, index, serial and CRL state, issued certificates) as a `gpg --symmetric` (AES-256) archive. The passphrase comes from a file readable only by you, never from the command line:

```bash
./scripts/client-pki backup --out ~/backups/client-pki-$(date +%F).tar.gpg --passphrase-file ~/.config/home-warden/pki-backup-passphrase
```

The backup takes a shared lock on the store, so it never captures a half-finished revoke, refuses to overwrite an existing file, writes the archive `0600`, and decrypts it again before reporting success. Copy it off the host to wherever your other backups go, and keep the passphrase somewhere other than the archive (a password manager). Take a new backup after every enroll or revoke; an old backup restores an old revocation list.

To restore, onto the same host or a replacement:

```bash
./scripts/client-pki restore --in client-pki-2026-09-28.tar.gpg --passphrase-file ~/.config/home-warden/pki-backup-passphrase
```

Restore refuses to write over a store that isn't empty (move it aside first), unpacks into a private staging directory, checks that the CA key matches the CA certificate (for an encrypted key it decrypts it with `--key-secret-file`, `TINY_PKI_KEY_SECRET_FILE` or the `tiny-pki-key` credential, and refuses without a secret that unlocks it), and only then moves it into place. Certificates issued before the backup keep working, revocations in it stay revoked, and new certificates continue the serial sequence. Rerun `./scripts/setup-service` afterwards so the sandbox binds and reload watch point at the restored `public/`.

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

### Keeping the CRL fresh

tiny-pki signs each CRL for 7 days by default (`crl --days N` changes that), and nginx rejects **every** client certificate once the CRL it loads has expired. Once the store has a CA, `./scripts/setup-service` installs `home-warden-client-pki-crl.timer`, which runs `scripts/client-pki crl` daily at 04:45 as the operator account and logs to `client-pki-crl.log` in the scratch directory. tiny-pki replaces `public/crl.pem` atomically, and the reload watch on `public/` picks up the new file, so no step of its own reloads nginx. A refresh takes the store lock like any other write, so it can't race a revoke and drop it.

To refresh by hand: `sudo systemctl start home-warden-client-pki-crl.service`, or `./scripts/client-pki crl`.

### Health check and alerts

`catalog-health-check`, `GET /health/catalog`, and the `catalog-heal` timer check every catalog entry with `client_cert` enabled (the `client_cert` dimension). It fails when:

- `ca_bundle` or `crl` isn't set (without a CRL, nginx accepts revoked certificates), or its file is missing, unreadable, unparseable, or not an absolute path;
- `home-warden-nginx` couldn't read a file: it needs `o+r` (for example `0644`) and its directory, which the nginx sandbox binds, needs `o+rx` (`0755`);
- a CA in the bundle is expired or expires within `CLIENT_CA_ALERT_DAYS` (default 60, long enough to rotate the CA);
- a CRL is expired or expires within `CLIENT_CRL_ALERT_DAYS` (default 3; with the daily refresh and 7-day CRLs, that means the timer has been failing for about four days);
- a CRL isn't signed by a CA in the bundle, or a CA in the bundle has no CRL (nginx rejects that CA's clients).

`catalog-heal` reports it as alert-only and mails it through the same path as its other alerts (`CATALOG_HEAL_ALERT_TO`, see `etc/home-warden-catalog-heal.env.example`); it never re-signs anything itself. Both settings go in `~/.config/home-warden-catalog-heal.env`.

## Managing devices

Every command below runs on the designated host. `scripts/client-pki` refuses any command that changes the store (`init`, `create`, `enroll`, `rotate`, `revoke`, `crl`, `renew-crl`, `delete`, `export`, `backup`, `restore`) on any other machine; read-only commands (`list`, `show`, `inspect`, `check`) run anywhere. One certificate per device, named after the device, for example `alice-phone`: revoking it then cuts off exactly that device.

### Bundle passwords

A `.p12` bundle is protected by a password of at least 16 characters, read from a file readable only by you (`chmod 600`), never from the command line. Use a fresh random password per bundle, for example `(umask 077; openssl rand -base64 18 >~/.config/home-warden/alice-phone.pass)` (the `umask` makes it `0600` from the start), and delete the file once the device has imported the bundle.

### Enroll a new device

```bash
./scripts/client-pki enroll alice-phone --password-file ~/.config/home-warden/alice-phone.pass
```

That issues the certificate and writes `conf/pki/bundles/alice-phone-<serial>.p12` (`0600`). `enroll` refuses a name that already has an active certificate, so it never silently revokes a working device; use `rotate` for that. `enroll` and `rotate` hold a lock on the store while they check and issue, so two runs for the same device can't revoke each other's certificate (a hand-run `create client` doesn't take that lock).

**Deliver the bundle and its password separately**: for example the `.p12` over AirDrop or a USB cable, and the password read out or sent over a different channel. Anyone with both can impersonate the device until you revoke it. Delete the `.p12` from the store and from wherever you copied it once the device has imported it; the store keeps the certificate and key, so you can export it again with `./scripts/client-pki export p12 alice-phone --password-file ...`.

### Install on the device

- **iOS / iPadOS**: open the `.p12` (Files, AirDrop, or Mail), then Settings → Profile Downloaded → Install, and enter the bundle password. Safari offers the certificate when a gated site asks for one.
- **Android**: Settings → Security → Encryption & credentials → Install a certificate → VPN & app user certificate (the menu names vary by vendor), pick the `.p12`, and enter the password. Chrome prompts for the certificate on first visit.
- **macOS**: double-click the `.p12` to add it to the login keychain. Safari and Chrome use the keychain; Firefox has its own store (Settings → Privacy & Security → Certificates → Your Certificates → Import).
- **Windows / Linux desktops**: import into the browser's certificate store (Chrome on Windows uses the Windows store; Firefox and Chrome on Linux use their own).

Modern devices take the default AES-256 bundle. Only an old device that rejects it (typically Android before 12, macOS before 10.15, or an old Java/Windows keystore) needs `--legacy`, which uses 3DES/SHA-1: weaker encryption for the bundle file itself, so keep the password strong and delete the file promptly.

```bash
./scripts/client-pki enroll old-tablet --password-file ~/.config/home-warden/old-tablet.pass --legacy
```

### Enroll a laptop or YubiKey from a CSR

A device that can generate its own key keeps it: it sends a certificate signing request, which holds only the public key, and gets back a certificate. Nothing secret travels, there is no bundle password, and the store (and every backup of it) holds no key that could impersonate the device.

1. **On the device**, generate a key and a CSR. The subject doesn't matter; the CA names the certificate. Pick one:
   - OpenSSL (Linux, macOS): `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout bob-laptop.key -out bob-laptop.csr -subj "/CN=bob-laptop"`, then `chmod 600 bob-laptop.key`.
   - macOS keychain: Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority, "Saved to disk", with an ECC 256-bit or RSA 2048+ key.
   - Windows: `certreq -new` with an `.inf` that sets `Exportable = FALSE` (and the TPM's "Microsoft Platform Crypto Provider" to keep the key in the TPM).
   - YubiKey (PIV): `ykman piv keys generate --algorithm ECCP256 9a pub.pem`, then `ykman piv certificates request --subject "CN=bob-laptop" 9a pub.pem bob-laptop.csr`.
2. **Read the fingerprint on the device**: `openssl req -in bob-laptop.csr -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $NF}'`. (OpenSSL 3 prints `SHA2-256(stdin)= <hex>`; `awk` keeps only the hex, which is the fingerprint to read out.)
3. **Copy the CSR to the designated host** over any channel; it's public.
4. **Sign it**, vouching for the fingerprint the device's owner reads out:

   ```bash
   ./scripts/client-pki enroll bob-laptop --csr bob-laptop.csr --fingerprint 3A:7F:...:C2 --out bob-laptop.crt
   ```

   `enroll` prints tiny-pki's summary of the CSR (key, signature, the SHA-256 of its public key), refuses one tiny-pki wouldn't sign (for example RSA 1024 or a SHA-1 signature), and signs only when the public key matches `--fingerprint` (colons, spaces and case don't matter). Without `--fingerprint` it asks you to confirm at the terminal instead, and refuses when there isn't one. The fingerprint check catches a CSR swapped in transit, which would otherwise get a certificate for someone else's key. `--out` (default `<cn>.crt` in the current directory) is checked before anything is issued, because tiny-pki records the certificate before it writes the file; if the write still fails, `enroll` and `rotate` say so and print the `export pem <cn> --out PATH` recovery command (and, for `rotate`, the revoke commands). The CN is always the name you give; a different CN or any extensions the CSR asks for are ignored with a warning, so a device can't pick its own name for an `allow_cn` list.
5. **Install the certificate next to the key**: copy `bob-laptop.crt` and the store's `public/ca.crt` back (both public). With OpenSSL, build a browser bundle on the device (`openssl pkcs12 -export -inkey bob-laptop.key -in bob-laptop.crt -certfile ca.crt -out bob-laptop.p12`) and import it; macOS Keychain Access pairs an imported certificate with the key it made; `certreq -accept bob-laptop.crt` installs it on Windows; `ykman piv certificates import 9a bob-laptop.crt` writes it to the YubiKey slot.

`export p12` refuses such a device, since the store has no key to put in a bundle; `export pem` writes the certificate alone.

### Rotate a device's certificate

Before a certificate expires (`./scripts/client-pki check --kind client --quiet` lists expiring ones), or whenever you want to replace it:

```bash
./scripts/client-pki rotate alice-phone --password-file ~/.config/home-warden/alice-phone.pass
```

That issues a new certificate while the old one keeps working, exports the new bundle, and prints the `revoke` command for each previous serial. Install the new bundle on the device, check it reaches a gated site, then run the printed command, for example `./scripts/client-pki revoke 0x1a2b...`. Until you do, both certificates work.

A device enrolled from a CSR rotates the same way with a fresh key and CSR, and the same fingerprint check:

```bash
./scripts/client-pki rotate bob-laptop --csr bob-laptop-2026.csr --fingerprint 91:0C:...:4E --out bob-laptop.crt
```

### Revoke a lost or retired device

```bash
./scripts/client-pki revoke alice-phone
```

That revokes the device's certificate and republishes `public/crl.pem`; nginx reloads when the file changes, so the device is rejected within seconds. If the name has two live certificates (mid-rotation), tiny-pki refuses the name and lists both serials: revoke each with `revoke 0x<serial>`. `--dry-run` previews either form. Take a new backup afterwards, since an old backup restores the old revocation list.

### Inventory

```bash
./scripts/client-pki list clients
./scripts/client-pki list revoked
./scripts/client-pki show alice-phone
```

`list clients --json` gives the same inventory in a machine-readable form.

## Catalog wiring

A catalog entry opts in with a `client_cert` object (schema reference: [`services.json.example`](../services.json.example)):

- `mode`: `off`, `optional`, or `required`; `required` is the one that gates a vhost.
- `ca_bundle`: the CA certificate nginx verifies clients against.
- `crl`: the CRL nginx checks for revoked serials.
- `verify_depth`: how many intermediate certificates to follow (`1` for this CA, which signs client certificates directly).
- `allow_cn`: optional list of common names; any other valid certificate gets a 403.

`ca_bundle` and `crl` point at the store's key-free `public/` directory (`public/ca.crt` and `public/crl.pem`), never at `ca/`, which holds the CA key. nginx runs as `home-warden-nginx` and can only read `public/`.

The web UI's catalog editor sets these fields too. Leaving the mode at "not set" removes `client_cert` from the entry. Each edit goes through the same validation and `nginx -t` preview as every other catalog change.

## Web UI

The "Client certificates" tab (`GET /pki/status`) is **read-only**. It shows the CA and its expiry, the CRL and when it was last refreshed, every issued certificate with its state and health, and which vhosts set `client_cert`. It reads the store through `tiny-pki list … --json` and `check --json`, none of which touches the CA key, and it never returns a file path.

Issuing, rotating, and revoking stay with `scripts/client-pki` on the host. These are deliberately not web actions yet. The API server runs as the operator account, which also owns the store, so the process could read `ca/ca.key` today. What stops a hijacked session or a request-forgery bug from minting a trusted device certificate is that no endpoint uses the key. A write endpoint would add exactly that path, so it needs, at minimum:

- **A separate privileged helper** under its own account, which owns the store and the CA key. The web process can't read `ca/`; it asks the helper for one of a few narrow operations (issue a named device, revoke a serial, refresh the CRL). This moves the store away from the operator account, so `scripts/client-pki` and the CRL timer would go through the helper too.
- **Re-authentication per action**: a fresh PAM password check for each issue or revoke, not just a valid session cookie.
- **An audit log** outside the web process's control, recording who did what, when, and to which certificate.
- **A path that doesn't depend on the UI for first enrollment.** Once the UI itself is a gated vhost (`client_cert.mode: required`), a device without a certificate can't reach it. The first certificate, and recovery after losing every enrolled device, must stay possible from the host's shell.

## Non-goals

- **Server certificates from the private CA**, including TLS to internal backends. Public vhosts use Let's Encrypt, and backend connections are out of scope for this CA.
- **Per-user self-service enrollment.** The operator issues and revokes every certificate.
- **A general-purpose PKI.** No intermediate CAs, no OCSP, no certificates for anything other than client authentication to home-warden's vhosts.
