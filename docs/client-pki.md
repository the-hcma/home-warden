# Private client-certificate CA

home-warden runs a small private certificate authority whose only job is to
issue **mTLS client certificates**: a device presents one to nginx, and nginx
lets it reach a gated vhost only if the certificate is valid, unrevoked, and
(optionally) carries an allowed common name. This page explains what the CA
is for, what it does and doesn't protect against, and where each piece of its
lifecycle is tracked. The epic is
[#49](https://github.com/the-hcma/home-warden/issues/49).

The CA is built on [`tiny-pki`](https://github.com/the-hcma/tiny-pki). Until
tiny-pki publishes a release, the integration lives in draft
[#149](https://github.com/the-hcma/home-warden/pull/149); this page describes
intent, not a shipped feature.

## Purpose

A client certificate is the **first gate** in front of a sensitive vhost, and
the service's own authentication is the **second**:

1. **Device gate (nginx).** A vhost with `client_cert.mode: required` refuses
   any request that doesn't come with a valid, unrevoked certificate from this
   CA (and, with `allow_cn`, an allowed common name). nginx answers it with an
   error itself (400, or 403 for a CN outside `allow_cn`); the request is never
   proxied, so an unenrolled device can't reach the service's login page, its
   API, or anything else behind the vhost.
2. **Service authentication.** Only requests from enrolled devices get as far
   as the service, which then applies its own login (PAM for the admin web
   UI, whatever a self-hosted app uses).

An attacker therefore has to get hold of an enrolled device's certificate
*before* a password is worth anything, and an unpatched login form isn't
exposed to the internet at all.

- **First candidate: the admin web UI.** It already requires a PAM login; the
  certificate goes in front of it. The generated web-UI vhost doesn't expose a
  `client_cert` setting yet, so until
  [#161](https://github.com/the-hcma/home-warden/issues/161) wires one up the
  UI is protected by its login alone.
- **Then every service that shouldn't be reachable from an arbitrary device**,
  such as admin panels of self-hosted apps, set per catalog entry through the
  `client_cert` field (see [Catalog wiring](#catalog-wiring)).
- **`optional` is not a gate.** With `mode: optional` nginx lets requests
  without a certificate through; it's only useful when the backend itself
  checks the certificate nginx forwards. Gated vhosts use `required`.
- **Public TLS stays with Let's Encrypt.** Server certificates keep coming from
  `scripts/cert-renewer`. The private CA never signs a certificate a browser is
  expected to trust for a server.

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

This is a **household CA**: a handful of personal devices (phones, tablets,
laptops) belonging to a few people.

- **One certificate per device**, never shared between devices. Losing one
  device then means revoking one certificate, not re-enrolling everything.
- **The common name names the person and the device**, for example
  `alice-phone` or `bob-laptop`. That makes the certificate inventory readable
  and lets a vhost's `allow_cn` list admit specific people or devices.
- Certificates are delivered to devices as password-protected PKCS#12 (`.p12`)
  files, which iOS, Android, macOS, and desktop browsers can all import.

## Lifecycle overview

| Stage | What happens | Tracked in |
| --- | --- | --- |
| CA setup | Create the CA once; decide where issuing happens, how the CA key is protected at rest, how it's backed up, and how the CA itself is rotated before it expires. | [#158](https://github.com/the-hcma/home-warden/issues/158) |
| Enroll | Issue a certificate for a new device and export it as a `.p12`. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Rotate | Issue a replacement while the old certificate keeps working, install it on the device, then revoke the old serial. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Revoke | Revoke a lost or retired device's serial and publish a new CRL; nginx reloads automatically when the CRL changes. | [#159](https://github.com/the-hcma/home-warden/issues/159) |
| Keep the CRL fresh | Republish the CRL on a timer before it expires (an expired CRL makes nginx reject every client), and alert on CA or CRL expiry. | [#160](https://github.com/the-hcma/home-warden/issues/160) |
| See and edit it | Web UI: CA status, certificate inventory, and `client_cert` editing per catalog entry. | [#161](https://github.com/the-hcma/home-warden/issues/161) |

Already in place on `main`: the nginx sandbox sees a republished CRL
([#148](https://github.com/the-hcma/home-warden/issues/148)), and nginx reloads
when the CRL or CA file changes
([#151](https://github.com/the-hcma/home-warden/issues/151)).

## Catalog wiring

A catalog entry opts in with a `client_cert` object (schema reference:
[`services.json.example`](../services.json.example)):

- `mode`: `off`, `optional`, or `required`; `required` is the one that gates
  a vhost.
- `ca_bundle`: the CA certificate nginx verifies clients against.
- `crl`: the CRL nginx checks for revoked serials.
- `verify_depth`: how many intermediate certificates to follow (`1` for this
  CA, which signs client certificates directly).
- `allow_cn`: optional list of common names; any other valid certificate gets
  a 403.

`ca_bundle` and `crl` point at the store's key-free `public/` directory
(`public/ca.crt` and `public/crl.pem`), never at `ca/`, which holds the CA key.
nginx runs as `home-warden-nginx` and can only read `public/`.

## Non-goals

- **Server certificates from the private CA**, including TLS to internal
  backends. Public vhosts use Let's Encrypt, and backend connections are out of
  scope for this CA.
- **Per-user self-service enrollment.** The operator issues and revokes every
  certificate.
- **A general-purpose PKI.** No intermediate CAs, no OCSP, no certificates for
  anything other than client authentication to home-warden's vhosts.
