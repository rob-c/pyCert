# Migrating from CertWizard

pyCert speaks the same CA protocol as CertWizard, so you can switch without
asking the CA for anything new. This guide maps the old workflow onto the new
one and explains what to do with the files CertWizard left behind.

## What CertWizard kept and where

CertWizard stored everything in `~/.ca`:

| File | Contents |
|---|---|
| `cakeystore.pkcs12` | all client keys and certificates, protected by one keystore passphrase |
| `backup/cakeystore.pkcs12.backup` | a copy of the above |
| `truststore.jks` | JKS trust store built from bundled PEMs, password `passwd` |
| `localcertificate.xml` | optional metadata |

pyCert does not use a single shared keystore. Each request gets its own
directory under `~/.local/share/pycert/requests/<slug>/`, its own key
(encrypted with the saved secret), its own certificate and its own `.p12`. That
makes permissions, backups and deletion per-certificate, and it means one
corrupt entry cannot take down the rest.

## Import existing keys and certificates

```console
$ pycert import ~/.ca/cakeystore.pkcs12 --alias "old cert"
```

* You will be prompted for the keystore passphrase (or use
  `--password-file`/`--password-stdin`).
* The file is read with `cryptography`, which understands the legacy
  PBE-SHA1-3DES and RC2 encryption Java 8 used.
* The imported key is re-encrypted with pyCert’s saved secret, the chain is
  verified against the configured anchors (or fetched via AIA), and a fresh
  `.p12` is written with modern cryptography.
* Use `--allow-unverified-chain` if the certificate was issued by a CA that is
  not in your configured chain and you have checked it manually.

Before importing, you can inspect the whole file without changing anything:
start `pycert gui`, choose **File → Inspect Java bundle...**, select
`cakeystore.pkcs12` and enter its passphrase. The viewer lists every certificate
with its Java alias, role, subject, issuer and fingerprint, and can save all
public certificates as PEM. It also understands `.jks`/`.jceks` trust stores
and PEM/DER bundles. Java is not required for this inspection.

If your Java keystore contains several entries, import them one at a time with
distinct `--alias` values. `keytool -list -keystore ~/.ca/cakeystore.pkcs12
-storetype pkcs12` prints the aliases (Java is still required for that one-time
step; pyCert itself does not need Java).

## Renewal

CertWizard renews by creating a new key pair and authenticating the CSR with the
private exponent of the **old** certificate (PPPK). pyCert does the same:

```console
$ pycert renew "old cert" --wait
```

* The old certificate remains usable until the new one is issued and verified.
* `key.next.pem` and `request.next.csr` hold the pending material.
* On success the old key, certificate and `.p12` move to
  `previous/<timestamp>/`, and the new ones become current.

A renewal keeps the subject of the existing certificate (with the attribute
order normalised for OpenCA) and preserves its SANs unless you override them
with `--san-dns`, `--san-email` or `--san-ip`.

## Host certificates

CertWizard’s host request is authenticated by an existing user certificate. In
pyCert:

```console
$ pycert request host.example.ac.uk --type host --auth "old cert" --wait
```

The authenticated certificate must be present in pyCert’s store and currently
valid.

## What maps to what

| CertWizard action | pyCert |
|---|---|
| Apply / request | `pycert request "Name" --wait` |
| Refresh status | `pycert status --refresh` (or `pycert wait ALIAS`) |
| Download | automatic after signing, or `pycert download ALIAS` |
| Export to PKCS #12 | automatic, or `pycert export ALIAS` |
| Export head certificate / chain | `cert.pem`, `chain.pem`, `fullchain.pem` in the request directory |
| Import from PKCS #12 | `pycert import FILE` |
| Renew | `pycert renew ALIAS` |
| Revoke | `pycert revoke ALIAS --reason …` |
| Remove from client | delete the request directory (or use the GUI’s folder button) |
| Install (PEM files in `~/.globus`) | `pycert install ALIAS --dir ~/.globus` |
| Change keystore password | `pycert secret set` (rotating the saved secret) |
| Online/offline mode | the CLI works offline for everything except CA calls; there is no mode switch |

## The keystore passphrase

CertWizard asked for one passphrase for `cakeystore.pkcs12`. pyCert generates a
32-byte URL-safe passphrase and stores it in your OS keychain (or configured
backend) under `pyCert:<profile>` / `default`. You normally never type it.

To see or change it:

```console
$ pycert secret get --show          # print it (avoid; needed for other tools)
$ pycert secret set                 # set a new one (see the caveat below)
```

**Rotating the secret is not free.** Existing `key.pem` files are encrypted with
the current passphrase; changing it makes them unreadable. Re-export keys before
rotating, or keep the old secret available. The GUI settings dialog therefore
does not offer secret rotation.

## Trust

CertWizard’s `truststore.jks` was built from `escience-2b.pem` and
`escience-root.pem` and protected with the literal password `passwd`. pyCert
ships the same four UK e-Science CA certificates (adding the 2026 ECDSA root and
CA 3B), pins each one by SHA-256, and uses them directly as TLS anchors and path
validation anchors. There is no trust store to rebuild and no password to leak.

If your organisation uses an internal CA, replace the `[[chain.certificates]]`
entries with your own certificates and pins; `pycert config check` will tell you
if a pin is wrong.

## Cutting over

1. Install pyCert and run `pycert init` with your e-mail and RA.
2. `pycert config check`, `pycert doctor` and `pycert ping`.
3. Import the certificates you still need from `~/.ca/cakeystore.pkcs12`.
4. Move any automation from the GUI to `pycert status --refresh` in cron.
5. Keep `~/.ca` read-only for a while; delete it once you are confident.
6. Do not delete the CA-side certificates; importing is a local operation.

Nothing on the CA side changes. The CA cannot tell whether the request came from
CertWizard or pyCert beyond the `Version` string, which pyCert keeps compatible
by default.

## Behaviour differences to be aware of

* pyCert refuses MD5/SHA-1 signatures in chains unless `ca.allow_sha1 = true`.
* A certificate whose chain does not validate is stored for inspection but no
  `.p12` is written, and the command exits 4. CertWizard exported whatever it
  downloaded. Use `--allow-unverified-chain` if you must override.
* The PIN is generated (rather than typed) unless you pass one. It is shown once.
* Requests are never retried automatically after a possible submission; use
  `pycert status --refresh` to find out whether the server received it.
* There is no “offline keystore manager”: pyCert is for this CA, not a general
  PKCS#12 browser. For that, use `keytool`, `openssl pkcs12` or Keychain Access.
