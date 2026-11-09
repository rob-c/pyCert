# pyCert

**A Python 3 client, test CA and ACME v2 front-end for the UK e-Science certificate service.**

pyCert is a replacement for the Java **CertWizard** client. It requests user and
host certificates, waits for RA approval and CA signing, downloads and verifies
the full chain, and writes an encrypted PKCS#12 bundle whose passphrase is kept
in the operating-system secret store.

The repository also contains a complete **local CA sandbox** that speaks the
legacy CertWizard/OpenCA protocol, and a reference **ACME v2 wrapper** that lets
standard clients such as `certbot` obtain certificates from the same CA state.
The sandbox is for development, interoperability testing and migration planning;
it is **not** a production CA.

```console
$ pycert request "Jane Doe" --wait
  Preparing request...
  Generating a 3072-bit RSA key...
  Submitting to the CA...
  CSR submitted; awaiting RA approval and CA signing.
  Certificate issued (server status VALID)
  Verifying the certificate chain...
  Writing PKCS#12 bundle .../jane_doe.p12
  PIN for the RA: K7QF-2M9X-P4RT

Request 'jane doe' is DOWNLOADED.
```

A Tkinter GUI provides the same workflow, a certificate list, expiry warnings,
chain inspection and one-click verification:

```console
$ pycert gui
```

The GUI follows the operating system's light/dark appearance by default. Use
**View → Appearance** to choose **System**, **Light** or **Dark** at runtime;
`PYCERT_THEME=light|dark|system` provides the same choice for unattended
launches. Logs, certificate text, PIN dialogs and the activity log use the
selected theme rather than fixed white backgrounds.

---

## What this repository contains

| Component | Location | Purpose |
|---|---|---|
| **pyCert client** | `src/pycert/` | CLI and GUI for the legacy UK-CA/CertWizard protocol: request, wait, download, verify, export, renew, revoke, import, install, watch and proxy delegation. |
| **Legacy CA sandbox** | `sandbox_ca/mock_ca.py`, `sandbox_ca/server.py` | A real-TLS test CA implementing the old CertWizard listener contract, with persistent requests/certificates, RA approval, signing and fault injection. |
| **ACME v2 wrapper** | `sandbox_ca/acme.py` | An RFC 8555 front-end over the sandbox CA state, for certbot, nginx and other ACME clients. |
| **Java compatibility kit** | `sandbox_ca/java_kit.py` | Patches a built CertWizard JAR so its pinned CA certificates and URLs point at the sandbox. |

The production UK e-Science CA is an external service. pyCert does not replace
it; it implements the client side of its legacy contract. `docs/CA_LISTENER.md`
documents that contract, and `sandbox_ca/` provides a runnable implementation
for testing.

### Architecture

```text
                         LEGACY PATH
  CertWizard (Java) ─┐
  pyCert CLI/GUI ────┼── HTTPS + XML + PPPK ──▶ Legacy CA listener
                     │                         /CSR, /CSRs, /CA, /pingservice,
                     │                         /resources/..., /certificate/<id>,
                     │                         /revoke
                     │                              │
                     │                              ▼
                     │                         RA approval → CA signing
                     │                         → certificate store
                     │
                         ACME PATH
  certbot / nginx ─────── HTTPS + JWS ───────▶ ACME v2 wrapper
  ACME clients            (RFC 8555)           /acme/directory, new-order,
                                               authz, challenge, finalize,
                                               certificate, revoke-cert
                                                    │
                                                    ▼
                                         same in-process CA state:
                                         CSR record → approve/sign
                                         → certificate id → download/revoke
```

The two front-ends share the sandbox CA records, signing function and
certificate store. The ACME wrapper is a façade: it does not implement a second
CA and does not bypass UK-CA policy.

## Contents

- [What this repository contains](#what-this-repository-contains)
- [What pyCert does](#what-pycert-does)
- [Install and quick start](#install-and-quick-start)
- [The legacy CA listener](#the-legacy-ca-listener)
- [The ACME v2 wrapper](#the-acme-v2-wrapper)
- [CLI reference](#cli-reference)
- [What pyCert writes](#what-pycert-writes)
- [Security](#security)
- [Compatibility notes](#compatibility-notes)
- [Development and tests](#development-and-tests)
- [Limitations and non-goals](#limitations-and-non-goals)

---

## What pyCert does

- Generates the private key and PKCS#10 CSR locally.
- Uses the legacy CertWizard protocol over HTTPS:
  - user requests: `POST /CSR`;
  - host requests: `POST /CSRs` with PPPK authentication;
  - renewals: `POST /CSR` with PPPK (the current Java behaviour; `/CSRs` remains
    a legacy alias);
  - status lookup by public-key SPKI, certificate download by id, revocation.
- Polls until the RA approves and the CA signs, with bounded backoff,
  cancellation and a clear timeout exit code.
- Builds and cryptographically verifies the full issuer chain before trusting
  the issued certificate.
- Writes a modern PKCS#12 bundle using PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC,
  with the passphrase in the macOS Keychain, Freedesktop Secret Service, an
  external command, an environment variable, or a `0600` file.
- Supports user certificates, host certificates, renewal with a new key,
  SAN/contact changes during renewal, revocation, import of old Java PKCS#12
  files, installation, scheduled renewal/watch, diagnostics and RFC 3820 proxy
  bundles.
- Includes a GUI bundle inspector/editor for old Java PKCS#12/JKS/JCEKS files:
  show every certificate, save all certs, write Java-compatible PKCS#12, and
  update a PKCS#12 with a backup.
- Has no mandatory runtime dependencies other than
  [`cryptography`](https://cryptography.io/) and supports Python 3.6+.

### Why not just use CertWizard?

The Java client works, but it is difficult to audit and automate: it carries a
bundled JRE, Restlet, BouncyCastle and Log4j, and its trust store password is
literally `passwd`. pyCert keeps the protocol behaviour but replaces the
implementation with a small Python package, explicit trust pins, verified chain
building, modern PKCS#12, machine-readable output and a testable transport.

---

## Install and quick start

```console
$ git clone https://github.com/rob-c/pyCert ~/src/pyCert
$ cd ~/src/pyCert
$ python3 -m venv .venv
$ .venv/bin/pip install -e .
$ .venv/bin/pycert --version
```

Then create a configuration and request a certificate:

```console
$ pycert init ~/.config/pycert --email you@example.org --ra "CLRC DL"
$ pycert config check
OK: 4 CA certificates loaded, 4 trust anchors, all pins verified.
$ pycert request "Jane Doe" --wait
```

`pycert init` copies the bundled UK e-Science CA certificates into the
configuration directory and records their SHA-256 fingerprints. They are used
as:

1. TLS trust anchors for the CA server;
2. trust anchors for certificate path validation;
3. the chain embedded in the exported PKCS#12.

Nothing fetched from the network is trusted without a signature check.
Certificates discovered through AIA URLs are accepted only if the child
signature verifies with them.

Host certificates require an existing, currently valid RSA certificate for PPPK
authentication:

```console
$ pycert request host.example.ac.uk --type host --auth "jane doe" --wait
```

Renew and revoke:

```console
$ pycert renew "jane doe" --wait      # new key, authenticated with the old one
$ pycert revoke "jane doe" --reason superseded
```

A renewal does not overwrite a working certificate until the replacement has
been issued and verified. The new files are written as `key.next.pem` and
`request.next.csr`; the old files are archived under `previous/<timestamp>/`
only after verification succeeds.

### Inspect an old Java bundle

The GUI can open a legacy CertWizard PKCS#12 file, a Java JKS/JCEKS trust
store, or a PEM/DER certificate bundle without importing it first:

1. Start `pycert gui`.
2. Open the **Java bundle** tab on the right, choose **Bundles → Open old Java
   bundle...**, **File → Open old Java bundle...**, or click the prominent
   **Java bundle...** button on the main toolbar (shortcut `Cmd/Ctrl+B`).
3. Select the file and enter its passphrase if required.
4. Every certificate is listed with its role (`leaf`, `chain`, `trusted` or
   `certificate`), subject, issuer, expiry, key, SHA-256 fingerprint and alias.
   Selecting a row shows the decoded fields and the certificate PEM.

The same actions are available from the **Bundles** menu; if no bundle is open
they tell you to open one first. The viewer never displays private keys.
Available actions:

- **Copy selected PEM** and **Copy all PEM**;
- **Save all certs (PEM)...** for every public certificate in the bundle;
- **Save all certs (Java PKCS#12)...** to write a new bundle containing every
  certificate and, when available, all original key entries;
- **Update Java bundle...** to rewrite an existing PKCS#12 in place. A
  `<name>.pkcs12.bak` backup is created first.

Java-compatible output uses the legacy PBE-SHA1-3DES + SHA-1 PKCS#12 profile
that old CertWizard/keytool releases understand. Bundles with no usable private
key are written as certificate-only PKCS#12 trust stores. JKS/JCEKS files can
be read and saved as Java-compatible PKCS#12; in-place update is only offered
for PKCS#12 because Java's JKS private-key protection is not re-created by
pyCert.

CertWizard's real `cakeystore.pkcs12` can contain many independent key entries:
the current files use RC2-40 for the certificate SafeContents and 3DES for each
key bag. pyCert's raw keystore path decodes the BER/indefinite-length container,
lists every certificate, and preserves all key bags, aliases and localKeyIDs
when saving or updating. Saving or updating such a bundle uses the passphrase
you entered to open it, because the original key bags remain individually
encrypted; changing the passphrase would require re-encrypting every private
key and is not offered in the GUI yet. On systems where the linked OpenSSL omits
legacy RC2, pyCert uses the local `openssl enc` legacy fallback and reports a
clear error if that is unavailable.

PKCS#12 files with legacy PBE-SHA1-3DES or RC2 encryption are decoded via
`cryptography`/OpenSSL where the installed library supports them. JKS/JCEKS
certificate entries are parsed natively; a supplied JKS password verifies the
integrity digest, while leaving it blank still lists the certificates with a
warning that the digest was not checked. Use `pycert import` when you want to
add a key and certificate to pyCert's own request store.

---

## The legacy CA listener

### What the production listener expects

The production listener is the HTTPS service used by the Java CertWizard
client. pyCert implements the client side; `docs/CA_LISTENER.md` records the
expected server behaviour, including the quirks that are part of the contract.

At a high level:

1. The client trusts a **pinned CA hierarchy**, not an arbitrary TLS certificate.
2. It submits XML CSRs, optionally authenticated with a **PPPK** challenge.
3. It polls the CA by public-key SPKI until the request has a certificate id.
4. It downloads the leaf certificate by id and builds the chain from configured
   anchors and AIA issuers.
5. It verifies signatures and key match before storing or exporting anything.

Key endpoints:

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/pingservice` | none | liveness |
| `GET` | `/CA` | none | CA certificates, RA list, policy, MOTD and client-version information |
| `GET` | `/CA/motd/text` | none | message of the day |
| `POST` | `/CSR` | none | new user request |
| `POST` | `/CSR` | PPPK | renewal with `<PublicKey>` |
| `POST` | `/CSRs` | PPPK | host request (`<Bulk><CSR>...`) or legacy renewal |
| `POST` | `/resources/resource/publickey/pk` | none | status lookup by base64 SPKI |
| `GET` | `/certificate/<id>` | none | download the issued leaf |
| `POST` | `/revoke` | PPPK | revocation |
| `GET` | `/ca/issuer.pem` | none | optional AIA issuer fetch |

The Java client's PPPK flow is a two-step challenge: the listener returns
`401` with `realm`, `nonce`, `keyid` and optionally `opaque`; the client signs
the challenge with the RSA private exponent and retries with `PPPK` and the
challenge headers. Renewal and host requests require RSA authentication even
when the new key is ECDSA.

Other compatibility points:

- TLS server certificates must chain to the CA material pinned inside
  `BundledCaCertificates.class`.
- Header names are case-insensitive, but the client uses specific cases such as
  `LocalHost`, `PPPK`, `serial`, `keyid`, `realm`, `response` and `opaque`.
- Both `Content-Length` and chunked request bodies must be accepted.
- The 202 rejection document contains more than one `<text>` element; the Java
  client reads the **second** one.
- Current Java renewals go to `/CSR`; older clients use `/CSRs`. A compatible
  listener should support both.

The full XML schemas, status model, certificate profile and error-document
quirks are in [`docs/CA_LISTENER.md`](docs/CA_LISTENER.md).

### Request lifecycle and state

The legacy listener models the CA/RA workflow with a small status machine:

1. A user or host CSR is accepted with `201` and enters `NEW` (`RENEW` for a
   renewal). The request is identified by the public-key SPKI.
2. In manual mode it stays pending until an RA/admin approves it (`APPROVED`)
   and the CA signs it. In auto-sign mode the sandbox performs those transitions
   after the configured number of status lookups.
3. Once signed, the status becomes `VALID` and the record has a certificate id.
   The client polls `/resources/resource/publickey/pk` until that id appears,
   then downloads `/certificate/<id>`.
4. A rejected request is `REJECTED`; a revoked certificate is `REVOKED`.
   Unknown public keys return `404`, and a rejected CSR returns `202` with an
   OpenCA error document.

The client never treats a certificate as trusted merely because the status is
`VALID`: it still checks the public-key match, signature chain, validity and
name constraints locally.

### The runnable sandbox

`sandbox_ca` implements the listener with a throw-away CA hierarchy. It is a
test double and must never be used as a real CA.

```console
$ python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443
```

By default it auto-approves and signs requests after one status lookup. For an
RA-style workflow, use manual mode:

```console
$ python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443 --manual
```

The sandbox provides:

- real TLS, with a server certificate issued by its own test CA;
- the same XML, PPPK, status, download and revocation paths as the legacy
  listener;
- persistent CA hierarchy, pending CSRs and issued certificates in
  `<data-dir>/state.json`, so a restart does not lose a certificate;
- an authenticated admin API and browser console at
  `https://localhost:8443/__sandbox__/ui?token=...`;
- approve, sign, reject and revoke operations, validity settings, captured
  requests and fault injection;
- a Java patcher that replaces CertWizard's bundled CA certificates, SHA-256
  pins and configured URLs.

Typical admin commands:

```console
$ python3 -m sandbox_ca.admin --data-dir .sandbox-ca status
$ python3 -m sandbox_ca.admin --data-dir .sandbox-ca approve 1001
$ python3 -m sandbox_ca.admin --data-dir .sandbox-ca sign 1001
$ python3 -m sandbox_ca.admin --data-dir .sandbox-ca reject 1001 --reason "wrong RA"
```

To run the real Java client against it:

```console
$ python3 -m sandbox_ca.java_kit \
    --data-dir .sandbox-ca \
    --jar /path/to/CertWizard-jar-with-dependencies.jar \
    --out /tmp/CertWizard-sandbox.jar
$ java -jar /tmp/CertWizard-sandbox.jar --self-test
$ java -jar /tmp/CertWizard-sandbox.jar /tmp/certwizard-sandbox-data
```

`sandbox_ca/README.md` covers the admin console, Java lifecycle and persistent
state in more detail.

---

## The ACME v2 wrapper

The ACME wrapper is an RFC 8555 server that lets certbot and other ACME clients
use the same CA state as the legacy listener. It is implemented in
`sandbox_ca/acme.py` and starts alongside the legacy listener:

```console
$ python3 -m sandbox_ca \
    --data-dir .sandbox-ca \
    --port 8443 \
    --acme-port 14000 \
    --acme-challenge-mode auto
```

The output includes both URLs:

```text
URL:              https://localhost:8443
ACME directory:   https://localhost:14000/acme/directory
```

The legacy endpoint remains available. The ACME endpoint is separate, so
migration does not require a flag day and both client generations can coexist.

### How an ACME order maps onto the UK-CA model

The wrapper does not issue from a second CA. It translates ACME objects into
the sandbox CA's existing CSR, signing, certificate and revocation records:

| ACME operation | CA operation |
|---|---|
| `new-order` identifiers | order and authorization records; expected DNS SANs |
| `finalize` CSR | a CA CSR record is created and passed to the CA signing path |
| auto-sign mode | order becomes `valid`; certificate id is the CA certificate id |
| manual CA mode | order stays `processing`; an operator signs the CA record; the next order poll sees `valid` |
| certificate download | CA leaf plus issuing CA PEM chain |
| `revoke-cert` | CA certificate record status becomes `REVOKED` |
| account contact | e-mail stored with the CA CSR record |

This keeps policy, RA behaviour and certificate data in the legacy CA model
rather than creating an ACME-only shadow CA.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/acme/directory` | service directory and metadata |
| `GET`/`HEAD` | `/acme/new-nonce` | fresh `Replay-Nonce` |
| `POST` | `/acme/new-account` | create/find an account using a JWS with `jwk` |
| `POST` | `/acme/new-order` | order DNS identifiers |
| `GET`/`POST` | `/acme/order/<id>` | order status (POST-as-GET) |
| `GET`/`POST` | `/acme/authz/<id>` | authorization and challenges |
| `GET`/`POST` | `/acme/chall/<id>` | challenge status; POST starts validation |
| `POST` | `/acme/finalize/<id>` | submit a base64url DER CSR |
| `GET`/`POST` | `/acme/cert/<id>` | PEM leaf and issuing chain |
| `POST` | `/acme/revoke-cert` | revoke a certificate |
| `POST` | `/acme/key-change` | not supported (501 problem document) |
| `GET` | `/acme/terms` | sandbox terms text |

POSTs use JWS (`application/jose+json`). Supported account algorithms are
`RS256`/`RS384`/`RS512`, `ES256`/`ES384`/`ES512` and `EdDSA`. Nonces are
one-shot and expire after ten minutes; a `badNonce` response includes a fresh
`Replay-Nonce`.

### Challenges and certbot

| Mode | Behaviour |
|---|---|
| `auto` | A challenge POST immediately marks it valid. No HTTP fetch. Useful for a self-contained local sandbox. |
| `http` | The wrapper fetches `http://<identifier>:<port>/.well-known/acme-challenge/<token>` and compares it to `<token>.<account-key-thumbprint>`. |
| `manual` | A challenge stays pending until an operator or a custom driver validates it through the ACME object API. |

Wildcard orders use `dns-01`; `auto` validates them immediately. There is no
DNS provider hook. HTTP validation works with certbot standalone and nginx
webroot.

A local certbot run:

```console
$ certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    -m test@example.org \
    --server https://localhost:14000/acme/directory \
    --no-verify-ssl \
    --http-01-port 18080 \
    -d sandbox.example
```

`--no-verify-ssl` is only needed because the sandbox uses a private test CA.
For a realistic validation use `--acme-challenge-mode http` and a name that
resolves to the machine running certbot. To verify the ACME TLS endpoint, point
the client's CA bundle at `.sandbox-ca/root.pem` instead.

nginx is not an ACME client itself: certbot (or another ACME client) obtains the
certificate, and nginx serves `fullchain.pem`/`privkey.pem`. See
[`docs/ACME.md`](docs/ACME.md) for nginx and webroot examples.

### External Account Binding and persistence

RFC 8555 §7.3.4 EAB is supported. Configure an institutional key identifier and
base64url HMAC secret:

```console
$ python3 -m sandbox_ca \
    --data-dir .sandbox-ca \
    --acme-port 14000 \
    --acme-eab-kid stfc-test \
    --acme-eab-hmac-key "$EAB_HMAC_KEY"
```

When EAB is configured the directory advertises
`externalAccountRequired: true`, and `new-account` without a valid binding is
rejected. HS256/HS384/HS512 are supported.

ACME accounts, orders, authorizations, challenges and certificate mappings are
persisted atomically to `<data-dir>/acme-state.json` (mode `0600`) and restored
on restart. Nonces are deliberately ephemeral, so restart the wrapper on the
same port if existing `kid` URLs must remain valid.

### ACME limits

The wrapper is a test service, not a production ACME deployment. It has:

- no ARI or ACME profiles;
- no key-change;
- in-memory nonces;
- no DNS provider hook for `dns-01`;
- no CAA, OCSP or CRL processing;
- no rate limiting;
- a local test CA that does not perform real domain or identity validation.

Do not expose it to the Internet without a reverse proxy, authentication
boundary, firewall and the production controls described in
[`docs/STFC-ACME-MODERNISATION.md`](docs/STFC-ACME-MODERNISATION.md).

---

## CLI reference

Global options: `--config PATH`, `--json`, `-q/--quiet`, `-v`, `--debug`.

| Command | Purpose |
|---|---|
| `pycert init [DIR]` | create configuration, copy/pin the CA chain and create the saved secret |
| `pycert config show\|check\|path\|set` | inspect, validate, locate or edit configuration |
| `pycert ping` | check connectivity and show the TLS peer |
| `pycert ras` | list RAs published by the CA |
| `pycert info` | message of the day, policy and CA certificates |
| `pycert request CN [--type user\|host]` | generate key + CSR and submit |
| `pycert wait ALIAS` | poll until signed, then download and export |
| `pycert status [ALIAS] [--refresh]` | local state, optionally refreshed from the CA |
| `pycert list` | all requests and permission audit |
| `pycert show ALIAS` | full detail for one request |
| `pycert download ALIAS` | download, verify, store and export |
| `pycert export ALIAS [--out FILE]` | write or rewrite the PKCS#12 |
| `pycert verify ALIAS` | key, certificate, chain and PKCS#12 checks (exit 4 on failure) |
| `pycert renew ALIAS` | renewal with a new key, PPPK-authenticated |
| `pycert renew --due DAYS` | renew certificates expiring within DAYS (`--dry-run` to preview) |
| `pycert proxy ALIAS [--hours N] [--remove]` | create and verify an RFC 3820 proxy bundle |
| `pycert watch [--once]` | poll pending requests continuously and export them |
| `pycert revoke ALIAS --reason R` | revoke at the CA |
| `pycert import FILE.p12` | import an existing bundle |
| `pycert install ALIAS [--dir ~/.globus]` | write `usercert.pem` / `userkey.pem` |
| `pycert delete ALIAS` | delete the local files for a request |
| `pycert secret set\|get\|rm\|list\|test` | manage the saved passphrase |
| `pycert doctor [--offline]` | diagnose configuration, chain, permissions, secrets, DNS, TLS and clock skew |
| `pycert selftest` | offline checks of TOML, keys, CSR, PKCS#12 and bundled chain |
| `pycert gui` | start the graphical interface |

`request`, `renew` and `wait` accept `--wait`, `--timeout`, `--interval`,
`--no-export` and `--allow-unverified-chain`.

Renewal definition options include `--email`, `--san-dns`, `--san-email`,
`--san-ip`, `--clear-san-dns`, `--clear-san-email`, `--clear-san-ip`,
`--key-algorithm`, `--rsa-bits` and `--ec-curve`. The certificate type is
preserved during renewal; changing a user certificate into a host certificate
is a new request, not a renewal. See [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | configuration, crypto, CA rejection or not-found error |
| 2 | command-line usage error |
| 3 | timed out waiting for signing; the request remains stored and can be polled again |
| 4 | certificate chain did not validate |

---

## What pyCert writes

One directory per request under `paths.data_dir` (default
`~/.local/share/pycert`), mode `0700`, files mode `0600`:

```text
requests/jane-doe/
├── state.json        metadata and history (no secrets or PIN)
├── key.pem           PKCS#8, encrypted with the saved secret
├── request.csr       submitted PKCS#10 request
├── cert.pem          issued leaf certificate
├── chain.pem         issuers, leaf-first
├── fullchain.pem     leaf + issuers
├── jane_doe.p12      leaf + chain + key (PBES2/AES-256/HMAC-SHA256)
├── key.next.pem      only while a renewal is in flight
├── request.next.csr  only while a renewal is in flight
├── proxy.pem         optional RFC 3820 proxy bundle
└── previous/         archived files from earlier renewals
```

The PKCS#12 passphrase lives in the configured secret backend (macOS Keychain,
Freedesktop Secret Service, an external password manager, or a `0600` file) and
is never written to configuration or state files.

---

## Security

See [`SECURITY.md`](SECURITY.md) for the full threat model. In short:

- TLS is verified by default against the pinned CA chain, with optional leaf
  pinning and a minimum of TLS 1.2; plaintext HTTP must be explicitly enabled.
- Certificates are accepted only when the public key matches the generated key,
  the chain reaches a configured anchor, every signature verifies, and validity
  and name constraints hold.
- MD5 and SHA-1 signatures are refused; RSA keys must be at least 2048 bits.
- PKCS#12 uses PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC and an HMAC-SHA-256
  integrity MAC, not CertWizard's legacy RC2/3DES.
- Private keys and `.p12` files are written atomically with mode `0600` in
  `0700` directories; `pycert list` audits permissions.
- XML responses are size-limited and DOCTYPE/ENTITY declarations are rejected.
- PINs are never stored, logged, or passed on the command line by default.
- The saved passphrase is kept in the OS keychain where available; the macOS
  backend passes it on stdin to `security -i`, never in `argv`.
- Proxy bundles contain a private key and are written `0600`; remove them when
  the delegated job finishes. See [`docs/PROXY.md`](docs/PROXY.md).

---

## Compatibility notes

The legacy protocol is undocumented and pyCert follows observed CertWizard
behaviour; [`docs/PROTOCOL.md`](docs/PROTOCOL.md) records the exact wire format.

- **PIN hash:** the current server compares the RA hash with SHA-1, so pyCert
  hashes the PIN with SHA-1 (upper-case hex), like CertWizard.
- **PPPK:** only RSA certificates can authenticate host requests and renewals;
  ECDSA keys are fine for ordinary user requests.
- **Host requests** need an existing, currently valid certificate (`--auth`).
- **E-mail:** for user certificates the contact e-mail is also a SAN e-mail and
  must match the XML `<Email>` element.
- **Renewal subject:** the existing subject is preserved, with attributes
  ordered for OpenCA.
- **AIA fetching** is enabled for missing intermediates; fetched certificates
  are signature-checked before use.

### Python support

pyCert runs on **Python 3.6 and newer**. It avoids `dataclasses`, `tomllib`,
`datetime.fromisoformat` and other newer APIs; `pycert/compat.py`,
`pycert/toml.py` and `pycert/_dataclasses.py` provide fallbacks. Every package
file is checked against the 3.6 grammar by `tools/check_py36.py`, and the test
suite runs against Python 3.6.15 with `cryptography 3.3.2` in a container.

Python 3.6 is end-of-life and the newest compatible `cryptography` is 3.3.x;
use Python 3.9+ for new deployments.

---

## Development and tests

```console
$ make dev            # virtualenv with pytest, ruff and vermin
$ make test           # full test suite (7,397 tests)
$ make coverage       # full suite + 100% non-GUI line coverage gate
$ make lint           # ruff
$ make check-py36     # grammar + runtime feature checks for Python 3.6
$ make build          # wheel and sdist
```

The suite includes:

- a **mock legacy CA** speaking XML/PPPK over real TLS, with fault injection;
- end-to-end CLI tests for every action;
- Java wire-parity fixtures and an optional live CertWizard differential test;
- 3,003 ACME cases covering JWS, orders, challenges, EAB, persistence, CSR
  matching, revocation and routing;
- 1,000 legacy listener/XML/PPPK cases;
- chain building, AIA fetching, PKCS#12, Python 3.6 fallbacks, proxy bundles and
  a differential TOML parser check against `tomllib`.

The optional real-client tests run when `CERTWIZARD_JAR` or `CERTBOT_BIN` is
set:

```console
$ CERTWIZARD_JAR=/path/to/CertWizard.jar .venv/bin/pytest -q tests/test_certwizard_wire_parity.py
$ CERTBOT_BIN=/path/to/certbot .venv/bin/pytest -q tests/test_acme_certbot.py
```

Project layout:

```text
src/pycert/
├── config.py          TOML configuration, validation and chain pins
├── ca.py              legacy CA client, PPPK, XML parsing
├── transport.py       hardened HTTP(S): deadlines, retries, limits, DNS, TLS
├── chain.py           chain building and path validation
├── certs.py           certificate/key helpers
├── csr.py             PKCS#10 construction
├── p12.py             PKCS#12 read/write
├── bundles.py         legacy Java/PEM certificate bundle decoder
├── ber.py             strict BER/DER reader for Java PKCS#12
├── pkcs12_writer.py   modern PKCS#12 container
├── store.py           on-disk state, permissions and locking
├── secrets_store.py   keychain/secret-service/file/command backends
├── workflow.py        request → wait → download → export → renew → revoke
├── proxy.py           RFC 3820 proxy bundles
├── diagnostics.py     doctor and selftest
├── cli.py             argparse front-end
└── gui.py             Tkinter front-end

sandbox_ca/
├── mock_ca.py         legacy listener implementation and fault injection
├── server.py          persistent sandbox, admin API and ACME startup
├── acme.py            RFC 8555 ACME v2 wrapper
├── java_kit.py        CertWizard JAR/URL/CA patcher
└── admin.py           admin CLI
```

Further documentation:

- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — configuration reference
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — legacy wire protocol
- [`docs/CA_LISTENER.md`](docs/CA_LISTENER.md) — legacy listener contract
- [`docs/ACME.md`](docs/ACME.md) — ACME endpoints, certbot and nginx
- [`docs/STFC-ACME-MODERNISATION.md`](docs/STFC-ACME-MODERNISATION.md) — production architecture, policy and migration dossier
- [`docs/PROXY.md`](docs/PROXY.md) — RFC 3820 proxy bundles
- [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md) — user/host definitions and renewal changes
- [`sandbox_ca/README.md`](sandbox_ca/README.md) — sandbox admin console and Java kit

---

## Limitations and non-goals

- No OCSP/CRL checking of issued certificates; the CA publishes CRL URLs, and
  `openssl verify -crl_check` can be used with the CRL if needed.
- One CA profile per configuration file; use `--config` for multiple profiles.
- No bulk host requests (`/CSRs` with multiple `<CSR>` elements).
- No Windows installer; the CLI and GUI run where Python 3.6+ and Tk are
  available.
- The legacy protocol implementation follows observed CertWizard behaviour, not
  a published specification.
- The sandbox CA and ACME wrapper are test systems, not a production CA.
- On Python 3.6, `cryptography` cannot be newer than 3.3.x; use a newer Python
  for security updates.

## Licence

GPL-2.0-or-later, the same licence as CertWizard. The bundled UK e-Science CA
certificates are public CA certificates published by the CA and by the IGTF.
