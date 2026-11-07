# pyCert

**A Python 3 replacement for the Java CertWizard client for the UK e-Science CA.**

One command requests a certificate, waits for the RA to approve and the CA operator
to sign it, downloads the issued certificate with its *full chain*, verifies that
chain, and writes an encrypted PKCS#12 bundle whose passphrase is kept in the OS
secret store:

```console
$ pycert request "Jane Doe" --wait
  Preparing request...
  Generating a 3072-bit RSA key (this can take a few seconds)...
  Building the PKCS#10 request for 'C=UK,O=eScience,OU=CLRC,L=DL,CN=jane doe'...
  Submitting to the CA...
  CSR submitted; awaiting RA approval and CA signing. ...
  submitted, awaiting RA approval — next check in 60s (attempt 1, 0s elapsed)
  Certificate issued (server status VALID)
  Verifying the certificate chain...
  Certificate stored: ~/.local/share/pycert/requests/jane-doe/cert.pem (valid until 2027-11-06)
  Writing PKCS#12 bundle ~/.local/share/pycert/requests/jane-doe/jane_doe.p12 ...
  PIN for the RA: K7QF-2M9X-P4RT

Request 'jane doe' is DOWNLOADED.
  PKCS#12: ~/.local/share/pycert/requests/jane-doe/jane_doe.p12
```

It also has a lightweight Tkinter GUI (`pycert gui`) that does the same thing and
adds a certificate list, expiry warnings, chain inspection and one-click verification.

---

## Why this exists

The Java client works, but it is hard to audit, hard to automate, and carries a
lot of legacy: a bundled JRE, Restlet, BouncyCastle, Log4j and a trust store
whose password is the literal string `passwd`. pyCert is about 10,700 lines of
Python - including a 2,000-line Tkinter GUI - plus 7,800 lines of tests, and
depends only on [`cryptography`](https://cryptography.io/). The modules that
talk to the CA (transport, client, chain, certificates, CSR, PKCS#12 and
workflow) are about 4,000 lines and can be reviewed end to end in an afternoon.

### At a glance

| | CertWizard (Java) | pyCert |
|---|---|---|
| Runtime | JDK 25+ (current `develop`), bundled JRE in installers | Python 3.6+ (stdlib + `cryptography`) |
| Startup | JVM + Swing + Restlet initialisation | ~90 ms CLI, ~440 ms to a painted GUI window (measured) |
| Build | Maven, NetBeans for the GUI forms | `pip install .` |
| TLS trust | JKS trust store, password `passwd` in the config | PEM chain in the config, pinned by SHA-256; optional leaf pin |
| CSR signature | `MD5WithRSA` in the shipped template | SHA-256 minimum; MD5/SHA-1 refused |
| Private key | PKCS#12 client keystore, password passed via a Java system property | PKCS#8 encrypted per request, mode 0600 |
| PKCS#12 export | manual, per certificate, password typed into a dialog | automatic after signing; passphrase in keychain/secret service, mode 0600 |
| Chain | downloaded certificate only; chain building was a TODO | full chain built and **cryptographically verified** before export |
| Waiting for signing | user clicks refresh repeatedly | `--wait` / `pycert wait`, exponential jitter, cancellable, exit code 3 on timeout |
| PIN | SHA-1 hash, entered in a Swing dialog | SHA-1 hash (server requirement), generated once and shown in a modal/GUI |
| Automation | GUI only | CLI + `--json` + exit codes + cron/launchd examples |
| Tests | a couple of XML parser tests | 3,170+ tests (3,174 at the last check), including a mock CA listener, every CLI action end-to-end, fault injection, fuzzing and concurrency suites |
| Documentation | `readme.txt` | README, configuration reference, protocol notes, CA-listener contract + Java sandbox, security model, migration guide |

Everything above is verifiable from the sources: the Java template default is in
`src/main/resources/template.configure.properties`, the trust store password in
`SysProperty.setupTrustStore()`, the “chain building” TODO in
`readme.txt` and `ClientKeyStoreCaServiceWrapper`.

---

## Install

```console
$ git clone <this repo> ~/src/pyCert
$ cd ~/src/pyCert
$ python3 -m venv .venv
$ .venv/bin/pip install -e .
$ .venv/bin/pycert --version
```

The only mandatory dependency is `cryptography` (OpenSSL-backed; `>=3.0`, with
the newest compatible release selected for your Python). The GUI uses
`tkinter` from the standard library; on macOS with Homebrew Python install it
with `brew install python-tk@3.15` (or the matching version).

### Supported Python versions

pyCert runs on **Python 3.6 and newer**.  The package deliberately avoids
`dataclasses`, `tomllib`, `datetime.fromisoformat` and other 3.7+ APIs; the
compatibility layer (`pycert/compat.py`, `pycert/toml.py`,
`pycert/_dataclasses.py`) has its own tests and every package file is checked
against the 3.6 grammar by `tools/check_py36.py`.

Python 3.6 is end-of-life, and the newest `cryptography` that supports it is
3.3.x.  pyCert works there — including the old-cryptography API fallbacks — but
for new deployments use Python 3.9 or newer.  On 3.6 the dependency resolver
picks cryptography 3.3.x automatically.

The package is validated on Python 3.6.15 with cryptography 3.3.2 in a
container: install, `pycert selftest`, `init`, `config check`, live `ping`/`ras`
and `doctor`, plus a full mock-CA request → download → PKCS#12 → renew → revoke
flow.  The 3,174 test suite itself runs on a modern Python.

---

## Quick start

```console
$ pycert init ~/.config/pycert --email you@example.org --ra "CLRC DL"
Configuration written to ~/.config/pycert/pycert.toml
Data directory:        ~/.local/share/pycert
Saved secret backend: keychain (p12 account 'default')
CA server:            https://cwiz-live.ca.ngs.ac.uk:443

$ pycert config check
OK: 4 CA certificates loaded, 4 trust anchors, all pins verified.

$ pycert ras
88 RAs on https://cwiz-live.ca.ngs.ac.uk:443:   # the count changes as RAs are added
    Aberdeen DIT
    ...

$ pycert request "Jane Doe" --wait
```

`pycert init` copies the four UK e-Science CA certificates into
`~/.config/pycert/chain/` and records their SHA-256 fingerprints in the config.
They are used for three things:

1. as the **TLS trust anchors** for the CA server (so the host certificate is
   verified, unlike CertWizard's hard-coded JKS),
2. as the **trust anchors for certificate path validation**,
3. as the **chain embedded in the exported PKCS#12**.

Nothing is trusted from the network without a signature check; certificates
fetched from `authorityInfoAccess` URLs are only accepted if the child's
signature verifies with them.

### Request a host certificate

Host certificates must be authenticated by an existing certificate (PPPK, as in
the Java client):

```console
$ pycert request host.example.ac.uk --type host --auth "jane doe" --wait
```

### Renew and revoke

```console
$ pycert renew "jane doe" --wait      # new key, PPPK-authenticated with the old one
$ pycert revoke "jane doe" --reason superseded
```

A renewal never overwrites a working certificate until the new one has been
issued: the new key and CSR are written as `key.next.pem` / `request.next.csr`,
and the previous key, certificate and `.p12` are moved to `previous/<timestamp>/`
only after the new certificate has been verified.

### Inspect and verify

```console
$ pycert list
ALIAS                        TYPE  STATUS      EXPIRES          DAYS  P12
jane doe                     user  DOWNLOADED  2027-11-06        364  yes

$ pycert verify "jane doe"
Verifying 'jane doe'
  [OK  ] certificate present: C=UK,O=eScience,OU=CLRC,L=DL,CN=jane doe
  [OK  ] private key present: RSA 3072
  [OK  ] key matches certificate: SubjectPublicKeyInfo comparison
  [OK  ] certificate valid now: 2026-11-06 .. 2027-11-06
  [OK  ] chain validates: 3 certificates
  [OK  ] chain is complete: root included
  [OK  ] PKCS#12 readable: .../jane_doe.p12
```

`pycert verify` exits 4 if anything fails, which makes it usable in monitoring.

### Import an existing CertWizard PKCS#12

```console
$ pycert import ~/.ca/cakeystore.pkcs12 --alias "old cert"
Imported 'old cert'; re-exported as ~/.local/share/pycert/requests/old-cert/old_cert.p12
```

Legacy PBE-SHA1-3DES and RC2 files produced by Java 8 are readable, so you can
migrate a key and keep renewing it without generating a new key pair.

---

## The GUI

```console
$ pycert gui
```

- **Certificate list** with alias, type, status, expiry and days remaining;
  status colours plus text (never colour alone).
- **Overview** of the selected request: subject, issuer, validity, key, SHA-256,
  SANs, chain verification result, file paths and CA state.
- **Certificate** tab: decoded certificate details and the verified chain.
- **History** tab: every state transition recorded by pyCert.
- **New request** dialog: type (user/host), RA fetched from the CA, key
  algorithm and size, extra SANs, PIN generation, “wait for signing and export”.
- **Wait** dialog with live progress and a cancel button.
- **Verify**, **Export**, **Renew**, **Revoke** and **Import** actions.
- **Settings** tabs for server/TLS, identity, keys/CSR, secrets and the CA chain
  (with pins), plus a secret-store self-test.
- Activity log with timestamps (bounded, copyable) and clear error dialogs.

The GUI never displays private keys or the PKCS#12 passphrase, and the PIN is
shown once in a modal dialog with a copy button.

---

## CLI reference

Global options: `--config PATH`, `--json`, `-q/--quiet`, `-v`, `--debug`.

| Command | Purpose |
|---|---|
| `pycert init [DIR]` | create config, copy/pin the CA chain, create the saved secret |
| `pycert config show\|check\|path\|set` | inspect, validate, locate or edit configuration |
| `pycert ping` | check connectivity and show the TLS peer |
| `pycert ras` | list RAs published by the CA (`*` = preferred) |
| `pycert info` | message of the day, policy, CA certificates |
| `pycert request CN [--type user\|host]` | generate key + CSR and submit |
| `pycert wait ALIAS` | poll until signed, then download and export |
| `pycert status [ALIAS] [--refresh]` | local state, optionally refreshed from the CA |
| `pycert list` | all requests (also audits file permissions) |
| `pycert show ALIAS` | full detail for one request |
| `pycert download ALIAS` | download, verify, store and export |
| `pycert export ALIAS [--out FILE]` | (re-)write the PKCS#12 |
| `pycert verify ALIAS` | key/certificate/chain/PKCS#12 checks (exit 4 on failure) |
| `pycert renew ALIAS` | renewal with a new key, PPPK-authenticated |
| `pycert renew --due DAYS` | renew every certificate expiring within DAYS (`--dry-run` to preview) |
| `pycert watch [--once]` | poll pending requests continuously and export them as they are signed |
| `pycert revoke ALIAS --reason R` | revoke at the CA |
| `pycert import FILE.p12` | import an existing bundle |
| `pycert install ALIAS [--dir ~/.globus]` | write `usercert.pem` / `userkey.pem` |
| `pycert delete ALIAS` | delete the local files for a request |
| `pycert secret set\|get\|rm\|list\|test` | manage the saved passphrase |
| `pycert doctor [--offline]` | diagnose configuration, chain, permissions, secrets, DNS, TLS and clock skew |
| `pycert selftest` | offline self-checks of TOML, key generation, CSR, PKCS#12 and the bundled chain |
| `pycert gui` | start the graphical interface |

`request`, `renew` and `wait` accept `--wait`, `--timeout` (default 24h),
`--interval` (default 60s), `--no-export` and `--allow-unverified-chain`.

PIN options: `--generate-pin` (default when there is no terminal), `--pin-file`,
`--pin-stdin`, or an interactive double prompt. `--pin VALUE` works but is
visible in the process list and prints a warning.

Passphrase options for `import`/`export`/`download`: `--password-file`,
`--password-stdin`, or the saved secret (the default).

### Network behaviour

The CA client is built on a hardened transport (`pycert/transport.py`) rather
than raw `urllib` calls:

* **deadlines**: every request has a total deadline (`ca.deadline`) in addition
  to socket timeouts; headers and body are read in bounded chunks so a trickling
  server cannot pin a thread;
* **DNS**: resolution has its own timeout (`ca.dns_timeout`), a small positive
  cache, and returns a clear `dns` error instead of hanging;
* **framing**: short `Content-Length`, malformed chunks, bad status lines,
  oversized headers/bodies and compressed responses are hard errors, never
  silently truncated data;
* **retries**: only idempotent requests (GET/HEAD and the status lookup) are
  retried, with exponential backoff and full jitter; `408`, `425`, `429`, `500`,
  `502`, `503`, `504` are retryable and `Retry-After` is honoured (capped);
  submissions and revocations are **never** retried;
* **redirects**: at most `ca.max_redirects` same-host redirects, never for POST,
  never to plaintext or another host;
* **cancellation**: a stop event is honoured before connecting and between body
  chunks, so the GUI's Cancel and Ctrl-C are responsive;
* **clock skew**: the server's `Date` header is used to correct the timestamp in
  the PPPK challenge, so a slightly wrong local clock does not break renewals.

Tune these with `ca.connect_timeout`, `ca.deadline`, `ca.dns_timeout`,
`ca.retries`, `ca.max_redirects`, `ca.max_body_bytes`, `ca.max_header_bytes`,
`ca.backoff_base` and `ca.backoff_cap` — see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error (configuration, crypto, CA rejection, not found) |
| 2 | command line usage error |
| 3 | timed out waiting for signing — the request is still stored and can be polled again |
| 4 | certificate chain did not validate |

### Automation

`pycert status --refresh` polls every pending request once and is safe to run
from cron. A typical crontab entry:

```cron
# every 15 minutes: finish any request the RA has approved
*/15 * * * * /home/you/.local/bin/pycert -q status --refresh >>/home/you/.local/state/pycert.log 2>&1
```

`examples/` contains a launchd plist for macOS and a systemd timer for Linux, plus
an example annotated configuration.

---

## What pyCert writes

One directory per request under `paths.data_dir`
(default `~/.local/share/pycert`), mode 0700, files mode 0600:

```
requests/jane-doe/
├── state.json        # metadata and full history (no secrets, no PIN)
├── key.pem           # PKCS#8, encrypted with the saved secret
├── request.csr       # the submitted PKCS#10 request
├── cert.pem          # issued leaf certificate
├── chain.pem         # issuers, leaf-first
├── fullchain.pem     # leaf + issuers
├── jane_doe.p12      # leaf + chain + key, PBES2/AES-256, HMAC-SHA256
├── key.next.pem      # only while a renewal is in flight
├── request.next.csr  # only while a renewal is in flight
└── previous/         # archived files from earlier renewals
```

The PKCS#12 passphrase lives in the configured secret backend (macOS Keychain,
Freedesktop Secret Service, an external password manager, or a 0600 file) and is
never written to the configuration or the state files.

---

## Security

Read [SECURITY.md](SECURITY.md) for the threat model. In short:

- TLS is verified by default against the pinned CA chain, with optional leaf
  pinning and a minimum of TLS 1.2; plaintext HTTP must be explicitly enabled.
- Certificates are only accepted if their public key matches the generated key,
  their chain reaches a configured anchor, every signature verifies, and the
  validity window and name constraints hold.
- MD5 and SHA-1 signatures are refused; RSA keys must be at least 2048 bits.
- PKCS#12 uses PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC and an HMAC-SHA-256
  integrity MAC (the modern OpenSSL default), not CertWizard's legacy RC2/3DES.
- Private keys and `.p12` files are written atomically with mode 0600 in 0700
  directories; the CLI audits permissions in `pycert list`.
- XML responses are size-limited and DOCTYPE/ENTITY declarations are rejected.
- PINs are never stored, logged or passed on the command line by default.
- The saved passphrase is kept in the OS keychain where available; the macOS
  backend passes it on stdin to `security -i`, never in `argv`.

---

## Compatibility notes

The CA protocol is undocumented; pyCert implements what CertWizard does (see
[docs/PROTOCOL.md](docs/PROTOCOL.md)). The listener contract and a runnable
sandbox for the real Java client are documented in
[docs/CA_LISTENER.md](docs/CA_LISTENER.md). Points to be aware of:

- **PIN hash:** the current server compares the RA’s hash with a SHA-1 hash, so
  `pycert` hashes the PIN with SHA-1 (upper-case hex), like the Java client.
  `csr.pin_hash = "sha256"` exists for future server changes and prints a warning.
- **PPPK:** host requests and renewals authenticate with the RSA private
  exponent. Only RSA certificates can authenticate these requests; ECDSA client
  keys are fine for ordinary user requests but cannot be used for renewal with
  this server.
- **Host requests** need an existing, currently valid certificate (`--auth`).
- **Email:** for user certificates the contact e-mail is also the SAN e-mail, and
  it must match the `<Email>` element (the server checks).
- **Renewal subject:** the existing subject is preserved, with attributes
  re-ordered to OpenCA’s expectation (CN, L, OU, O, C, e-mail first).
- **AIA fetching** is enabled for missing intermediates. Fetched certificates are
  signature-checked before use, so an untrusted HTTP AIA URL cannot inject a
  bogus issuer.

---

## Development

```console
$ make dev            # virtualenv with pytest, ruff and vermin
$ make test           # 3,174 tests
$ make lint           # ruff
$ make check-py36     # grammar + runtime feature checks for Python 3.6
$ make build          # wheel + sdist
```

The test suite includes a **mock CA** (`sandbox_ca/mock_ca.py`, re-exported as
`tests/mock_ca.py`) that speaks the same
XML protocol over real TLS, with an RSA root signing an ECDSA intermediate, and a
raw fault-injection server (`tests/raw_server.py`) that can send malformed
status lines, truncated bodies, slow bytes, resets, redirects and oversized
responses. Tests cover submission, PPPK challenges, polling, certificate
download, chain building (including AIA fetching over HTTP), renewal, revocation,
PKCS#12 export, the Python 3.6 fallbacks and a differential TOML parser check
against `tomllib`. Generated `.p12` files and certificates are cross-checked with
the `openssl` command line where available.

```
src/pycert/
├── config.py          TOML configuration, validation, chain pins
├── ca.py              HTTP/TLS client, PPPK, XML parsing
├── chain.py           chain building and path validation
├── certs.py           certificate/key helpers, descriptions, names
├── csr.py             PKCS#10 construction
├── p12.py             PKCS#12 read/write
├── pkcs12_writer.py   modern PKCS#12 container (PBES2/AES-256, HMAC-SHA256)
├── asn1.py            minimal DER encoder for the PKCS#12 container
├── store.py           on-disk state, permissions, locking
├── secrets_store.py   keychain/secret-service/file/command backends
├── workflow.py        request → wait → download → export → renew → revoke
├── transport.py       hardened HTTP(S): deadlines, retries, limits, DNS, TLS
├── toml.py            TOML parser for Python 3.6
├── compat.py          version/API compatibility helpers
├── diagnostics.py     doctor / selftest
├── cli.py             argparse front-end
└── gui.py             Tkinter front-end
```

## Limitations and non-goals

- No OCSP/CRL checking of issued certificates (the CA publishes CRL URLs; use
  `openssl verify -crl_check` with the CRL if you need revocation checking).
- One CA profile per configuration file (use `--config` for several).
- No bulk host certificate requests (`/CSRs` with multiple `<CSR>` elements).
- No Windows installer; the CLI and GUI run wherever Python 3.6+ and Tk are
  available.
- The protocol implementation follows observed CertWizard behaviour, not a
  published specification; see docs/PROTOCOL.md for the exact wire format.
- On Python 3.6, `cryptography` cannot be newer than 3.3.x (upstream EOL), so
  security fixes may require a newer Python; pyCert warns about this in
  `pycert doctor`.

## Licence

GPL-2.0-or-later, the same licence as CertWizard. The bundled UK e-Science CA
certificates are public CA certificates published by the CA and by the IGTF.
