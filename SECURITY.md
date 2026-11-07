# Security model

This document describes what pyCert protects, what it does not, and the
reasoning behind the defaults. It is written for the person who has to sign off
on using pyCert in a production environment.

## What pyCert is

pyCert is a client for one specific CA (the UK e-Science CA, OpenCA-based). It:

1. generates a key pair and a PKCS#10 request on the local machine;
2. submits it over HTTPS to the CA;
3. polls the CA until a certificate for that public key appears;
4. verifies the certificate, its public key, and its chain;
5. writes the key, certificate, chain and an encrypted PKCS#12 bundle.

It never sends the private key anywhere. The only secret that leaves the machine
is the PIN hash (a one-way hash of the PIN the RA checks), which is part of the
protocol.

## Threat model

In scope:

* a **network attacker** who can intercept or modify traffic between the client
  and the CA;
* a **malicious or compromised CA response** (forged certificate, mismatched
  public key, unexpected chain);
* **other local users** on a shared machine reading keys or passphrases;
* **accidental disclosure** through logs, shell history, backups or crash dumps;
* **operator error** (wrong server, wrong CA, stale certificate, wrong key).

Out of scope:

* an attacker with **root on the machine** while pyCert is running, or who can
  read process memory;
* **malware** in the Python environment or its dependencies;
* **side-channel attacks** against the OpenSSL code used by `cryptography`;
* **hardware token** protection — pyCert keeps keys in files, which is what this
  CA expects. If you need a TPM/HSM, do not use pyCert for those keys.

## TLS

* `ca.tls_verify = true` by default. Verification uses the CA chain in
  the configuration as trust anchors (`ca.tls_trust = "chain"`), the OS store
  (`"system"`), or both.
* Minimum protocol version is TLS 1.2 (pyCert never disables certificate
  verification silently; turning it off produces a warning on every load).
* `ca.tls_pin_sha256` optionally pins the server's leaf certificate. This is
  defence in depth: it protects against a compromised public CA that is somehow
  in your trust store, but the chain check is the primary control.
* Plaintext HTTP is refused unless `ca.allow_plaintext = true`; that option
  exists for a local test CA only.
* The Java client built a JKS trust store whose password is the literal
  `passwd`. A trust store password protects nothing in that design; pyCert does
  not use one, and the trust anchors are ordinary PEM files you can diff and pin.

## Certificate validation

A downloaded certificate is accepted only if all of these hold:

1. its SubjectPublicKeyInfo is **byte-for-byte identical** to the public key
   stored for the request (so the CA cannot substitute a different key);
2. the current time is inside its validity window;
3. the subject common name is the one that was requested (a difference is
   recorded as a warning, not silently accepted);
4. a chain can be built in which every signature verifies with the issuer's
   public key, AuthorityKeyIdentifier/SubjectKeyIdentifier agree, and no issuer
   is marked `basicConstraints CA=false`;
5. every certificate below the trust anchor is inside its validity window and
   uses an acceptable signature hash (MD5 and SHA-1 are refused; the anchor is
   trusted out of band, as in RFC 5280);
6. any DNS name constraints in the issuer permit the subject alternative names.

Intermediates that are missing locally are downloaded from the certificate's
`authorityInfoAccess` URL. That download is unauthenticated by design (the URLs
are often plain HTTP), which is safe here because the fetched certificate must
verify the child's signature before it is used. The URL content is size-limited
to 1 MiB.

The chain and leaf are verified **before** a `.p12` is written. If the chain does
not reach a configured anchor, pyCert stores the certificate so you can inspect
it, but refuses to export, and exits 4. `--allow-unverified-chain` overrides
this and is deliberately verbose about the risk.

## Keys and PKCS#12

* RSA keys are at least 2048 bits; the default is 3072. ECDSA P-256/P-384/P-521
  are available for ordinary user requests. MD5/SHA-1 **signatures** are refused.
* Private keys are stored as encrypted PKCS#8 (`BestAvailableEncryption`, i.e.
  PBES2 with a strong KDF) with mode 0600 in a 0700 directory.
* The exported PKCS#12 is written by pyCert's own container encoder using
  `cryptography` primitives: PBES2, PBKDF2-HMAC-SHA256 (100,000 iterations),
  AES-256-CBC for the key bag and encrypted SafeContents, and an HMAC-SHA-256
  integrity MAC.  This is deliberately independent of the OpenSSL version
  linked into `cryptography`, because older releases would otherwise write
  legacy PBE-SHA1-3DES/SHA-1 files.  A SHA-1 MAC fallback is used only if the
  installed reader cannot verify HMAC-SHA-256; the encryption stays AES-256.
  The output is readable by OpenSSL 3, Java 11+, macOS Keychain, Firefox and
  Windows.
* The PKCS#12 passphrase is generated with `secrets.token_urlsafe(32)` (256 bits
  of entropy) when pyCert creates it, so the KDF iteration count is not the
  limiting factor.  The MAC key is derived with the RFC 7292 KDF and validated
  against published test vectors. If you supply your own weak passphrase, that is on you; the
  `import`/`export` commands accept one for interoperability.
* CertWizard’s export path used Java’s default provider and had a documented
  7-character password limit and legacy PBE ciphers. pyCert’s default is modern;
  legacy files can still be **read** for migration.

## The saved passphrase

pyCert must be able to write a `.p12` unattended, so the passphrase is stored.
Backends, in order of preference:

| Backend | Storage | Notes |
|---|---|---|
| `keychain` | macOS login keychain | macOS only. Written through `security -i` on **stdin**, so the secret never appears in `argv` or the process list. |
| `secret-service` | GNOME Keyring / KWallet via `secret-tool` | Linux desktops. |
| `command` | external password manager | The command is trusted configuration. Reads stdout / writes stdin. |
| `file` | JSON, mode 0600 | Plaintext at rest. pyCert prints a warning when it creates one. |
| `env` | environment variable | Read-only; for CI. |
| `prompt` | nothing | Asks every time; cannot generate a secret. |

`auto` picks keychain, then secret-service, then file. The chosen backend is
recorded in the configuration so behaviour is reproducible.

Limitations: the `file` backend protects against other users, not against
someone who can read your home directory (backups, sync clients, root). Use
`keychain`, `secret-service` or `command` if that matters. A secret passed with
`--password` is visible in `ps` for the lifetime of the process; use
`--password-file` or the saved secret instead.

## Secrets that are never stored

* the **PIN**: used once to compute the hash sent with the CSR, printed to the
  user for the RA, and discarded. It is never written to `state.json`, the log,
  or a temporary file. In the GUI it is shown in a modal dialog and not added to
  the activity log.
* the **private key passphrase** is derived from the secret store and only held
  in memory for the duration of a command.
* the CA operator’s PIN, passwords, or any other credential: pyCert does not
  know about them.

## Filesystem

* directories containing keys are created 0700, files 0600, atomically (write to
  a temporary file in the same directory, `fsync`, `rename`), so a crash cannot
  leave a partially written key and there is no window in which the file is
  world-readable.
* permissions of existing files are checked, and `pycert list` audits the whole
  data directory, reporting anything group/other-accessible or symlinked;
* secret files are updated under an advisory lock (threads and processes), and
  the secret store refuses symlinked secret files and symlinked lock files;
* atomic writes `fsync` the file and then the parent directory, so a crash or
  power loss cannot lose a completed rename;
* TOML, XML, PEM, certificate, state and PKCS#12 inputs all have hard size,
  depth and count limits (see docs/CONFIGURATION.md).
* backups: a renewal moves the old key, certificate and `.p12` into
  `previous/<timestamp>/` with the same 0600/0700 permissions. Deleting a request
  removes the directory recursively; nothing is copied elsewhere.

## Network hardening

The transport is written for a hostile network and is covered by fault-injection
tests (`tests/test_transport.py`):

* **total deadlines** per request, checked between body chunks, with socket
  timeouts set to the smaller of the read timeout and the remaining deadline;
* **DNS timeouts** and a positive cache; resolver errors are classified as
  `dns` rather than surfacing as opaque connection failures;
* **strict framing**: declared vs actual body length, chunked encoding, status
  line, header count/size, `Content-Encoding: identity`; truncation and
  oversized data are errors;
* **retry policy**: idempotent requests only, exponential backoff with full
  jitter, `Retry-After` support and a cap; POST submissions and revocations are
  never retried, so a duplicate CSR cannot be created by a retry;
* **redirect policy**: same host, same scheme, GET/HEAD only, bounded count,
  loop detection; cross-host and plaintext redirects are refused;
* **cancellation** via an event checked before connecting and between body
  chunks;
* **clock skew correction** from the server's `Date` header for PPPK timestamps.

## Network surface

* Only HTTPS requests to URLs derived from `ca.base_url` and the configured
  endpoint paths are made. Certificate IDs are validated before being appended
  to a URL (no `../` traversal).
* GET requests are retried with jitter on connection errors; **POST requests are
  never retried**, because a submission might already have reached the server.
  After a failed submission the state is preserved and you are told to check the
  status rather than risk a duplicate.
* Response bodies are capped at 8 MiB; XML at 4 MiB; DOCTYPE and ENTITY
  declarations are rejected (entity-expansion and XXE defence).
* Error messages include the server's `<text>` elements, HTTP status and the URL
  host/path. They never include request header values, key material,
  passphrases or the PIN.

## Logging

* Progress goes to stderr; machine-readable results to stdout with `--json`.
* The GUI keeps a bounded in-memory log. It contains aliases, subjects, HTTP
  statuses and file paths; never PINs or passphrases.
* `--debug` prints a traceback. Tracebacks can contain local file paths but no
  secret values (secrets are not passed as arguments to functions that raise).

## Comparison with CertWizard’s known weaknesses

These are properties of the Java code as shipped in this repository, not
opinions:

| Issue in CertWizard | pyCert |
|---|---|
| `ngsca.cert.signature.algorithm=MD5WithRSA` in the template properties | SHA-256 default; MD5/SHA-1 refused for certificates and requests |
| JKS trust store with password `passwd` | PEM anchors, SHA-256 pinned; no store password |
| Password handed between components in a Java **system property** | secret store; never in environment variables by default |
| PKCS#12 export with a user-typed password and legacy ciphers | saved high-entropy passphrase; PBES2/AES-256/HMAC-SHA-256 |
| Key store backup copies (`backup/cakeystore.pkcs12.backup`) created with default umask | no implicit copies; archives are explicit, 0600 |
| No chain verification of the downloaded certificate | full cryptographic path validation before export |
| No automated polling | `--wait`, `wait`, `status --refresh`, cron/launchd examples |
| XML parsing via DocumentBuilder without hardening | DOCTYPE/ENTITY rejected, size limits |
| Error messages occasionally include raw exception dumps | typed errors, one-line messages, `--debug` for tracebacks |

## Python 3.6

pyCert supports Python 3.6 by using its own TOML parser, a tested dataclasses
fallback and compatibility shims for old `cryptography` releases.  Python 3.6 is
end-of-life and the newest compatible `cryptography` is 3.3.x, which no longer
receives fixes.  `pycert doctor` warns about this.  Run pyCert on a supported
Python for anything security-sensitive.

## Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue. Include the version (`pycert --version`), the platform, and a
reproduction that does not contain real private keys.
