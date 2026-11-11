# Configuration reference

pyCertWiz reads one TOML file. Use `--config PATH`, set `PYCERT_CONFIG`, or place it
at `$XDG_CONFIG_HOME/pycert/pycert.toml` / `~/.config/pycert/pycert.toml` (also
`~/.pycert/config.toml`). The file is parsed with the standard library's
`tomllib` (`tomli` on Python 3.10) and must be smaller than 1 MiB. The current
directory is deliberately **not** searched: a `pycert.toml` in an untrusted
directory could point the tool at an attacker’s CA or a `command` secret backend.

Create a starting point with:

```console
$ pycert init ~/.config/pycert --email you@example.org
$ pycert config check
```

`pycert config set key=value` edits scalar values in place. Comments are
preserved only until the next `config set` (the file is rendered by pyCertWiz);
keep notes in a separate file if that matters.

---

## Top level

```toml
version = 2              # configuration format version (1 and 2 are accepted)
profile = "default"      # name used to namespace saved secrets
default_ca = "uk-escience"  # CA profile for new requests (see "CA profiles")
```

`profile` lets several configurations on one machine share a secret backend
without colliding (`service:profile`). Version 1 files (pyCert 1.x) load
unchanged: their `[ca]` becomes the primary CA profile.

---

## `[ca]`

The primary CA, spoken to with the CertWizard/OpenCA protocol.

| Key | Default | Meaning |
|---|---|---|
| `name` | `uk-escience` | profile name stored with each request (lower-case letters, digits, `.-_`) |
| `display_name` | `UK e-Science CA` | name shown by `pycert ca list` and the GUI |
| `base_url` | `https://cwiz-live.ca.ngs.ac.uk:443` | CA server, scheme + host + optional port |
| `version_string` | `CertWizard 2.2.1` | value sent in the `<Version>` XML element; the server validates it |
| `user_agent` | `pyCertWiz/2.0` | HTTP `User-Agent` |
| `timeout` | `30` | socket read timeout in seconds |
| `connect_timeout` | `10` | TCP connect timeout in seconds |
| `deadline` | `90` | total time for one request attempt (headers + body) |
| `dns_timeout` | `10` | name-resolution timeout in seconds |
| `retries` | `2` | retries for idempotent requests only (never POST submissions) |
| `max_redirects` | `2` | same-host redirects allowed for GET/HEAD |
| `max_body_bytes` | `8388608` | maximum response body size |
| `max_header_bytes` | `131072` | maximum response header size |
| `backoff_base` | `0.4` | initial retry backoff in seconds |
| `backoff_cap` | `8.0` | maximum retry/Retry-After delay in seconds |
| `tls_verify` | `true` | verify the server certificate |
| `tls_trust` | `"chain"` | `chain`, `system` or `both` |
| `tls_pin_sha256` | `[]` | optional SHA-256 leaf fingerprints (colon or plain hex) |
| `allow_plaintext` | `false` | permit `http://` (local test CA only) |
| `allow_sha1` | `false` | accept SHA-1-signed certificates in a chain |

These bounds are what make pyCertWiz safe against malformed or malicious network
peers.  Lowering them is fine on a fast network; raising `retries` above 10 or
`deadline` above an hour is rejected by validation.

`tls_trust = "chain"` uses the `[[chain.certificates]]` anchors for TLS,
`"system"` uses the OS store, `"both"` accepts either. If verification is on and
no trust material exists, pyCertWiz refuses to make a request.

### `[ca.endpoints]`

Override if your deployment differs (paths only; the host comes from
`base_url`):

| Key | Default |
|---|---|
| `csr` | `/CSR` |
| `bulk` | `/CSRs` |
| `lookup` | `/resources/resource/publickey/pk` |
| `certificate` | `/certificate` |
| `revoke` | `/revoke` |
| `ping` | `/pingservice` |
| `info` | `/CA` |
| `motd` | `/CA/motd/text` |

---

## `[identity]`

Defaults used for requests; every field can be overridden on the command line.

| Key | Default | Meaning |
|---|---|---|
| `c` | `"UK"` | country (two letters) |
| `o` | `"eScience"` | organisation |
| `ou` | `"CLRC"` | organisational unit (part of the RA) |
| `l` | `"DL"` | locality (part of the RA) |
| `st` | `""` | optional state/province |
| `email` | `""` | default contact e-mail; also the SAN e-mail for user certificates |
| `ra` | `""` | default RA as `"OU L"`, e.g. `"CLRC DL"` |

List available RAs with `pycert ras`. The RA’s OU and L become part of the
certificate subject.

---

## `[keys]`

| Key | Default | Meaning |
|---|---|---|
| `algorithm` | `"rsa"` | `rsa` or `ec` |
| `rsa_bits` | `3072` | 2048, 3072, 4096 or 8192 |
| `ec_curve` | `"P-256"` | `P-256`, `P-384` or `P-521` |

Note: renewal and host requests authenticate with PPPK, which requires the
**existing** certificate to have an RSA key. An ECDSA certificate can be issued
and used, but cannot be renewed with this server protocol.

---

## `[csr]`

| Key | Default | Meaning |
|---|---|---|
| `hash` | `"sha256"` | CSR signature hash (`sha256`, `sha384`, `sha512`) |
| `extensions` | `["san"]` | extensions to request: `san`, `key_usage`, `extended_key_usage`, `basic_constraints` |
| `pin_hash` | `"sha1"` | PIN hash the RA expects; `sha1` is required by the current server |

The SAN is always built from the request type:

* user certificate → `RFC822Name` of the contact e-mail (plus `--san-email`,
  `--san-dns`, `--san-ip`);
* host certificate → `DNSName` of the common name (plus extras).

The default `extensions = ["san"]` matches CertWizard and the current CA. Set
`extensions = ["san", "key_usage", "extended_key_usage", "basic_constraints"]`
for a CA that honours CSR extensions.

---

## `[p12]`

| Key | Default | Meaning |
|---|---|---|
| `filename_template` | `"{cn}.p12"` | output name; must contain `{cn}` or `{alias}` |
| `friendly_name` | `"{cn}"` | PKCS#12 friendly name |
| `export_dir` | `""` | empty = the request directory; otherwise a directory (created 0700) |
| `include_chain` | `true` | embed the issuer chain |

The passphrase is **not** configured here. It comes from `[secrets]`.

---

## `[paths]`

| Key | Default | Meaning |
|---|---|---|
| `data_dir` | `$PYCERT_DATA_DIR`, `$XDG_DATA_HOME/pycert`, or `~/.local/share/pycert` | where keys, requests and `.p12` files live |

Relative paths in the config (including chain files) resolve against the
configuration file’s directory, not the current working directory.

---

## `[secrets]`

| Key | Default | Meaning |
|---|---|---|
| `backend` | `"auto"` | `auto`, `keychain`, `secret-service`, `keyring`, `file`, `command`, `env`, `prompt` |
| `service` | `"pyCert"` | service name; the profile is appended (`pyCert:default`). It keeps the pre-rename name so existing secrets are found. |
| `account` | `"default"` | account name for the PKCS#12 passphrase |
| `key_account` | `""` | account for the key-at-rest passphrase; empty = reuse `account` |
| `file` | `""` | JSON file for the `file` backend (default `<data_dir>/secrets.json`) |
| `command` | `""` | shell command for the `command` backend |
| `command_timeout` | `15` | timeout for keychain/secret-tool/command calls (seconds) |
| `env_var` | `"PYCERT_P12_PASSPHRASE"` | variable for the `env` backend |

Backends are described in [SECURITY.md](../SECURITY.md). Examples:

```toml
# 1Password CLI
[secrets]
backend = "command"
command = "op read op://Private/UK-eScience/p12-password"

# GNOME Keyring
[secrets]
backend = "secret-service"

# Any platform keyring via the 'keyring' package (pip install 'pyCertWiz[keyring]'):
# macOS Keychain, Secret Service, KWallet, Windows Credential Locker
[secrets]
backend = "keyring"

# CI: read from the environment, never store
[secrets]
backend = "env"
env_var = "PYCERT_P12_PASSPHRASE"
```

Use `pycert secret test` to check the configured backend, `pycert secret set`
to store a passphrase, and `pycert secret get --show` if you must print it.

---

## `[[chain.certificates]]`

The CA chain. Each entry is a file **or** inline PEM, optionally pinned by the
SHA-256 fingerprint of the certificate. The chain is used for TLS trust, path
validation and the exported PKCS#12.

```toml
[[chain.certificates]]
label = "UK e-Science CA 2B"
file = "chain/escience-2b.pem"
sha256 = "b6d140a765d165d8917bb9941f7ab21ff89c04155a4dce52cad345862c3e686e"
# anchor = true   # default; set false to include a certificate without trusting it
```

```toml
# Inline PEM for a fully self-contained configuration
[[chain.certificates]]
label = "internal root"
pem = '''
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
'''
sha256 = "..."
```

* A file may contain several certificates; the pin then applies to each.
* A mismatch is fatal: pyCertWiz refuses to start rather than trust the wrong CA.
* `anchor = false` includes a certificate in the chain (for bundling) without
  making it a trust anchor.
* `pycert init` copies the four bundled UK e-Science CA certificates into
  `chain/` and writes their pins, so the default configuration works out of the
  box.

---

## Complete example

```toml
version = 1
profile = "stfc"

[ca]
base_url = "https://cwiz-live.ca.ngs.ac.uk:443"
version_string = "CertWizard 2.2.1"
user_agent = "pyCertWiz/1.0 (grid team)"
timeout = 30.0
retries = 2
tls_verify = true
tls_trust = "chain"
tls_pin_sha256 = []
allow_plaintext = false
allow_sha1 = false

[identity]
c = "UK"
o = "eScience"
ou = "CLRC"
l = "DL"
email = "grid-ops@example.org"
ra = "CLRC DL"

[keys]
algorithm = "rsa"
rsa_bits = 3072
ec_curve = "P-256"

[csr]
hash = "sha256"
extensions = ["san"]
pin_hash = "sha1"

[p12]
filename_template = "{cn}.p12"
friendly_name = "{cn}"
export_dir = ""
include_chain = true

[paths]
data_dir = "~/.local/share/pycert"

[secrets]
backend = "keychain"
service = "pyCert"
account = "default"
key_account = ""
file = ""
command = ""
env_var = "PYCERT_P12_PASSPHRASE"

[[chain.certificates]]
label = "UK e-Science Root (2007)"
file = "chain/escience-root.pem"
sha256 = "76f3a5942e22012d7e10e11b416fb2eea21d8f4583f2d2fc799bd4ced0210323"

[[chain.certificates]]
label = "UK e-Science CA 2B"
file = "chain/escience-2b.pem"
sha256 = "b6d140a765d165d8917bb9941f7ab21ff89c04155a4dce52cad345862c3e686e"

[[chain.certificates]]
label = "UK e-Science Root 2026"
file = "chain/escience-root-2026.pem"
sha256 = "565c16e7d6ff0f602aefca2a585634c190d7d9da411c7750d79cac6b351ffffa"

[[chain.certificates]]
label = "UK e-Science CA 3B"
file = "chain/escience-3b.pem"
sha256 = "16383860bc6e61488ffb945e961963967c4fe8d73d2b2e9641d0b535cca4b845"
```

---

## CA profiles: `[cas.<name>]`

pyCertWiz manages certificates from several CAs at once. The `[ca]` section above
is the *primary* profile; add more as `[cas.<name>]` tables. Every request
records the profile it belongs to, and `default_ca` chooses the profile for new
requests (`pycert request --ca NAME` overrides it). Manage profiles with
`pycert ca list|show|add-acme|add-ukca|default|remove|eab` or the GUI's
**Settings → Certificate authorities**.

### Another CertWizard-protocol CA (`kind = "ukca"`)

A second UK-CA-compatible service (a test instance, the repository's sandbox, a
future endpoint). It accepts every `[ca]` key, plus its own identity overrides
and chain:

```toml
[cas.sandbox]
kind = "ukca"
display_name = "Local sandbox CA"
base_url = "https://localhost:8443"
tls_trust = "chain"

[cas.sandbox.identity]   # optional; unspecified keys fall back to [identity]
ra = "CLRC DL"

[[cas.sandbox.chain]]
file = "/home/me/.sandbox-ca/root.pem"
sha256 = "…"
```

### An ACME CA (`kind = "acme"`)

RFC 8555 CAs (Let's Encrypt, Sectigo/Jisc with External Account Binding, a
future UK-CA ACME service) issue **host** certificates after validating
control of each name. Full reference: [ACME_CLIENT.md](ACME_CLIENT.md).

```toml
[cas.letsencrypt]
kind = "acme"
display_name = "Let's Encrypt"
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["grid-ops@example.org"]
terms_agreed = true          # after reading the CA's terms of service
challenge = "http-01"        # or "dns-01"
http_mode = "webroot"        # or "standalone"
webroot = "/var/www/html"
# eab_kid = "…"              # EAB key id; the HMAC key goes in the secret store
```

ACME profiles default to `tls_trust = "system"`; all `[ca]` transport keys
(timeouts, pins, `allow_plaintext`…) apply to them too.

### Plugins

Other CA protocols can be added by installing a package that registers a
provider under the `pycert.providers` entry-point group and selecting it with
`kind = "<name>"`. See [PROVIDERS.md](PROVIDERS.md).

---

## Java keystores: `[[keystores]]`

Java PKCS#12 keystores (CertWizard's `cakeystore.pkcs12`) linked as a live
certificate store. Manage them with `pycert keystore link|unlink` rather than
by hand. See [KEYSTORES.md](KEYSTORES.md).

| Key | Default | Meaning |
|---|---|---|
| `name` | (required) | name of the link (lower-case identifier) |
| `path` | (required) | the keystore file |
| `ca` | primary CA | CA profile the keystore's certificates belong to |
| `auto_import` | `true` | import key entries pyCertWiz does not manage yet |
| `write_back` | `true` | write issued and renewed certificates into the keystore |

There is deliberately no passphrase setting. Keystore passphrases are never
stored: pyCertWiz asks for them in each session.

---

## GUI preferences

Appearance, expiry thresholds, the background check interval, automatic
collection of issued certificates and tray notifications are per-user GUI
preferences, not part of this file. They live in the platform's settings store
(`~/Library/Preferences` on macOS, `~/.config/pyCertWiz` on Linux) and are edited
in **Settings → Appearance & monitoring**. Set `PYCERT_GUI_SETTINGS=/path/file.ini`
to keep them in an INI file instead.

---

## Validation rules

`pycert config check` (and every command) enforces:

* `ca.base_url` is a valid `http(s)` URL; plain HTTP requires
  `allow_plaintext = true`;
* `tls_trust` is one of `chain`, `system`, `both`;
* pins are 64 hex digits;
* country code is two characters;
* key algorithm/size/curve and CSR hash are supported;
* PIN hash is `sha1` or `sha256`;
* extensions are known;
* the PKCS#12 filename template contains `{cn}` or `{alias}`;
* the secret backend is known, and `command` is set for the `command` backend;
* every chain entry resolves and matches its pin;
* CA profile names are lower-case identifiers, unique, and `default_ca` names one;
* every `[cas.<name>]` has a known `kind`, valid transport settings and, for
  ACME, a directory URL, a known challenge/mode, a webroot when
  `http_mode = "webroot"`, valid contact addresses and sane timeouts.

## Resource limits

Independent of the network settings, pyCertWiz bounds every untrusted input:

| Input | Limit |
|---|---|
| TOML configuration | 1 MiB; excessive nesting is rejected cleanly |
| Server XML | 4 MiB, depth 100, 100,000 elements |
| Certificate | 1 MiB |
| Certificate bundle | 4 MiB, 200 certificates |
| PEM bundle | 200 blocks |
| Stored state file | 2 MiB |
| PKCS#12 file | 16 MiB, 20 chain certificates |

Problems are fatal (exit 1), warnings are printed and do not stop anything.
