# Using ACME CAs with pyCertWiz

pyCertWiz's primary CA is the UK e-Science CA, which uses the CertWizard protocol.
It can also obtain **host certificates** from any **ACME (RFC 8555)** CA:

- Let's Encrypt (staging and production);
- commercial or academic ACME services that require **External Account
  Binding** (EAB), such as Sectigo's ACME service used by the Jisc certificate
  service;
- a future UK-CA ACME endpoint;
- the ACME sandbox in this repository (`python3 -m sandbox_ca --acme-port ...`).

ACME certificates are managed exactly like UK-CA ones. They appear in
`pycert list` and in the GUI, and they can be renewed (`pycert renew`, or
automatically with `pycert renew --due`), revoked, exported to PKCS#12 and
deployed. Only the conversation with the CA is different: ACME proves control
of each DNS name with a **challenge** instead of an RA PIN.

ACME issues host (server) certificates only. Personal certificates, IP address
SANs and e-mail SANs are refused before any key is generated.

The client is implemented natively on pyCertWiz's hardened HTTPS transport. It
uses `cryptography` for the JSON Web Signatures and adds no extra
dependencies. Deadlines, response-size limits, TLS pinning and cancellation
work exactly as they do for the UK-CA.

---

## Quick start: Let's Encrypt staging

```console
$ pycert ca add-acme le-staging \
    --directory https://acme-staging-v02.api.letsencrypt.org/directory \
    --display-name "Let's Encrypt (staging)" \
    --contact you@example.org \
    --webroot /var/www/html
$ # read the terms of service, then:
$ pycert config set cas.le-staging.terms_agreed=true
$ pycert request www.example.org --type host --ca le-staging --wait
```

The first request generates an account key, registers the account and places
the order. It then answers the challenges, finalizes with a freshly generated
key and CSR, and downloads, verifies and stores the certificate. To issue for
real, repeat with the production directory
`https://acme-v02.api.letsencrypt.org/directory`.

---

## Configuration reference

An ACME CA is an extra CA profile in `pycert.toml`:

```toml
default_ca = "uk-escience"          # new requests still go to the UK-CA by default

[cas.letsencrypt]
kind = "acme"
display_name = "Let's Encrypt"
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["hostmaster@example.ac.uk"]
terms_agreed = true
account_key = "ec"                  # ec (P-256, ES256) or rsa (3072-bit, RS256)
challenge = "http-01"               # http-01 or dns-01
http_mode = "webroot"               # standalone or webroot
webroot = "/var/www/html"
```

| Key | Default | Meaning |
|---|---|---|
| `kind` | — | must be `"acme"` |
| `directory` | — (required) | the ACME directory URL |
| `display_name` | profile name | name shown in listings and the GUI |
| `contact` | `[identity].email` | account contact e-mail addresses (sent as `mailto:` URIs) |
| `terms_agreed` | `false` | must be `true` before an account can be registered. pyCertWiz shows the CA's terms URL when it refuses. |
| `eab_kid` | `""` | External Account Binding key identifier from the CA |
| `eab_hmac_env` | `""` | name of an environment variable that holds the EAB HMAC key. If unset, the secret store is used. |
| `account_key` | `"ec"` | algorithm of a newly generated account key; an existing key is kept |
| `challenge` | `"http-01"` | `http-01` or `dns-01`. Wildcard names always use `dns-01`. |
| `http_mode` | `"standalone"` | `standalone`: pyCertWiz listens briefly on `http_port`. `webroot`: pyCertWiz writes token files under `webroot`. |
| `http_port` | `80` | standalone listener port (the CA always connects to port 80; forward it if you listen elsewhere) |
| `http_bind` | `""` | standalone bind address (empty = all interfaces) |
| `webroot` | `""` | document root served at `http://<name>/` (required for `webroot` mode) |
| `dns_hook` | `""` | command that publishes and removes dns-01 TXT records; empty = manual |
| `dns_propagation_seconds` | `0` | wait after publishing TXT records |
| `validation_timeout` | `300` | how long to wait for validation and issuance steps (seconds) |
| `poll_interval` | `2` | seconds between authorization/order polls (`Retry-After` is honoured) |

The transport and TLS keys from `[ca]` also apply: `tls_trust` (default
`"system"` for ACME profiles), `tls_pin_sha256`, `timeout`, `connect_timeout`,
`deadline`, `retries`, `user_agent`, and so on. For a private ACME CA, set
`tls_trust = "chain"` and list its CA certificates under
`[[cas.<name>.chain]]`, exactly as for the primary CA's `[chain]`. Those
certificates are then trusted both for TLS and for validating issued chains.

Settings can be changed with `pycert config set`, for example
`pycert config set cas.letsencrypt.http_port=8080`.

---

## External Account Binding (Sectigo / Jisc and similar)

CAs that tie ACME accounts to an existing customer account issue an **EAB key
id** and an **HMAC key** (base64url). The HMAC key is a secret, so it is never
written to `pycert.toml`:

```console
$ pycert ca add-acme sectigo \
    --directory https://acme.sectigo.com/v2/OV \
    --display-name "Sectigo OV (Jisc)" \
    --contact hostmaster@example.ac.uk \
    --webroot /var/www/html
$ pycert config set cas.sectigo.terms_agreed=true
$ pycert ca eab sectigo --kid 'kid-from-the-portal'
HMAC key (input hidden): ****
```

`pycert ca eab` stores the key in the configured secret backend (the macOS
Keychain, Secret Service, a 0600 file, ...) under the account
`acme-eab:<profile>`. For unattended hosts, set `eab_hmac_env` and supply the
key in that environment variable instead.

The EAB key is only used once, when the account is registered. If the
directory advertises `externalAccountRequired` and no EAB is configured,
pyCertWiz refuses with instructions rather than sending a doomed request.

---

## Challenges

### http-01, webroot

The best choice when a web server already answers on port 80 for the name.
pyCertWiz writes `<webroot>/.well-known/acme-challenge/<token>` (mode 0644) for
each name in the order, asks the CA to validate, then removes the files and
any directories it created. Tokens are checked against the base64url alphabet
before use, so a hostile CA cannot write outside the challenge directory.

### http-01, standalone

When nothing listens on port 80, pyCertWiz runs a tiny HTTP listener for the
duration of the validation only. It serves nothing but this order's tokens
(everything else is a 404), and it is always shut down afterwards, including
on errors and cancellation. Binding port 80 needs privileges: run pyCertWiz with
them, give Python `CAP_NET_BIND_SERVICE`, or forward port 80 to a high
`http_port`. If the port is in use, pyCertWiz says so and suggests webroot mode.

### dns-01 with a hook

Needed for wildcard names, and for hosts that are not reachable from the
Internet. The hook is any executable. It is run without a shell, as:

```text
<dns_hook...> add    <domain> <record-name> <value>
<dns_hook...> remove <domain> <record-name> <value>
```

For example:

```text
dns_hook add host.example.org _acme-challenge.host.example.org 0Ln2...Q8
```

- `domain` is the name being validated; a wildcard keeps its `*.` prefix.
- `record-name` is the TXT record to create (`_acme-challenge.<name>`, with
  any `*.` removed). A wildcard and its base name share one record name with
  two different values, so the hook must **add** values, not replace them.
- `value` is the TXT record content: base64url(SHA-256(key authorization)).
- Exit 0 on success. Any other exit status aborts the order and the hook's
  stderr is shown. `remove` runs after validation even when it failed.
- Each call has a 120-second timeout. Set `dns_propagation_seconds` if your
  DNS needs time to propagate before the CA looks.

```toml
[cas.letsencrypt]
challenge = "dns-01"
dns_hook = "/usr/local/libexec/pycert-dns-hook --zone example.org"
dns_propagation_seconds = 30
```

### dns-01 by hand

With `challenge = "dns-01"` and no `dns_hook`, an interactive front-end shows
the TXT records to create and waits for you to confirm. In the GUI this is a
dialog; at a terminal it is a prompt. Unattended runs such as
`pycert renew --due` from cron cannot do this and fail with a message
explaining that a `dns_hook` is needed.

---

## Accounts and keys

| File | Contents |
|---|---|
| `<data_dir>/acme/<profile>/account.pem` | the account private key, PKCS#8 encrypted with pyCertWiz's saved secret, mode 0600 |
| `<data_dir>/acme/<profile>/account.json` | account URL, directory URL, contact, key algorithm, creation time (no secrets), mode 0600 |

- One account is registered per CA profile and reused for every order.
- If the directory URL changes, pyCertWiz registers again with the same key.
- If the CA has forgotten the account, the next request registers it again
  automatically.
- To start over with a new account, delete the profile's `acme/<profile>`
  directory.

Each request still gets its own freshly generated certificate key. The account
key only signs ACME messages.

---

## Lifecycle

| pyCertWiz action | ACME operation |
|---|---|
| `pycert request HOST --type host --ca NAME` | new-order for the CN plus any `--san-dns` names, challenges, finalize |
| `pycert wait` / `status --refresh` / `watch` | POST-as-GET the order. If it is valid, download the chain. If it is still `pending` or `ready` (e.g. after a crash), validation and finalisation are resumed. |
| `pycert renew` / `renew --due` | a new order with a new key for the certificate's DNS names. The old certificate stays in place until the new one is verified. |
| `pycert revoke ALIAS --reason R` | revoke-cert signed by the account key. Reasons: `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`. |

The certificate is accepted only if its public key matches the request's key,
it is currently valid, and its chain verifies against the profile's trust
anchors. The intermediates the CA sends are used as hints for building that
chain. An order the CA marks `invalid` fails the request with the CA's
explanation.

The CSR always lists the common name among its DNS names, because ACME CAs and
TLS clients require it. pyCertWiz adds it automatically if you only give extra
`--san-dns` names.

---

## The sandbox ACME server

The repository's sandbox CA can expose an ACME front-end for local testing:

```console
$ python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443 \
    --acme-port 14000 --acme-challenge-mode auto
```

```toml
[cas.sandbox-acme]
kind = "acme"
display_name = "Sandbox ACME"
directory = "https://localhost:14000/acme/directory"
contact = ["test@example.org"]
terms_agreed = true
tls_trust = "chain"

[[cas.sandbox-acme.chain]]
file = "/path/to/.sandbox-ca/root.pem"
```

In `auto` mode the sandbox accepts every challenge, so no web server or DNS is
needed. `--acme-challenge-mode http` really fetches the http-01 token, and
`--acme-eab-kid`/`--acme-eab-hmac-key` exercise EAB. The pyCertWiz test suite
(`tests/test_provider_acme.py`) runs every flow above against this server.

---

## Security notes

- Network access goes through pyCertWiz's hardened transport: TLS 1.2+, the
  profile's trust anchors and optional leaf pin, bounded response sizes,
  deadlines, and no redirects to plaintext. Signed POSTs are never retried
  blindly. Only `badNonce` (with a fresh nonce) and an explicit `Retry-After`
  on 429/503 are retried, at most three times.
- Problem documents are reported with their ACME type and detail, truncated.
- Private keys, the EAB HMAC key and the saved passphrase are never logged or
  shown. TXT record values and http-01 tokens are public by design.
- The standalone listener serves only this order's tokens and exists only
  while the CA is validating.
- The hook runs without a shell, with fixed arguments, from the trusted
  configuration file. Keep `pycert.toml` writable only by its owner.
