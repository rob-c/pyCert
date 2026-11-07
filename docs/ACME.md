# ACME v2 front-end for the sandbox CA

The sandbox exposes an RFC 8555 (ACME v2) endpoint in front of the same UK
e-Science/OpenCA-style CA state used by the CertWizard listener.  This lets
`certbot` issue, renew and revoke certificates without speaking the UK-CA XML
or PPPK protocols directly.

> For the wider STFC architecture, assurance, policy and migration plan, read
> [`STFC-ACME-MODERNISATION.md`](STFC-ACME-MODERNISATION.md).

> This is a test CA. It issues certificates without real domain or identity
> validation unless you select the HTTP challenge mode. Never trust its CA or
> certificates outside a test environment.

## Start it

```sh
python3 -m sandbox_ca \
  --data-dir .sandbox-ca \
  --port 8443 \
  --acme-port 14000 \
  --acme-challenge-mode auto
```

The sandbox prints both listeners:

```text
URL:              https://localhost:8443
ACME directory:   https://localhost:14000/acme/directory
```

The UK-CA listener remains available at `https://localhost:8443` for the Java
CertWizard client and pyCert.  The ACME listener is separate so either can be
used independently.

| ACME option | Meaning |
|---|---|
| `--acme-port PORT` | start ACME on this TLS port (`0` = free port); omit to disable |
| `--acme-challenge-mode auto\|http\|manual` | validation policy (see below) |
| `--acme-http-port PORT` | port used for `http-01` fetches (default 80) |
| `--acme-public-url URL` | advertised base URL when behind a reverse proxy |

The ACME listener uses the same test TLS certificate as the CA listener, so a
client must trust `--data-dir/root.pem` or use its "skip verification" option.

## ACME ↔ UK-CA mapping

The wrapper deliberately keeps the UK-CA semantics underneath:

| ACME operation | UK-CA operation |
|---|---|
| new-order identifiers | order/authz records; expected DNS SANs |
| finalize CSR | a CA CSR record is created and signed |
| CA auto-sign | order becomes `valid`; certificate id is the CA cert id |
| CA manual mode | order stays `processing`; an admin signs the CA record; the next order poll becomes `valid` |
| certificate download | CA leaf + issuing CA PEM chain |
| revoke-cert | CA certificate record status becomes `REVOKED` |
| account contact | e-mail stored on the CA CSR record |

The CA record is created with `kind="host"` when the order has DNS names, so
the leaf receives the host/serverAuth profile and the requested SANs.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/acme/directory` | service directory and meta |
| GET/HEAD | `/acme/new-nonce` | fresh `Replay-Nonce` |
| POST | `/acme/new-account` | create/find account (JWS with `jwk`) |
| POST | `/acme/new-order` | create order for DNS identifiers |
| GET/POST | `/acme/order/<id>` | order status (POST-as-GET) |
| GET/POST | `/acme/authz/<id>` | authorization and challenges |
| GET/POST | `/acme/chall/<id>` | challenge status; POST starts validation |
| POST | `/acme/finalize/<id>` | submit base64url DER CSR |
| GET/POST | `/acme/cert/<id>` | PEM leaf + issuing CA chain |
| POST | `/acme/revoke-cert` | revoke by certificate DER/PEM |
| POST | `/acme/key-change` | unsupported (501 problem) |
| GET | `/acme/terms` | sandbox terms text |

All POSTs use JWS (`application/jose+json`).  Supported account signature
algorithms are `RS256`/`RS384`/`RS512`, `ES256`/`ES384`/`ES512` and `EdDSA`.
Nonces are one-shot and expire after ten minutes.  `new-account` uses a JWK;
later requests use the account `kid`.  A `badNonce` response includes a fresh
`Replay-Nonce`.

The challenge response includes the RFC 8555 `Link: <authz>;rel="up"` header;
certbot requires this.

## Challenge modes

### `auto` (default, easiest for a local sandbox)

A POST to the challenge marks it valid immediately.  No HTTP server is needed.
Certbot still performs its normal challenge/authorization exchange, but the
sandbox does not fetch a token.

### `http`

The sandbox fetches:

```text
http://<identifier>[:<acme-http-port>]/.well-known/acme-challenge/<token>
```

and compares the body with `<token>.<account-key-thumbprint>`.  This works with
certbot standalone (`--http-01-port`) and with nginx webroot.  Use a resolvable
test domain or a hosts entry pointing at the listener host.

### `manual`

POSTing a challenge leaves it `pending` until an operator validates it through
the ACME object API.  It is useful when integrating a custom DNS/validation
driver.  The ordinary sandbox CLI does not provide a browser button for this.

Wildcard orders use `dns-01`; in `auto` mode this validates immediately.  The
`http` mode does not pretend to validate DNS.

## certbot

A complete local run (certbot installed separately):

```sh
python3 -m sandbox_ca \
  --data-dir .sandbox-ca \
  --port 8443 \
  --acme-port 14000 \
  --acme-challenge-mode auto

certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  -m test@example.org \
  --server https://localhost:14000/acme/directory \
  --no-verify-ssl \
  --http-01-port 18080 \
  -d sandbox.example
```

The full chain is written under certbot's live directory.  For a more
realistic HTTP validation use `--acme-challenge-mode http` and a domain that
resolves to the machine running certbot:

```sh
certbot certonly --standalone \
  --server https://localhost:14000/acme/directory \
  --no-verify-ssl --http-01-port 18080 \
  -d localhost
```

`--no-verify-ssl` is only because the sandbox has a private test CA.  To verify
the TLS endpoint instead, point certbot's Python requests stack at the sandbox
root:

```sh
REQUESTS_CA_BUNDLE="$PWD/.sandbox-ca/root.pem" \
certbot certonly --standalone \
  --server https://localhost:14000/acme/directory \
  -d sandbox.example
```

Certbot renewal and revocation work with the same server URL:

```sh
certbot renew --cert-name sandbox.example --server https://localhost:14000/acme/directory --no-verify-ssl
certbot revoke --cert-path /etc/letsencrypt/live/sandbox.example/fullchain.pem \
  --server https://localhost:14000/acme/directory --no-verify-ssl --reason keycompromise
```

## nginx

nginx is not itself an ACME client; use certbot (or another ACME client) to
obtain the certificate and let nginx serve it:

```nginx
server {
    listen 443 ssl;
    server_name sandbox.example;

    ssl_certificate     /etc/letsencrypt/live/sandbox.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sandbox.example/privkey.pem;

    # Optional: make the test CA explicit in diagnostics.
    # ssl_trusted_certificate /path/to/.sandbox-ca/ca-chain.pem;
}
```

For webroot validation instead of standalone, use
[`sandbox_ca/nginx-sandbox.conf.example`](../sandbox_ca/nginx-sandbox.conf.example):

```nginx
server {
    listen 80;
    server_name sandbox.example;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type text/plain;
    }
}
```

```sh
certbot certonly --webroot -w /var/www/html \
  --server https://localhost:14000/acme/directory \
  --no-verify-ssl \
  -d sandbox.example
```

The sandbox must be able to resolve `sandbox.example` to the nginx host and
must run with `--acme-challenge-mode http` (and a matching
`--acme-http-port` if nginx is not on port 80).

After issuance, `nginx -s reload` reloads the certificate.  Browsers and
clients will still warn about the private sandbox CA until its root is
installed as trusted.

## Limits

- No external account binding (EAB), ARI, profiles, or key-change.
- ACME accounts/orders/nonces are in memory; the CA hierarchy, CSR queue and
  certificates are persisted by the sandbox's normal `state.json`.
- `dns-01` only auto-validates in `auto` mode; there is no DNS provider hook.
- No OCSP, CRL, CAA checking, or rate limiting.
- Revocation removes the certificate's CA status; it does not publish a CRL.
- The ACME endpoint is a local test service: do not expose it to the Internet
  without an explicit reverse proxy, authentication boundary and firewall.

## Implementation

`sandbox_ca/acme.py` contains the protocol state machine and the TLS listener;
`sandbox_ca/server.py` starts it through `SandboxCA.start_acme()`.  The tests
are split between `tests/test_acme_emulation.py` (lifecycle and edge cases),
`tests/test_acme_matrix.py` (a large routing/JWS/identifier/order matrix) and
`tests/test_acme_certbot.py` (optional real-certbot integration).
