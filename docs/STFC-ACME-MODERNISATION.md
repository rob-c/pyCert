# Moving the UK e-Science CA to ACME v2

### An implementation, assurance and migration dossier for STFC

**Audience:** STFC CA operators, service owners, security/assurance staff,
RA administrators, platform/network teams, and application owners who currently
use CertWizard or the UK e-Science CA.

**Status:** architectural proposal plus a working reference implementation and
test harness. The sandbox CA is not a production CA; the recommended production
changes are called out explicitly.

**Companion documents**

- [`CA_LISTENER.md`](CA_LISTENER.md) — the existing UK-CA/CertWizard listener
  contract.
- [`ACME.md`](ACME.md) — the reference ACME v2 endpoint and certbot/nginx
  instructions.
- [`../sandbox_ca/`](../sandbox_ca/) — runnable reference implementation.
- [`../tests/test_acme_emulation.py`](../tests/test_acme_emulation.py),
  [`../tests/test_acme_matrix.py`](../tests/test_acme_matrix.py) and
  [`../tests/test_acme_deep_matrix.py`](../tests/test_acme_deep_matrix.py) —
  the 2,000+ ACME/CA emulation cases and the wider conformance suite.

---

## 0. The short version

The UK e-Science CA still speaks a private, reverse-engineered XML protocol to a
single Java desktop client. That protocol works, but it puts certificate
automation in a 2005-shaped client instead of in the operating system and web
server tooling that everyone else uses.

ACME v2 (RFC 8555) is the interoperable answer: `certbot`, `acme.sh`,
`cert-manager`, Caddy, Traefik, lego and nginx integrations already speak it.
The UK CA does not need to throw away its CA core, its RA model, its trust
anchors or its IGTF profile to adopt it. It needs a **carefully governed ACME
façade** in front of the existing CA, with a migration path to a native ACME
service.

This dossier sets out:

1. what the current listener actually does;
2. what an ACME v2 listener must do, in normative terms;
3. how to map ACME accounts/orders/challenges onto the existing CA, RA and
   certificate policy;
4. the security, assurance, operations and audit work that must accompany it;
5. an incremental migration plan that does not break CertWizard users;
6. the test evidence already in this repository (7,396 tests at the time of
   writing, including 3,000+ ACME/CA-emulation cases and a real certbot test);
7. concrete certbot/nginx configurations that can be used for a pilot.

The blunt recommendation: **stop making certificate automation require a
desktop Java application.** Put a standards-based ACME endpoint in front of the
CA, keep RA policy authoritative, and let the operating system do certificate
renewal.

---

## 1. Where we are: the current UK-CA protocol

The UK e-Science CA is an X.509 CA with an OpenCA-derived REST interface. Its
public client is CertWizard. There is no comprehensive public API specification;
the contract has been reconstructed from the Java client, live observations and
golden wire fixtures.

### 1.1 Current endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/pingservice` | liveness |
| GET | `/CA` | CA certificates, RA list, preferred RA, policy |
| GET | `/CA/motd/text` | message of the day XML |
| POST | `/CSR` | new user CSR |
| POST | `/CSRs` | host CSR, and legacy renewal |
| POST | `/CSR` with PPPK | current renewal |
| POST | `/resources/resource/publickey/pk` | status lookup by base64 SPKI |
| GET | `/certificate/<id>` | issued leaf certificate |
| POST | `/revoke` | revocation with PPPK |

### 1.2 What the protocol requires

- HTTPS with a JKS truststore built from four pinned CA resources (Root 2007,
  CA 2B, Root 2026, CA 3B in the current client).
- HTTP/1.1, XML bodies, `Content-Length` **or** chunked request framing.
- Headers including `LocalHost`, `Date`, `Accept: */*`,
  `Content-Type: application/xml; charset=UTF-8`, `PPPK`, and on host requests
  `serial`.
- A PIN represented as a 40-character upper-case SHA-1 hash.
- PPPK authentication for host/renew/revoke: RSA challenge with
  `realm`, `nonce`, `keyid` and `response`; an `opaque` cookie alternative is
  supported by the Java client for renewal and revocation.
- Status lookup by `SubjectPublicKeyInfo` rather than by a CSR/order id.
- An OpenCA error document whose **second** `<text>` element is the useful
  message for Java renewal/host/revocation failures.
- A certificate profile with user/host EKUs, SANs and a chain that validates
  against the bundled CA anchors.

All of that is now documented in [`CA_LISTENER.md`](CA_LISTENER.md) and covered
by the Java/pyCert wire-parity suite.

### 1.3 The operational pain

The current model creates avoidable friction:

- **Desktop dependency.** Certificate renewal means opening a Java GUI, finding
  a keystore, clicking a status check and exporting a PKCS#12 file.
- **No server-native lifecycle.** nginx, Apache, HAProxy and Kubernetes cannot
  ask the CA for a certificate. A human or a bespoke wrapper has to bridge the
  gap.
- **Manual RA steps.** Approval and signing are separate operational actions
  with no standard machine-readable workflow.
- **Weak automation story.** There is no standard renewal schedule, no standard
  challenge type, no standard certificate URL, and no standard account model.
- **Knowledge concentration.** The protocol is undocumented outside the client
  source; every integration is bespoke.
- **Security drift.** Passwords, PIN hashes and PKCS#12 files move through
  desktop flows instead of short-lived, auditable service credentials.
- **No ecosystem.** Every modern CA and public cloud offers ACME; users expect
  `certbot` to work.

---

## 2. What “modern” means: ACME v2

ACME is an IETF standard for automating certificate issuance and renewal. The
core specification is **RFC 8555**. It defines:

- a **directory** describing service endpoints;
- **accounts** identified by a key pair;
- **orders** for one or more identifiers;
- **authorizations** and **challenges** proving control of a name;
- a **finalize** step carrying a PKCS#10 CSR;
- certificate download, revocation, nonce handling and problem documents.

Relevant extensions and related standards:

| Standard | Relevance |
|---|---|
| RFC 8555 | ACME v2 core |
| RFC 7515 / 7517 / 7638 | JWS, JWK and JWK thumbprints |
| RFC 7807 | Problem Details for HTTP APIs |
| RFC 8737 | TLS-ALPN-01 challenge |
| RFC 8738 | IP identifiers |
| RFC 9773 | ACME Renewal Information (ARI) |
| RFC 8659 | CAA |
| RFC 5280 | X.509 certificate and CRL profile |
| RFC 6960 | OCSP |
| RFC 6962 | Certificate Transparency |
| RFC 8555 §7.3.4 | External Account Binding (EAB) |
| CA/Browser Forum BRs | Publicly trusted TLS certificate profile (where applicable) |
| IGTF APs / GFD.125 | Grid/classic and MICS profiles for the existing trust community |

ACME is not a CA policy. It is a transport and workflow protocol. The CA still
decides **who may request what**, **which identifiers are acceptable**, **what
certificate profile is issued**, **how long it lives**, and **when it is
revoked**. That distinction is essential for STFC assurance.

### 2.1 What clients expect

A conforming client such as certbot will:

1. fetch the directory;
2. obtain a fresh nonce;
3. create/reuse an account (JWS signed with the account key);
4. create an order for DNS identifiers;
5. fetch authorizations and choose a challenge;
6. provision the HTTP token or DNS TXT record;
7. ask the server to validate;
8. poll until the order is `ready`;
9. POST a CSR to `finalize`;
10. download the PEM chain;
11. install it and reload the service;
12. renew before expiry, ideally using ARI (RFC 9773).

If any of those steps is non-standard, the client ecosystem will not work.
“Mostly ACME” is not useful to operations teams.

---

## 3. Target state

### 3.1 Recommended architecture

```
       certbot / acme.sh / cert-manager / Caddy / Traefik
                              |
                    HTTPS + JWS (RFC 8555)
                              |
                 +------------v-------------+
                 |      ACME façade         |
                 |  accounts, orders, authz |
                 |  challenges, nonces      |
                 |  policy/EAB/rate limits  |
                 +------------+-------------+
                              |
                 +------------v-------------+
                 |  UK-CA adapter / CA API  |
                 |  CSR, RA, signing, ids   |
                 +------------+-------------+
                              |
                 +------------v-------------+
                 |  Existing CA core / HSM  |
                 |  IGTF profile, CRLs, OCSP|
                 +--------------------------+
```

The façade can be deployed as a separate service while the CA core remains
unchanged. This is the lowest-risk route to a useful service and is exactly what
the `sandbox_ca` reference implements.

### 3.2 Why a façade first

- It can be delivered without changing the CA signing machinery or HSM
  integration.
- It can run alongside CertWizard and the existing REST endpoints.
- It can enforce EAB/institutional authorization and rate limits independently.
- It can be tested against real certbot before any CA policy changes.
- It can be replaced later by a native ACME implementation without changing
  clients.

### 3.3 What not to do

- Do not make ACME a thin unauthenticated wrapper around `/CSR`. That would let
  anyone with network access obtain certificates for any name.
- Do not bolt ACME onto the desktop client. ACME belongs on the server.
- Do not expose the sandbox CA or its test anchors to production.
- Do not implement a subset that only works with one client and call it
  “ACME support”.
- Do not automate away RA accountability for profiles where identity proofing
  is required.

---

## 4. Normative CA server behaviour

This section is the contract a production implementation should meet. It is
split into the legacy listener (for compatibility) and the ACME endpoint.

### 4.1 Legacy UK-CA listener: MUST/SHOULD

| ID | Requirement | Level |
|---|---|---|
| L1 | HTTPS only; TLS certificate chains to the configured trust anchors | MUST |
| L2 | Accept HTTP/1.1 requests with `Content-Length` or chunked bodies | MUST |
| L3 | Accept the CertWizard headers (`LocalHost`, `Date`, `PPPK`, `serial`) case-insensitively | MUST |
| L4 | `GET /pingservice` returns 200 | MUST |
| L5 | `GET /CA` returns RA list and latest client version | MUST |
| L6 | `GET /CA/motd/text` returns XML with `/CA/Motd/text` | MUST |
| L7 | `POST /CSR` accepts user CSR XML and returns 201 or a 202 `<error>` | MUST |
| L8 | `POST /CSRs` accepts host XML with PPPK and `serial` | MUST |
| L9 | Renewal is accepted on `/CSR` with PPPK; `/CSRs` remains a legacy alias | MUST |
| L10 | PPPK challenge verifies RSA recovery, nonce and timestamp window | MUST |
| L11 | Status lookup returns 404 for unknown keys and 200 with certificate/CSR blocks | MUST |
| L12 | Certificate download returns `<certificate><X509Certificate>` PEM | MUST |
| L13 | Revocation accepts PPPK and returns 201 | MUST |
| L14 | 202 errors use `<error><status><major><text>…</text></major><minor><text>…</text></minor></status></error>` | MUST |
| L15 | Status dates are `dd/MM/yyyy`; statuses include NEW/APPROVED/VALID/REVOKED | MUST |
| L16 | The listener does not retry or duplicate a submission on its own | SHOULD |
| L17 | Every response is bounded in size and rejects XML entities/DOCTYPE | SHOULD |
| L18 | Required headers/body are logged without private keys, PINs or passphrases | MUST |

Full details: [`CA_LISTENER.md`](CA_LISTENER.md). The 1,000-case legacy
listener emulation matrix is `tests/test_ca_server_matrix.py`.

#### 4.1.1 Requirement traceability

| Requirements | Primary test evidence |
|---|---|
| L1–L6 | `tests/test_ca_server_matrix.py` CA info/liveness/header matrix; `tests/test_sandbox_java.py` |
| L7–L10 | `tests/test_ca_server_matrix.py` CSR and PPPK matrices |
| L11–L15 | `tests/test_ca_server_matrix.py` status/download/revoke and response-shape matrices |
| L16–L18 | `tests/test_transport.py`, `tests/test_e2e_listener_faults.py`, `tests/test_e2e_security.py` |
| A1–A6 | `tests/test_acme_emulation.py`, `tests/test_acme_deep_matrix.py` |
| A7–A11 | `tests/test_acme_matrix.py`, `tests/test_acme_deep_matrix.py` |
| A12–A16 | `tests/test_acme_emulation.py` (bad CSR, orderNotReady, revocation) |
| A18 (durability) | `tests/test_acme_eab_persistence.py`; sandbox persists ACME state to `acme-state.json` |
| A19 (EAB) | `tests/test_acme_eab_persistence.py`; production still needs institutional onboarding/assurance |
| A20 (production) | roadmap/assurance gate; not claimed by the sandbox |

The matrix is evidence for the reference behaviour, not a substitute for a
production conformance programme. A production service must still run the
independent RFC/client/security gates in section 10.2.

### 4.2 ACME endpoint: MUST/SHOULD

| ID | Requirement | Level |
|---|---|---|
| A1 | HTTPS with a client-trusted endpoint certificate | MUST |
| A2 | `GET /directory` returns `newNonce`, `newAccount`, `newOrder`, `revokeCert`, `keyChange`, `meta` | MUST |
| A3 | Every response carries a fresh `Replay-Nonce`; nonces are single-use and expire | MUST |
| A4 | JWS supports at least RS256 and ES256; algorithm/key type must match | MUST |
| A5 | `new-account` accepts a JWK and returns 201 with `Location`; existing keys return 200 | MUST |
| A6 | Subsequent requests use the account `kid`; unknown kids return `accountDoesNotExist` | MUST |
| A7 | `new-order` accepts DNS identifiers and returns 201, `Location`, authz URLs and finalize URL | MUST |
| A8 | Authorizations expose at least `http-01`; wildcard orders use `dns-01` | MUST |
| A9 | Challenge POST validates and returns `Link: <authz>;rel="up"` | MUST |
| A10 | Order states are `pending`, `ready`, `processing`, `valid`, `invalid` | MUST |
| A11 | Finalize accepts base64url DER CSR; CSR SANs must equal order identifiers | MUST |
| A12 | Finalize is rejected with `orderNotReady` before all authz are valid | MUST |
| A13 | Certificate download returns a PEM leaf + issuer chain | MUST |
| A14 | Revocation accepts a DER or PEM certificate and returns 200 | MUST |
| A15 | Errors use `application/problem+json` and the ACME error namespace | MUST |
| A16 | Account/order/authz resources enforce account ownership | MUST |
| A17 | Private account keys never leave the client; the server stores only JWK/public metadata | MUST |
| A18 | Nonce and account state is durable across restarts | SHOULD |
| A19 | EAB is supported for institutional account authorization | SHOULD (production MUST) |
| A20 | ARI, CAA checks, rate limits, audit and metrics are production requirements | SHOULD/PRODUCTION MUST |

The reference implementation in `sandbox_ca/acme.py` implements A1–A19, plus
ARI is a documented roadmap item rather than a sandbox feature. Production
hardening still requires durable HA storage, HSM-backed signing, rate limits,
CAA, CRL/OCSP, monitoring and independent conformance testing. Test evidence:
`tests/test_acme_emulation.py`, `tests/test_acme_matrix.py`,
`tests/test_acme_deep_matrix.py` and `tests/test_acme_certbot.py`.

### 4.3 Mapping ACME to the UK CA

| ACME | Legacy CA |
|---|---|
| account key / contact | client identity + contact e-mail; EAB/policy authorizes the account |
| order identifiers | DNS SANs expected in the CSR |
| authorization | policy decision: auto-approved host cert, or RA approval |
| challenge | proof of control; does not replace identity proofing where policy requires it |
| finalize CSR | `CSRRecord` in the CA queue |
| `auto` CA mode | immediate signing for a lab/pilot |
| manual CA mode | order stays `processing` until RA/CA signs |
| certificate URL | CA certificate id |
| revoke | CA certificate status → REVOKED |

The façade must not accept a CSR whose SANs differ from the order. It must not
accept a certificate id belonging to another account. It must not let a
challenge validation status be forged by a client request.

---

## 5. Certificate policy and profiles

ACME adoption does not remove the need for a certificate policy. STFC should
publish/refresh the CP/CPS and state explicitly:

- which certificate types are available through ACME (recommended initial
  scope: TLS server/host certificates and internal service certificates);
- whether **user/identity certificates** remain RA/portal-only;
- subject DN and SAN rules;
- key algorithms and minimum sizes (RSA ≥ 2048, ECDSA P-256/P-384);
- validity periods and maximum lifetimes;
- EKU/keyUsage and basicConstraints;
- SAN wildcard policy;
- revocation reasons and CRL/OCSP publication;
- audit, retention and incident response;
- IGTF/classic/MICS applicability and any profile differences;
- trust-anchor distribution and endpoint TLS certificate requirements;
- Subscriber Agreement and privacy notice.

A sensible pilot profile:

```
Subject: CN=<primary DNS name>, O=..., OU=..., C=GB
SANs: exactly the order identifiers (no silent extra names)
BasicConstraints: CA=false
KeyUsage: digitalSignature, keyEncipherment (RSA)
EKU: serverAuth (and clientAuth only if explicitly required)
Validity: 90 days initially; evaluate 30–90 days for automation
AIA: issuer URL; CRLDP: CRL URL
Serial: unique, positive, unpredictable
```

Important: the existing sandbox CA issues 365-day certificates and uses the
test hierarchy. Production policy should not copy those values blindly merely
because the emulator does.

### 5.1 Revocation is not optional

ACME clients expect revocation to be meaningful. At minimum:

- revocation by the account that ordered the certificate or by an authorized
  CA/RA operator;
- reason-code mapping;
- a published CRL and/or OCSP responder;
- an audit record of who revoked what and why;
- a documented compromise process (including CA key compromise, which is not
  an ACME client concern but must be in the CP/CPS).

---

## 6. Security architecture

### 6.1 Trust boundaries

1. **Client to ACME endpoint:** TLS; the endpoint certificate must be trusted
   by the client. A private CA endpoint certificate can be used only if clients
   are configured to trust it.
2. **ACME service to CA/HSM:** mutually authenticated, least-privilege service
   identity; no human CA operator credentials embedded in the ACME process.
3. **ACME service to policy/EAB:** institutional identity provider or signed
   EAB credentials.
4. **CA to CRL/OCSP/publication:** signed artifacts and monitored distribution.

### 6.2 Threats and controls

| Threat | Control |
|---|---|
| Unauthorized certificate issuance | EAB, account allowlists, RA policy, rate limits, approval workflows |
| Account key theft | short-lived accounts where possible, revocation, audit, HSM-backed service keys, monitoring |
| Nonce replay | one-time nonce store, expiry, atomic consume |
| JWS algorithm confusion | explicit alg/key allowlist; reject `none`; verify signature over exact protected+payload |
| SSRF through HTTP-01 | block private/link-local/metadata ranges except explicit lab allowlists, validate redirects, short timeouts, no arbitrary ports |
| DNS rebinding | resolve and connect with pinning, or use a controlled resolver/egress |
| Wildcard abuse | DNS-01 only, EAB/policy approval, stricter rate limits |
| CSR/order substitution | compare CSR SANs and public key to order; never trust client-supplied ids |
| Cross-account access | per-object account ownership checks |
| Replay of finalize/cert requests | nonce + order state machine; certificate URL tied to order |
| Audit gaps | structured logs, request ids, account/order/cert correlation, retention |
| Endpoint compromise | separate service, minimal secrets, HSM, network policy, monitoring, rapid key rotation |
| CA key compromise | CP/CPS incident plan, trust-anchor rollover, CRL/OCSP, communications |

### 6.3 What the sandbox deliberately does not prove

The sandbox uses a test CA and auto-validation. It now persists
accounts/orders/challenges in `acme-state.json` and supports EAB, but that is
still local JSON, not a production HA database. It is excellent for protocol
and interoperability testing; it is **not** a production security boundary.
Production still needs HSM-backed signing, durable HA state, rate limits, CAA,
OCSP/CRL, monitoring and a security review.

---

## 7. Operations and data model

A production ACME service needs durable state. A minimal schema:

### 7.1 Tables

| Table | Key fields |
|---|---|
| `acme_accounts` | id, jwk, thumbprint, contact, status, created_at, eab_id |
| `acme_orders` | id, account_id, status, expires, identifiers, certificate_id, error |
| `acme_authorizations` | id, order_id, identifier, wildcard, status, expires |
| `acme_challenges` | id, authz_id, type, token, status, validated_at, error |
| `acme_nonces` | nonce_hash, expires_at, used_at (or a fast expiring store) |
| `acme_certificates` | cert_id, account_id, order_id, serial, status, issued_at |
| `acme_audit` | event_id, time, account, order, action, source, result |
| `ca_requests` | existing CA CSR/approval/signing records |

Indexes: account thumbprint, order account, authz order, challenge authz,
certificate serial, nonce expiry.

### 7.2 HA and consistency

- Nonces must be consumed atomically; use a shared store or sticky sessions.
- Account/order state must be transactional with CA request creation.
- A finalize must be idempotent for a given account/order/CSR (return the same
  order/certificate rather than issuing duplicates).
- Use a database with point-in-time recovery; back up CA request/cert records
  independently of the signing keys.
- Time synchronization is security-critical for nonce and PPPK timestamps.
- Separate signing/HSM from the public ACME web tier.

### 7.3 Monitoring

Track at least:

- directory/API availability and latency;
- new-account, new-order, challenge, finalize and certificate rates;
- validation success/failure by challenge type;
- certificate issuance/revocation counts;
- badNonce, unauthorized, accountDoesNotExist and rate-limit rates;
- queue age for manual RA approval;
- certificate expiry/renewal lead time (ARI where available);
- CRL/OCSP publication freshness;
- audit log delivery failures.

Alert on spikes in failures, unexpected account creation, certificate issuance
for sensitive domains, stale CRLs and HSM errors.

---

## 8. Client integration

### 8.1 certbot

The reference sandbox has been tested with real certbot 5.9.0:

```sh
certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  -m test@example.org \
  --server https://acme.example.ac.uk/acme/directory \
  --http-01-port 80 \
  -d host.example.ac.uk
```

For the local sandbox:

```sh
python3 -m sandbox_ca \
  --data-dir .sandbox-ca \
  --port 8443 \
  --acme-port 14000 \
  --acme-challenge-mode auto

certbot certonly --standalone --non-interactive --agree-tos \
  -m test@example.org \
  --server https://localhost:14000/acme/directory \
  --no-verify-ssl \
  --http-01-port 18080 \
  -d sandbox.example
```

Production should use a publicly/IGTF-trusted endpoint certificate, not
`--no-verify-ssl`. For an internal trust anchor, configure the client's trust
store explicitly (for certbot/Python requests, `REQUESTS_CA_BUNDLE` is one
option, but a platform-wide trust configuration is better).

### 8.2 nginx

nginx is not itself an ACME client. Use certbot (or another ACME client) to
obtain the certificate, then nginx serves it:

```nginx
server {
    listen 443 ssl;
    server_name host.example.ac.uk;

    ssl_certificate     /etc/letsencrypt/live/host.example.ac.uk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/host.example.ac.uk/privkey.pem;
}
```

For webroot validation, nginx serves:

```nginx
location ^~ /.well-known/acme-challenge/ {
    root /var/www/html;
    default_type text/plain;
}
```

```sh
certbot certonly --webroot -w /var/www/html \
  --server https://acme.example.ac.uk/acme/directory \
  -d host.example.ac.uk
```

The ACME service must be able to reach the webroot over HTTP (port 80 or a
documented validation port). A reverse proxy must preserve `/.well-known/`
paths and must not rewrite challenge tokens.

### 8.3 Other clients

ACME v2 is supported by `acme.sh`, cert-manager, Caddy, Traefik and lego.
For cert-manager, an `Issuer`/`ClusterIssuer` points at the directory URL and
uses a Kubernetes Secret for the account key; EAB credentials should be stored
in a Secret and rotated. Caddy and Traefik can obtain certificates directly but
need the endpoint trusted by their container/host trust store.

### 8.4 Existing CertWizard and pyCert users

Do not switch off the legacy listener on day one. Run both:

- CertWizard/pyCert continue to use `/CSR`, `/CSRs`, `/revoke`;
- ACME clients use `/acme/*`;
- both feed the same CA queue and certificate store;
- issue a compatibility matrix and deprecation date;
- provide a migration guide with example certbot/nginx commands.

The reference repository already has a Java-vs-pyCert wire-parity suite and a
headless Java `SandboxFlow`; use it to prove that the legacy path remains
unchanged during the ACME rollout.

---

## 9. Migration roadmap

### Phase 0 — inventory and policy (2–4 weeks)

- Inventory all CertWizard users, hostnames, certificates, keystores and
  renewal dates.
- Classify certificate types: user, host/TLS, service, wildcard, internal.
- Decide ACME scope and RA policy; update CP/CPS and Subscriber Agreement.
- Choose production ACME architecture (façade vs native) and EAB model.
- Define endpoint DNS name, TLS certificate and network exposure.

### Phase 1 — ACME façade pilot (6–10 weeks)

- Deploy a non-production façade against a test CA.
- Implement directory, nonces, JWS accounts, orders, http-01/dns-01,
  finalize, certificate and revocation (the reference implementation is a
  starting point, not production).
- Add EAB and account-to-RA authorization.
- Add durable state, audit logging, rate limits and metrics.
- Run certbot, acme.sh and cert-manager interoperability tests.
- Run the 2,000+ ACME/CA emulation suite and the legacy parity suite.
- Publish a pilot guide; recruit 3–5 service owners.

### Phase 2 — production hardening (6–12 weeks)

- HSM-backed signing; separate ACME web tier and CA signing service.
- Database HA, backups, disaster recovery, incident response.
- CAA checks, CRL/OCSP publication, ARI (RFC 9773) if supported.
- Security review, penetration test, SSRF/redirect/challenge abuse tests.
- Load/scale test; establish SLOs and on-call.
- EAB onboarding and account lifecycle.

### Phase 3 — migration (1–2 quarters)

- Onboard host/TLS certificates by cohort.
- certbot/nginx/cert-manager templates and automated renewal.
- Keep legacy endpoints; monitor use; communicate deprecation.
- Migrate RA approval where possible; keep identity-proofing exceptions.
- Publish dashboards and monthly migration reports.

### Phase 4 — modernisation (ongoing)

- Native ACME or façade consolidation.
- Short-lived certificates and ARI-driven renewal.
- Automated revocation/incident response.
- Retire CertWizard desktop dependency where policy allows.
- Contribute profile/CA documentation to IGTF and the wider community.

---

## 10. Test and conformance strategy

### 10.1 Current evidence in this repository

- **7,396 tests** in the full suite.
- **3,000+ ACME/CA-emulation cases**, including:
  - routing/method matrix;
  - JWS envelope and algorithm rejection;
  - DNS identifier validation;
  - order creation and state transitions;
  - CSR/order SAN matching;
  - HTTP-01 body/path validation;
  - nonce lifecycle and concurrency;
  - problem documents;
  - CA manual signing and wildcard orders;
  - EAB HMAC/account-key binding and ACME-state restart/persistence.
- **1,000 legacy-listener cases** in `tests/test_ca_server_matrix.py`:
  - CSR XML/PIN/email/version validation;
  - PPPK host, renewal and revocation challenges;
  - status lookup, download and revocation modes;
  - CA info/MOTD/health/header/response-shape matrices.
- **Real certbot 5.9.0** obtain and revoke test (`tests/test_acme_certbot.py`).
- Legacy Java/CertWizard vs pyCert wire-parity tests.
- Python 3.6 compatibility and lint checks.

### 10.2 Production conformance gates

A production ACME service should additionally pass:

1. **RFC 8555 conformance** against an independent test harness (Pebble or
   equivalent), including POST-as-GET, badNonce, account reuse and order state.
2. **Client matrix:** certbot (standalone + webroot), acme.sh, cert-manager,
   Caddy, Traefik and lego.
3. **Challenge negative tests:** wrong token, redirect, private IP, SSRF,
   DNS rebinding, wildcard, IPv6.
4. **Security tests:** JWS alg confusion, key substitution, cross-account
   access, replay, nonce exhaustion, rate limits.
5. **Durability tests:** restart, failover, database loss, clock skew.
6. **Operational tests:** CRL/OCSP freshness, audit delivery, certificate
   renewal/reload, emergency revocation.
7. **Policy tests:** EAB identity mapping, unauthorized names, approval bypass,
   certificate profile constraints.

### 10.3 Acceptance criteria for the pilot

- certbot can obtain, renew and revoke a certificate non-interactively;
- nginx serves the issued chain and reloads on renewal;
- no cross-account access is possible;
- every issuance and revocation is auditable;
- legacy CertWizard flows remain green;
- p95 API latency and availability meet agreed SLOs;
- rollback to the legacy path is exercised.

---

## 11. Risks and decisions

| Risk | Mitigation |
|---|---|
| ACME bypasses RA identity proofing | EAB + policy; scope ACME to host/service certs initially |
| SSRF via HTTP-01 | egress allowlists, private-IP blocking, redirect limits, controlled resolver |
| Account key theft | EAB, account revocation, monitoring, short-lived service credentials |
| Nonce/state loss in HA | shared atomic nonce store, sticky sessions or transactional DB |
| CA/HSM integration complexity | façade first; signing service API with least privilege |
| Client trust of private CA endpoint | public/IGTF-trusted endpoint cert; documented trust bundle for internal clients |
| Legacy client regression | dual stack, wire-parity suite, deprecation window |
| Scope creep (ARI, profiles, EAB) | phase; publish supported/unsupported matrix |
| Operational ownership unclear | name service owner, on-call, SLAs before pilot |

**Decisions required from STFC**

1. Is ACME initially for host/TLS certificates only, or also user certs?
2. What is the EAB/identity source and who approves accounts?
3. Which CA profile(s) and lifetimes are issued via ACME?
4. Where is ACME state stored and who operates it?
5. What is the public endpoint name and TLS trust model?
6. What is the deprecation date for desktop-only issuance?

Without answers to these, an ACME pilot will become an unowned science project.

---

## 12. Appendix A — ACME request flow

```text
Client                          ACME server                     CA/RA
  | GET /directory                   |                             |
  |--------------------------------->|                             |
  |<---------------------------------| endpoints + nonce           |
  | POST /new-account (JWS/JWK)      |                             |
  |--------------------------------->| account + kid               |
  | POST /new-order (JWS/kid)        |                             |
  |--------------------------------->| order/authz/challenges      |
  | POST /authz/<id> (POST-as-GET)   |                             |
  |--------------------------------->| challenge token             |
  | provision http token / DNS TXT   |                             |
  | POST /chall/<id> (JWS)           |                             |
  |--------------------------------->| validate challenge          |
  |<---------------------------------| challenge + Link up         |
  | POST /order/<id> (poll)          |                             |
  |--------------------------------->| ready                       |
  | POST /finalize/<id> (CSR)        |                             |
  |--------------------------------->| create CA request --------->|
  |                                  |<--------- approve/sign -----|
  |<---------------------------------| valid + certificate URL     |
  | GET/POST /cert/<id>              |                             |
  |--------------------------------->| leaf + issuer PEM           |
  |<---------------------------------|                             |
  | install + reload                 |                             |
```

## 13. Appendix B — Error taxonomy

| ACME type suffix | Typical HTTP | Meaning |
|---|---|---|
| `malformed` | 400 | bad JSON/JWS/request shape |
| `badNonce` | 400 | nonce missing/expired/reused |
| `unauthorized` | 403 | signature/ownership/authorization failure |
| `accountDoesNotExist` | 400 | unknown `kid` |
| `orderNotReady` | 403 | finalize before all authz valid |
| `badCSR` | 400 | CSR parse/signature/SAN mismatch |
| `badPublicKey` | 400 | unsupported/malformed JWK |
| `badSignatureAlgorithm` | 400 | alg/key mismatch |
| `unsupportedIdentifier` | 400 | non-DNS identifier |
| `rejectedIdentifier` | 400 | policy-invalid identifier |
| `serverInternal` | 500 | server fault |

Problem bodies must use `application/problem+json`, include a fresh
`Replay-Nonce`, and never leak private keys, tokens or account secrets.

## 14. Appendix C — Configuration checklist

- [ ] ACME endpoint hostname and publicly trusted TLS certificate
- [ ] DNS/reverse proxy preserves `/.well-known/acme-challenge/`
- [ ] Port 80/443 reachability documented
- [ ] Nonce store with atomic consume and expiry
- [ ] Account/EAB policy and approval owner
- [ ] CA queue/RA integration and manual-sign fallback
- [ ] CSR SAN ↔ order identifier validation
- [ ] Rate limits per account/IP/domain
- [ ] CAA checking and audit
- [ ] CRL/OCSP publication and monitoring
- [ ] ARI support/roadmap
- [ ] Audit log retention and SIEM integration
- [ ] HSM/key custody and separation of duties
- [ ] Backups, DR, clock synchronization
- [ ] Client matrix and rollback plan
- [ ] Legacy CertWizard compatibility window
- [ ] Documentation and support runbook

## 15. Appendix D — Glossary

| Term | Meaning |
|---|---|
| ACME | Automated Certificate Management Environment, RFC 8555 |
| ARI | ACME Renewal Information, RFC 9773 |
| CSR | PKCS#10 certificate signing request |
| EAB | External Account Binding, binds an ACME account to an institution |
| JWS | JSON Web Signature, RFC 7515 |
| JWK | JSON Web Key, RFC 7517 |
| PKCS#12 | container for key + certificate chain |
| PPPK | the legacy UK-CA public-key challenge |
| RA | Registration Authority |
| SAN | Subject Alternative Name |
| SPKI | Subject Public Key Info |
| TLS-ALPN-01 | ACME challenge over TLS, RFC 8737 |

## 16. Appendix E — Reproduce the reference evidence

```sh
# Full test suite
.venv/bin/pytest -q

# ACME/CA emulation matrices (>1,000 cases)
.venv/bin/pytest -q tests/test_acme_emulation.py tests/test_acme_matrix.py tests/test_acme_deep_matrix.py

# Legacy listener emulation matrix (1,000 cases)
.venv/bin/pytest -q tests/test_ca_server_matrix.py

# Optional real certbot
CERTBOT_BIN=/path/to/certbot .venv/bin/pytest -q tests/test_acme_certbot.py

# Start the sandbox with ACME
python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443 \
  --acme-port 14000 --acme-challenge-mode auto
```

The sandbox is deliberately small enough to review, but it demonstrates the
protocol, the CA mapping and the certbot/nginx path. It is the starting point
for a production design, not the production design itself.

---

# Part II — STFC implementation blueprint

This part turns the architectural case into an executable programme. It is
written for the people who will actually deliver, assure, operate and migrate
the service. It is deliberately opinionated; change the decisions through the
ADR process if STFC chooses a different route.

## 17. Work breakdown and delivery sequence

### 17.1 Workstreams

| Workstream | Owner | Outcome |
|---|---|---|
| WS1 Policy and assurance | CA manager + assurance | Updated CP/CPS, Subscriber Agreement, profile and EAB policy |
| WS2 ACME service | Platform/service owner | RFC 8555 endpoint with directory, accounts, orders, challenges, finalize, cert, revoke |
| WS3 CA integration | CA operations | Durable CSR/approval/signing adapter and certificate lookup/download |
| WS4 Identity and EAB | Security/identity | Institutional account onboarding, key custody, rotation and revocation |
| WS5 Operations | SRE/operations | HA, monitoring, backup, DR, runbooks, on-call |
| WS6 Clients and migration | Service owners | certbot/nginx/cert-manager integration and cohort migration |
| WS7 Security and conformance | Security + test | Threat model, pen test, interop and conformance gates |
| WS8 Documentation and training | Service owner | Staff guides, FAQ, training, support model |

### 17.2 Epics and acceptance criteria

| Epic | Scope | Acceptance |
|---|---|---|
| E1 Directory and nonce | `/directory`, `/new-nonce`, nonce store | RFC shape; single-use nonce; expiry; HA-safe |
| E2 Accounts and EAB | JWK/JWS, account lifecycle, EAB | New/existing account; EAB HMAC; deactivation; audit |
| E3 Orders | identifiers, authz, challenges, state machine | DNS/IP identifiers; pending→ready→processing→valid/invalid |
| E4 Challenges | HTTP-01, DNS-01, TLS-ALPN-01 where in scope | Positive/negative tests; SSRF/DNS-rebinding controls |
| E5 Finalize and certificate | CSR validation, CA adapter, PEM chain | SAN equality; CA signing; account ownership; idempotency |
| E6 Revocation and publication | revoke-cert, CRL/OCSP | Authorized revocation; freshness SLO; audit |
| E7 Durability | database, nonce store, restart/failover | RPO/RTO met; no nonce reuse; order recovery |
| E8 Operations | metrics, logs, alerts, DR, capacity | Dashboards; runbooks; load/DR tests |
| E9 Client enablement | certbot/acme.sh/cert-manager/nginx | Documented, tested, supported matrix |
| E10 Migration | inventory, pilots, cohorts, decommission | All host/TLS certs migrated or exceptioned |

### 17.3 Indicative sequence

```text
Phase 0  Policy, inventory, EAB model, endpoint/trust decision
Phase 1  ACME core + CA adapter + certbot/nginx pilot
Phase 2  HA database, HSM, EAB onboarding, monitoring, security review
Phase 3  Cohort migration, training, dual-run legacy + ACME
Phase 4  ARI/short lifetimes, native consolidation, retire desktop dependency
```

Do not start Phase 3 before the Phase 1 client matrix and the Phase 2 security
and durability gates pass.

## 18. Reference service architecture

```
                       Internet / campus network
                                  |
                         TLS ingress / WAF
                                  |
                 +----------------v----------------+
                 |  ACME API (stateless)           |
                 |  JWS, nonce consume, policy     |
                 +------+------------------+-------+
                        |                  |
             +----------v----+     +-------v--------+
             |  ACME state DB |     | nonce store    |
             |  accounts      |     | (Redis/DB)     |
             |  orders/authz  |     +----------------+
             |  challenges    |
             +----------+-----+
                        |
             +----------v------------------+
             |  CA adapter / signing queue |
             |  CSR, approval, status      |
             +----------+------------------+
                        |
             +----------v------------------+
             |  CA core + HSM             |
             +----------+------------------+
                        |
             +----------v------------------+
             | CRL/OCSP publisher         |
             +-----------------------------+
```

### 18.1 Component responsibilities

- **Ingress:** TLS termination, request limits, WAF/rate limits, access logs.
- **ACME API:** stateless workers; all state in DB; no account/order state on
  local disk.
- **Nonce store:** atomic consume, short TTL, HA; never reuse a nonce.
- **State DB:** transactional account/order/authz/challenge/cert mapping.
- **CA adapter:** the only component allowed to submit CSR/approval/signing
  requests; least-privilege service identity.
- **CA core/HSM:** existing signing custody; no public exposure.
- **Publisher:** CRL/OCSP/ARI metadata; monitored freshness.

### 18.2 Availability model

- At least two ACME API instances behind a load balancer.
- Shared nonce store and database; no sticky-session dependency.
- CA signing is an asynchronous or short-RPC dependency; ACME returns
  `processing` if signing is not immediate.
- Backpressure: bounded queues, explicit 503/`serverInternal` with retry
  guidance, not unbounded memory.
- Rolling upgrades preserve nonce and order state.

## 19. Data model (production-ready)

Use PostgreSQL (or an equivalent transactional DB) rather than local JSON.
The reference sandbox uses JSON only for reviewability.

```sql
CREATE TABLE acme_accounts (
    id              text PRIMARY KEY,
    jwk             jsonb NOT NULL,
    thumbprint      text NOT NULL UNIQUE,
    contact         jsonb NOT NULL DEFAULT '[]',
    status          text NOT NULL DEFAULT 'valid', -- valid|deactivated|revoked
    eab_kid         text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    deactivated_at  timestamptz
);

CREATE TABLE acme_orders (
    id              text PRIMARY KEY,
    account_id      text NOT NULL REFERENCES acme_accounts(id),
    status          text NOT NULL,
    identifiers     jsonb NOT NULL,
    expires_at      timestamptz NOT NULL,
    certificate_id  bigint,
    error           jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE acme_authorizations (
    id              text PRIMARY KEY,
    order_id        text NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    identifier      jsonb NOT NULL,
    wildcard        boolean NOT NULL DEFAULT false,
    status          text NOT NULL,
    expires_at      timestamptz NOT NULL
);

CREATE TABLE acme_challenges (
    id              text PRIMARY KEY,
    authz_id        text NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
    type            text NOT NULL,
    token           text NOT NULL,
    status          text NOT NULL,
    validated_at    timestamptz,
    error           jsonb
);

CREATE TABLE acme_nonces (
    nonce_hash      bytea PRIMARY KEY,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz
);

CREATE TABLE acme_certificates (
    id              bigint PRIMARY KEY,
    account_id      text NOT NULL REFERENCES acme_accounts(id),
    order_id        text NOT NULL REFERENCES acme_orders(id),
    serial          numeric NOT NULL,
    status          text NOT NULL,
    issued_at       timestamptz NOT NULL,
    revoked_at      timestamptz
);

CREATE TABLE acme_audit (
    event_id        bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    account_id      text,
    order_id        text,
    certificate_id  bigint,
    action          text NOT NULL,
    source_ip       inet,
    result          text NOT NULL,
    detail          jsonb
);

CREATE INDEX ON acme_orders(account_id, created_at);
CREATE INDEX ON acme_authorizations(order_id);
CREATE INDEX ON acme_challenges(authz_id);
CREATE INDEX ON acme_certificates(account_id);
CREATE INDEX ON acme_nonces(expires_at);
```

Nonces may live in Redis with `SET NX`/Lua compare-and-delete semantics. The
database rows must be the source of truth for issuance and audit.

## 20. EAB onboarding and account lifecycle

EAB binds an ACME account key to an institution. It is not a password and must
not be emailed in clear text.

### 20.1 Onboarding flow

1. Service owner requests ACME access with service name, owner, hostnames,
   environment and certificate profile.
2. RA/security validates the request against policy (host ownership, IGTF
   applicability, data classification).
3. CA operator creates an EAB credential (`kid` + random HMAC key) and records
   the mapping in the account register.
4. Secret is delivered through an approved secret channel (vault/one-time
   link), not a ticket comment.
5. Client registers with `--eab-kid`/`--eab-hmac-key`; the server records the
   EAB kid against the account.
6. Rotation: issue a new EAB kid/key, re-register or create a new account,
   revoke the old account, update automation, record dates.
7. Offboarding: deactivate account, revoke certificates if required, remove
   DNS/challenge access and archive audit records.

### 20.2 Account policy

- One account per service/team, not one per host, unless isolation requires it.
- Account key material is generated on the client and stored in the platform
  secret store; it is never sent to the CA.
- EAB keys are scoped to an environment (test/staging/prod).
- Account deactivation is a first-class operation and must be auditable.
- Alert on account creation for protected domains and on unexpected EAB kids.

## 21. Certificate profile matrix

| Profile | Use | Key | Validity | SANs | EKU | Publication |
|---|---|---|---|---|---|---|
| `tls-server` | Public/campus HTTPS | RSA ≥2048 or P-256 | 90 days pilot | exact order DNS names | serverAuth | CRL + OCSP/AIA |
| `tls-server-wildcard` | Wildcard HTTPS | RSA ≥2048 or P-256 | 90 days | `*.example` | serverAuth | CRL + OCSP |
| `internal-service` | Internal mTLS/API | RSA/EC | 90 days | DNS/IP as approved | serverAuth + clientAuth | CRL |
| `user-identity` | Human grid identity | existing CA policy | existing | email/DN | clientAuth/emailProtection | existing; **not initial ACME scope** |
| `host-grid` | Grid host cert | existing IGTF | existing policy | DNS | serverAuth/clientAuth per IGTF | existing |

Do not silently widen SANs, EKUs or lifetimes in the name of automation. The
ACME order must be constrained by an authorisation policy, not merely by the
CSR the client sends.

## 22. Capacity and service levels

### 22.1 Planning assumptions (replace with measured STFC data)

- 10,000 active host certificates, 90-day lifetime → ~111 renewals/day average;
  plan for 10× burst during incidents or coordinated renewals.
- 100 new orders/minute peak for a 30-minute window.
- 5–20 API requests per order (challenge/poll/finalize/download).
- Nonce traffic can be several times order traffic; size the nonce store
  accordingly.

### 22.2 Suggested SLOs for the pilot

| SLO | Target |
|---|---|
| Directory/API availability | 99.9% monthly (pilot may be lower) |
| p95 new-order latency | < 500 ms excluding CA signing |
| p95 finalize-to-certificate | < 30 s in auto mode; < 2 business days manual |
| Certificate download availability | 99.9% |
| CRL freshness | within published CRL interval |
| RPO for ACME state | ≤ 5 minutes |
| RTO for ACME API | ≤ 30 minutes |
| Audit log delivery | ≥ 99.9%, retained per policy |

Measure and publish queue age for manual approval; it is the usual source of
“ACME is broken” reports.

## 23. Security control mapping

| Control area | Implementation | Evidence |
|---|---|---|
| Governance | CP/CPS, RACI, change board | approved documents |
| Asset management | account/order/cert register | DB + audit |
| Access control | EAB, service identities, least privilege | IAM logs |
| Cryptography | HSM, algorithm allowlist, key rotation | HSM audit, config |
| Logging/monitoring | structured logs, SIEM, alerts | dashboards, retention |
| Incident response | runbooks, revocation, CA compromise plan | exercises |
| Supplier/HSM | procurement, firmware, dual control | vendor assurance |
| Secure development | code review, dependency scanning, fuzzing | CI records |
| Network | egress controls, WAF, private-IP blocks | firewall/proxy config |
| Privacy | contact data minimisation, retention | privacy notice |

Map these to NCSC CAF, ISO/IEC 27001 Annex A and IGTF requirements in the
assurance artefacts; the table is an index, not a substitute for the mapping.

## 24. Operational runbooks

### 24.1 ACME API returning 5xx

1. Confirm database and nonce-store health.
2. Check CA adapter health and signing queue.
3. Stop retries at the ingress if the fault is persistent; return a clear
   problem document and preserve nonce/order state.
4. Fail over to a healthy worker; do not delete state.
5. Communicate with client owners; publish an incident note.

### 24.2 Signing queue backed up

1. Check HSM/CA availability and operator approval backlog.
2. Increase manual signing capacity or enable the approved auto-sign policy.
3. Orders remain `processing`; clients must poll, not resubmit blindly.
4. Alert if queue age exceeds the SLO.

### 24.3 Suspected account compromise

1. Deactivate the ACME account and revoke its certificates per policy.
2. Rotate/revoke EAB credentials.
3. Preserve audit logs and source IPs.
4. Notify security and certificate owners; follow the CP/CPS incident plan.

### 24.4 CRL/OCSP delay

1. Check publisher health and signing key access.
2. Publish the previous valid CRL until a new one is signed; never serve an
   unsigned/stale artefact without an explicit incident decision.
3. Notify relying parties and record the deviation.

### 24.5 Nonce store outage

1. Fail closed for new POSTs; do not accept unverified/replayed nonces.
2. Keep GET directory/terms available if safe.
3. Restore the store; clients will retry with fresh nonces.
4. Investigate whether any nonce was reused.

## 25. Migration cohorts

| Cohort | Scope | Prerequisites |
|---|---|---|
| Pilot | 3–5 services, non-critical hostnames | EAB, certbot/nginx guide, rollback |
| Wave 1 | Low-risk internal HTTPS | monitoring, support desk, profile approval |
| Wave 2 | Campus/public HTTPS | CAA/CRL/OCSP, load test, security review |
| Wave 3 | High-value services | change board, DR exercise, per-service runbook |
| Exception | user/identity certs or legacy-only clients | documented exception and owner |

Track for every certificate: owner, hostnames, issuer, profile, expiry, ACME
account/EAB kid, client/tool, renewal timer, last successful renewal and
rollback contact.

## 26. First 30 / 60 / 90 days

### Days 0–30

- appoint service owner and technical lead;
- inventory CertWizard users/certificates;
- decide ACME scope, EAB model and endpoint name;
- stand up the reference sandbox and run certbot/nginx pilot;
- draft CP/CPS changes and assurance questions.

### Days 31–60

- implement/deploy database, nonce store and EAB onboarding;
- integrate CA adapter and HSM signing;
- run certbot/acme.sh/cert-manager matrix;
- complete threat model and SSRF/redirect tests;
- publish pilot guide and support rota.

### Days 61–90

- security review and load/DR exercise;
- onboard pilot cohort;
- establish SLO dashboards and audit reports;
- decide go/no-go for Wave 1;
- publish legacy deprecation principles (not necessarily a date).

## 27. RACI (minimum)

| Activity | CA manager | Platform | Security | RA | Service owners |
|---|---|---|---|---|---|
| CP/CPS and profiles | A | C | C | C | I |
| ACME service operation | A | R | C | I | I |
| EAB issuance | A | C | C | R | I |
| Certificate approval policy | A | I | C | R | C |
| Client integration | I | C | I | I | R |
| Incident/revocation | A | R | C | R | C |
| Migration cohort | A | C | I | C | R |

A = accountable, R = responsible, C = consulted, I = informed.

## 28. Decision log (ADRs)

| ADR | Decision | Rationale |
|---|---|---|
| ADR-001 | ACME façade before native CA rewrite | lowest risk, fastest client value |
| ADR-002 | Host/TLS certificates first; user certs remain RA/portal | preserves identity proofing |
| ADR-003 | EAB required for production accounts | institutional authorization, not open enrollment |
| ADR-004 | Durable DB + shared nonce store, not local files | HA and replay safety |
| ADR-005 | CA signing remains in HSM-backed CA core | custody and separation of duties |
| ADR-006 | Private endpoint certificate for internal pilot; public/IGTF endpoint for production | client trust practicality |
| ADR-007 | ARI after basic issuance | renewal-load benefits need stable issuance first |
| ADR-008 | Keep legacy listener during migration | no flag-day break for CertWizard users |

## 29. Procurement / vendor questions

- Does the ACME server support RFC 8555, EAB and ARI? Which versions?
- Where are account/order/nonce keys stored; can they use our HSM/KMS?
- What is the HA topology and RPO/RTO?
- How are nonces consumed atomically across regions?
- What challenge types and SSRF controls are implemented?
- How are CRL/OCSP/CT published and monitored?
- What audit fields and retention are available?
- Can it issue IGTF/classic/MICS profiles?
- What is the upgrade/rollback and vulnerability response process?
- Is source available for review, or is there an escrow/exit plan?

## 30. Final recommendation

STFC does not need to choose between “keep CertWizard forever” and “replace the
CA in a big bang”. The low-risk path is:

1. publish the policy and stop pretending the desktop client is the only
   supported interface;
2. put a governed ACME façade in front of the existing CA;
3. require EAB and keep RA policy authoritative;
4. run certbot/nginx on a pilot, then migrate host certificates by cohort;
5. harden durability, HSM, monitoring, CRL/OCSP and ARI before declaring the
   service production;
6. keep the legacy endpoints until every user has a migration path.

The reference implementation and 7,396-test evidence in this repository are a
starting point, not a production certificate authority. The next step is an
STFC-owned service design with named owners, an approved policy and a funded
operations model.
