# The CA listener: expected behaviour and API

This document defines the server behaviour that the Java **CertWizard** client
(UK e-Science CA client, version 2.2.1 / the current `develop` branch) expects
from its HTTPS **CA listener**, and describes the runnable sandbox
implementation in [`sandbox_ca/`](../sandbox_ca/) for testing the real Java
client without touching the production CA.

The authoritative sources for this description are the Java client itself
(`OnlineUserCertRequest`, `OnlineHostCertRequest`, `OnlineCertRenewRequest`,
`ResourcesPublicKey`, `CertificateDownload`, `RevokeRequest`, `CAInfo`,
`CAMotd`, `PingService`, `CaHttpClient`), its golden wire fixtures under
`src/test/resources/golden/`, and observation of the live service. Where the
Java client has a quirk, the quirk is part of the contract.

> **Sandbox warning.** `sandbox_ca` is a test double. It uses a throw-away CA,
> issues certificates to anyone who can reach it, and has no RA identity
> checks. Bind it to loopback, keep the generated admin token, and never use its
> CA or certificates for anything real.

## 1. Roles and topology

```
 CertWizard (Java, GUI)                         CA listener (HTTPS)
 ─────────────────────                         ───────────────────
 truststore built from bundled CA PEMs  ──────▶ TLS server certificate
   (four resources, each SHA-256 pinned)          chains to a pinned CA
 config URLs in configure.properties   ──────▶ /pingservice, /CA, /CSR, ...
 user/host CSR + PPPK authentication   ──────▶ RA approval workflow
 status lookup by public key           ◀─────▶ NEW / APPROVED / VALID / ...
 certificate download by id            ◀─────▶ PEM leaf certificate
```

The listener is not just an HTTP API: the Java client also validates the TLS
server certificate against a truststore built from **bundled, pinned** CA
certificates. A listener with a self-signed certificate (or a certificate from
a different CA) is rejected before any HTTP request is made. The sandbox
therefore provides a patcher that replaces the bundled CA material *and* the
pins inside the client.

## 2. Transport and TLS contract

| Item | Requirement |
|---|---|
| Scheme | HTTPS only. The client's `java.net.http.HttpClient` is created with the JVM default `SSLContext`. |
| TLS versions | TLS 1.2 or 1.3 (whatever the JVM enables). The server certificate must be valid for the hostname in the configured URL. |
| Trust | The client builds `$dataDir/truststore.jks` from the four classpath resources `/escience-root.pem`, `/escience-2b.pem`, `/escience-root-2026.pem`, `/escience-3b.pem`. Every resource is checked against a hard-coded SHA-256 pin in `BundledCaCertificates`. |
| Server chain | Send the leaf **and** the issuing CA certificate. The root is a trust anchor and need not be sent. |
| HTTP version | HTTP/1.1. `java.net.http` may use keep-alive; a `Connection: close` response is accepted. |
| Redirects | Not followed. Every endpoint must answer directly. |
| Request body framing | Accept both `Content-Length` and `Transfer-Encoding: chunked`. The current Java client uses a byte-array publisher (normally `Content-Length`), while older Restlet-based builds and the golden fixtures use chunked. Proxies may choose either. |
| Response body framing | `Content-Length` or chunked. Bodies are XML unless stated otherwise. |
| Timeouts | The client has connect and whole-request timeouts (defaults 10 s and 30 s). The listener should answer well inside those. |
| Header names | HTTP header names are case-insensitive, but the client sends specific cases (`LocalHost`, `PPPK`, `serial`, `keyid`, `realm`, `response`, `opaque`). Do not rely on a framework rewriting them; do not require a particular case. |
| Host header | The normal HTTP `Host` header is present, including a non-default port for the sandbox. |

The client's default proxy selector is used. In a sandbox, make sure
`http.proxyHost`/`https.proxyHost` and friends are not set to a proxy that
cannot reach the listener.

### 2.1 Headers the client sends

Every request:

```
Accept: */*
User-Agent: NGS-CertWizard/2.2.0
LocalHost: <canonical local hostname, or empty>
Date: <RFC 1123 date>
```

`LocalHost` can be an empty header value (the golden fixture
`null-localhost.1.http` covers this). The listener must not treat it as a
required value.

Requests with an XML body also send:

```
Content-Type: application/xml; charset=UTF-8
```

PPPK-authenticated requests send `PPPK: this is pppk` on both the challenge
and response requests, plus the challenge headers on the second request.

### 2.2 Configuration keys

The Java client reads these keys from its bundled `configure.properties`:

| Key | Default path | Used for |
|---|---|---|
| `uk.ngs.ca.request.csr.url` | `/CSR` | new **user** CSR, and **renewal** (`OnlineCertRenewRequest`) |
| `uk.ngs.ca.request.bulkhost.reqid.url` | `/CSRs` | host (bulk) CSR |
| `uk.ngs.ca.request.ca.url` | `/CA` | RA list and latest-version check |
| `uk.ngs.ca.request.ca.motd.text.url` | `/CA/motd/text` | message of the day |
| `uk.ngs.ca.request.resource.publickey` | `/resources/resource/publickey` | status lookup; the client appends `/pk` |
| `uk.ngs.ca.request.certificate.url` | `/certificate` | certificate download; the client appends `/<id>` |
| `uk.ngs.ca.request.revoke.url` | `/revoke` | revocation |
| `uk.ngs.ca.request.pingservice.url` | `/pingservice` | liveness |
| `ngsca.issuer.dn` | semicolon-separated RFC 2253 DNs | only certificates whose issuer DN is in this list get online status checks |
| `ngsca.cert.truststore.password` | `passwd` | truststore password |

**Renewal endpoint change:** current Java renewals go to `/CSR` (the same
resource as user requests) with the `PPPK` header. Older clients used `/CSRs`.
A listener that supports both is compatible with old and new clients; the
sandbox dispatches `/CSR` on the presence of `PPPK`. The renewal XML contains
a `<PublicKey>` element, which distinguishes it from a user request.

## 3. Endpoint summary

| Method | Path | Auth | Success | Purpose |
|---|---|---|---|---|
| `GET` | `/pingservice` | none | 200 | liveness; body ignored |
| `GET` | `/CA` | none | 200 | CA certificates, RA list, policy, MOTD, latest client version |
| `GET` | `/CA/motd/text` | none | 200 | message of the day XML |
| `POST` | `/CSR` | none | 201 | new user certificate request |
| `POST` | `/CSR` | PPPK | 201 | renewal (current Java); same XML shape as a user request plus `<PublicKey>` |
| `POST` | `/CSRs` | PPPK | 201 | host certificate request (`<Bulk><CSR>...`), or legacy renewal |
| `POST` | `/resources/resource/publickey/pk` | none | 200 / 404 | status lookup by base64 SPKI |
| `GET` | `/certificate/<id>` | none | 200 | download issued leaf certificate |
| `POST` | `/revoke` | PPPK | 201 | revoke a certificate |
| `GET` | `/ca/issuer.pem` | none | 200 | optional AIA issuer fetch (sandbox/pyCertWiz; the Java client normally builds chains from its truststore) |

Status codes used by the Java client:

| Status | Meaning in the client |
|---|---|
| 200 | GET succeeded; status lookup found a key (or `/CA` is valid) |
| 201 | CSR/renewal/host/revocation accepted |
| 202 | CSR/renewal rejected with an OpenCA `<error>` document |
| 401 | PPPK challenge; read `realm`, `nonce`, `keyid` and optionally `opaque` |
| 403 | authentication failed or service refuses |
| 404 | unknown certificate/service (also means "public key not known" for lookup) |
| 405 | wrong method |

## 4. User certificate request: `POST /CSR`

Sent by `OnlineUserCertRequest`, unauthenticated.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<CSR>
  <Request>-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
</Request>
  <PIN>5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8</PIN>
  <Email>user@example.org</Email>
  <Version>CertWizard 2.2.1</Version>
</CSR>
```

Contract:

* `Request` is a PEM PKCS#10 CSR. The CA should verify its self-signature.
* `PIN` is a SHA-1 PIN hash rendered as **40 upper-case hexadecimal
  characters** (the client sends upper case). Reject other lengths/cases or
  malformed values with 202.
* `Email` is a valid contact address and, for the CA's normal policy, must
  match an `rfc822Name` in the CSR's subjectAltName. The Java
  `CertificateRequestCreator` includes it for user requests.
* `Version` is the client version (`CertWizard 2.2.1`).
* Success is **HTTP 201** with any (usually empty) body. The client treats any
  other status as a failure; 202 is parsed as an error document.

The CA assigns its own request id, applies RA approval, then signs. The client
does not receive that id here; it later looks the key up by public key.

## 5. Host certificate request: `POST /CSRs`

Sent by `OnlineHostCertRequest`, PPPK-authenticated by an existing certificate
and private key.

First request:

```http
POST /CSRs HTTP/1.1
PPPK: this is pppk
serial: 4242
Content-Type: application/xml; charset=UTF-8

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<Bulk>
  <CSR>
    <Request>-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----</Request>
    <PIN>5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8</PIN>
    <Email>host.admin@example.org</Email>
    <Version>CertWizard 2.2.1</Version>
  </CSR>
</Bulk>
```

The server responds **401** with challenge headers:

```http
realm: UK e-Science CA
nonce: <base64 nonce>
keyid: <modulus-hex>.<exponent-hex>
```

The client computes the PPPK response and repeats the same request with:

```http
PPPK: this is pppk
serial: 4242
keyid: <the keyid from the challenge>
realm: <the realm from the challenge>
response: <lower-case hex PPPK response>
```

Success is **201**. `serial` is the decimal serial number of the authenticating
certificate. A host CSR's subjectAltName is a DNS name (normally the CN). The
CA may apply different EKU/validity policy for host certificates.

## 6. Renewal: `POST /CSR` (current client) or `/CSRs` (legacy)

Sent by `OnlineCertRenewRequest`. The request is a `<CSR>` document, not a
`<Bulk>` document, and contains a `<PublicKey>` element identifying the
authenticating certificate:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<CSR>
  <Request>-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----</Request>
  <PIN>...</PIN>
  <Email>user@example.org</Email>
  <PublicKey>df9382...a751.10001</PublicKey>
  <Version>CertWizard 2.2.1</Version>
</CSR>
```

* `<PublicKey>` is the **auth certificate's RSA public key** as
  `<modulus hex>.<exponent hex>`, not a base64 SPKI. The server uses it to find
  the existing certificate.
* The first request has `PPPK: this is pppk` and no `response`; answer 401
  with `realm`, `nonce`, `keyid`.
* The second request carries `keyid`, `realm`, `response`; success is 201.
* The renewal certificate is normally issued for the same subject/SAN; the
  client builds a new key pair and CSR.
* The server may support the nonce challenge or the `opaque` cookie challenge.
  `OnlineCertRenewRequest` supports both; `OnlineHostCertRequest` currently
  supports only the nonce challenge.

The sandbox accepts renewal on both `/CSR` and `/CSRs` to cover old and new
clients. pyCertWiz follows the current Java client and posts renewal to `/CSR`.

## 7. PPPK authentication

PPPK is the historical "public-key proof" challenge used by the UK e-Science
CA. It only works with RSA keys.

1. Client sends an unauthenticated request with `PPPK: this is pppk`. The
   server chooses an authenticating certificate (from `serial` for host
   requests, or `<PublicKey>` for renewals / the `<id>` body for revocation).
2. Server returns **401** with:
   * `realm` — an arbitrary realm string;
   * `nonce` — a base64 value (the sandbox uses a fixed test value);
   * `keyid` — the auth certificate's public key as
     `<modulus hex>.<exponent hex>`.
   * or `opaque` — a cookie for the alternative challenge flow. The client then
     repeats the request with `opaque: <cookie>` and no crypto.
3. Nonce flow: the client forms `nonce + ":" + currentTimeMillis`, lower-cases
   it, encodes each ASCII character to hex, converts that hex to an integer,
   raises it to the private exponent `d` modulo `n`, and sends the lowercase
   hex result as `response`.
4. Server checks that RSA recovery of `response` yields the expected
   `nonce:timestamp` text and that the timestamp is within its tolerance
   (the sandbox allows ±5 minutes).

The sandbox's implementation is the reference for these details; see
`_verify_pppk` in [`sandbox_ca/mock_ca.py`](../sandbox_ca/mock_ca.py).

## 8. Status lookup: `POST /resources/resource/publickey/pk`

The Java client does not poll a request id. It asks "do you know this public
key?" and parses the returned XML.

Request:

```xml
<PublicKey>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...IDAQAB</PublicKey>
```

`<PublicKey>` is the base64 DER `SubjectPublicKeyInfo` (SPKI) of the key in the
keystore entry. The endpoint is a POST but is read-only; the client may retry
it.

### 8.1 Known key with an issued certificate

Return **200**:

```xml
<resources>
  <resource>
    <publickey>MIIB...</publickey>
    <certificates>
      <certificate>
        <id>4242</id>
        <X509Certificate>-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----</X509Certificate>
        <status>VALID</status>
        <useremail>user@example.org</useremail>
        <role>RA Operator</role>
        <RA><OU>CLRC</OU><L>DL</L></RA>
        <owner>CN=golden test user,L=DL,OU=CLRC,O=eScience,C=UK</owner>
        <startdate>06/11/2026</startdate>
        <enddate>06/12/2027</enddate>
        <lifedays>395</lifedays>
        <renew>06/11/2027</renew>
      </certificate>
    </certificates>
    <CCRs/>
    <CRRs/>
  </resource>
</resources>
```

Fields the Java client reads: `id`, `status`, `owner`, `role`, `useremail`,
`startdate`, `enddate`, `lifedays`, `renew`. Dates are `dd/MM/yyyy`. The inline
`X509Certificate` is optional for pyCertWiz but is used by Java's status path when
it wants to refresh a chain; include it for maximum compatibility. Status
`VALID` is what makes the client download/install the certificate.

### 8.2 Known key with a pending CSR

Return **200** with a `<CSRs>` block instead of `<certificates>`:

```xml
<resources><resource>
  <publickey>...</publickey>
  <CSRs><CSR>
    <id>1001</id><status>NEW</status><owner>...</owner><role>...</role>
    <useremail>user@example.org</useremail>
  </CSR></CSRs>
</resource></resources>
```

Typical statuses: `NEW` (awaiting RA), `APPROVED` (awaiting CA signing),
`VALID` (issued), `REVOKED`, `DELETED`. The Java client's messages distinguish
`NEW` and `DELETED`; unknown statuses produce a generic message.

### 8.3 Unknown key

Return **404** (any body). Java's `ResourcesPublicKey.isExist()` is
counter-intuitively named: it returns `true` when the lookup was **not** found
or failed, and `false` when a 200 document was returned.

## 9. Certificate download: `GET /certificate/<id>`

The id is the `<id>` from the status lookup (or the certificate row in the
GUI). Return:

```xml
<certificate>
  <X509Certificate>-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----</X509Certificate>
</certificate>
```

`CertificateDownload` evaluates `/certificate/X509Certificate` and parses it as
PEM. A 404 or malformed document makes the download fail (logged; no
exception). The sandbox also returns an `<id>` and status for human inspection,
but Java ignores them.

The returned certificate must chain to the CA material in the client's
truststore. The Java client builds the chain from its pinned CA certificates;
the sandbox's issuing CA is therefore one of the patched trust anchors.

## 10. CA information and message of the day

### `GET /CA`

Used by `CAInfo` (RA list) and `CAMotd.getLatestVersion()`.

```xml
<CA>
  <certificates>
    <certificate>-----BEGIN CERTIFICATE-----...</certificate>
  </certificates>
  <RAlist>
    <ra><id>1</id><ou>CLRC</ou><l>DL</l><operator/></ra>
    <ra><id>2</id><ou>CLRC</ou><l>RAL</l><operator/></ra>
  </RAlist>
  <PreferredRA><ra><ou>CLRC</ou><l>DL</l></ra></PreferredRA>
  <Policy>
    <MaxExpiredRekey>30</MaxExpiredRekey>
    <MaxPrivateKeyLifeTime>365</MaxPrivateKeyLifeTime>
  </Policy>
  <motd><text>Welcome...</text></motd>
  <certWizard><latestVersion>2.2.1</latestVersion></certWizard>
</CA>
```

* `CAInfo` requires HTTP 200 and at least one `<RAlist/ra>` with `<ou>` and
  `<l>`. It combines them as `"<ou> <l>"` for the RA picker.
* `CAMotd.getLatestVersion()` searches for `<certWizard><latestVersion>`.
  Return the version the client is running (2.2.1 for this build) to avoid an
  update warning.
* `<certificates>` is informational in the Java client (the truststore is
  built from pinned resources, not from this list). Do not use it as a trust
  source.
* The live `/CA` has historically contained old/expired CA certificates; that
  is normal.

### `GET /CA/motd/text`

```xml
<CA><Motd><text>Message of the day</text></Motd></CA>
```

The XPath is `/CA/Motd/text` (capital `M`). It is XML, not plain text;
`CAMotd.getText()` returns null if parsing fails.

## 11. Liveness: `GET /pingservice`

Return **200**; the body is ignored by `PingService.ping()`. The sandbox
returns the live service's XML shape:

```xml
<pingservice><host>sandbox-ca</host></pingservice>
```

Any 2xx/3xx is not enough: the client specifically checks `status == 200`.

## 12. Revocation: `POST /revoke`

Sent by `RevokeRequest`, PPPK-authenticated by the certificate's private key.
The first request has `PPPK` and the body; the server must find the certificate
from the body `<id>` and return a 401 challenge using that certificate's public
key. The second request has `keyid`, `realm`, `response`; success is 201.

```xml
<Revoke>
  <id>4242</id>
  <reason>Key compromise</reason>
</Revoke>
```

`id` is the CA certificate id (not the serial number). `reason` is free text.
The client treats 401 as the challenge and 201 as success; other statuses are
reported as a failure. An `opaque` challenge is also supported by
`RevokeRequest`.

## 13. Error documents

The Java client has two different error parsers, both of which must work:

* `OnlineCertUtil.getServerErrorMessage` (renewal/host/revocation) reads the
  **second** `<text>` element in a 202 document.
* `OnlineUserCertRequest` reads the first `<text>` inside `<minor>`.

Emit the OpenCA shape used by the real CA and the golden fixture
`responses/error-202.xml`:

```xml
<error>
  <request>
    <method>POST</method>
    <location>/CSR</location>
    <time>2026-11-06 15:00:00</time>
  </request>
  <status>
    <major><code>3</code><text>Certificate error</text></major>
    <minor><code>3.2</code><text>PIN does not match the pending request</text></minor>
  </status>
</error>
```

A document with only `<minor><text>` (as some simple test doubles use) makes
the Java renewal error message empty because there is no second `<text>`.

Status mapping in `OnlineCertUtil`:

| Status | Message |
|---|---|
| 202 | second `<text>` from the error document |
| 403 | "Failed authentication. Please contact the helpdesk" |
| 404 | "There is no such service..." |
| 405 | "Server does not support POST." |
| other | generic submission problem |

## 14. Certificate and chain policy

A useful sandbox (and the real CA) must:

* sign the leaf with an issuing CA that chains to a trust anchor in the
  client's truststore;
* preserve the CSR subject and SAN (user e-mail; host DNS names; optional IP
  SANs);
* set `BasicConstraints(ca=False)`, appropriate `KeyUsage`
  (`digitalSignature`, and `keyEncipherment` for RSA), and EKU
  (`clientAuth`/`emailProtection` for users, `serverAuth` for hosts);
* give the leaf a unique positive serial number and a validity period that
  starts slightly before "now" (clock skew);
* return the leaf PEM from `/certificate/<id>` and the same leaf (optionally
  inline) from the status lookup;
* include the issuing CA in the TLS chain.

The sandbox issues 365-day leaves from an ECDSA P-256 issuing CA under an RSA
root, exercising both signature families. The Java client trusts the patched
root/issuing CA; its PKCS#12/keystore code handles RSA leaf keys used for PPPK.

## 15. Request lifecycle expected by the client

1. **User request**: POST `/CSR` → 201. The request is now pending under the
   public key.
2. **RA approval**: out of band (the Java GUI lets the user choose an RA; the
   RA approves in the CA's web interface).
3. **CA signing**: out of band; the certificate gets an id and status `VALID`.
4. **Status check**: POST lookup by SPKI. A pending CSR returns `NEW` /
   `APPROVED`; an issued certificate returns `VALID` and its id.
5. **Download/install**: GET `/certificate/<id>`, build the chain from the
   truststore, store the key + chain in the client keystore.
6. **Renew**: POST `/CSR` (or legacy `/CSRs`) with PPPK, then repeat steps 3–5
   for the new key.
7. **Revoke**: POST `/revoke` with PPPK; the certificate status becomes
   `REVOKED`.

The Java client only performs online checks for certificates whose issuer DN
is listed in `ngsca.issuer.dn`. If that setting does not match the sandbox
issuing CA, the GUI will appear to ignore the certificate. The Java kit sets
this automatically.

## 16. Full runnable mock CA

The full mock CA lives in [`sandbox_ca/`](../sandbox_ca/) and
shares its protocol code with the pyCertWiz test suite (`tests/mock_ca.py` is a
compatibility shim). The same server also exposes an RFC 8555 ACME v2 front-end
for certbot/nginx; see [ACME.md](ACME.md) and the STFC modernisation dossier
[STFC-ACME-MODERNISATION.md](STFC-ACME-MODERNISATION.md).

### 16.1 Start it

From the pyCertWiz repository:

```sh
python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443
```

The server prints:

* the HTTPS URL (default `https://localhost:8443`);
* the root and issuing CA SHA-256 fingerprints;
* the issuing CA's RFC 2253 DN (for `ngsca.issuer.dn`);
* an admin token, the admin-console URL and the path to
  `.sandbox-ca/sandbox.json`.

Useful options:

| Option | Meaning |
|---|---|
| `--host` / `--port` | listener address; port 0 picks a free port |
| `--public-host NAME` | add a DNS/IP SAN for a client on another machine (repeatable) |
| `--data-dir DIR` | persistent CA hierarchy, `state.json` and `sandbox.json` |
| `--auto-sign` (default) | approve and issue after `--sign-after-polls` status lookups |
| `--manual` | leave requests pending for the admin API |
| `--sign-after-polls N` | 0 = issue on submission; 1 = first status lookup |
| `--admin-token TOKEN` | fixed admin token; otherwise a random token is generated |
| `--no-admin-auth` | disable admin auth (loopback-only sandbox) |
| `--java-jar JAR` | patch a Java jar immediately after starting |

The CA hierarchy and the CSR/certificate database (`state.json`) are persisted,
so restarting the sandbox does not invalidate a patched Java client and does
not lose issued certificates: a certificate already downloaded by the Java
client can still be looked up, renewed or revoked after a restart. The TLS leaf
is regenerated on each start (it is trusted through the persisted CA, so
rotation is harmless). Use the admin UI's **Clear all requests/certs** button,
or `sandbox_ca.admin reset`, to start a clean RA queue. The patched Java URLs
contain the port, so restart on the same `--port` or repatch the jar.

### 16.2 Admin API

Admin endpoints are on the same TLS listener under `/__sandbox__/` and require
`X-Sandbox-Token: <token>` (or `Authorization: Bearer <token>`). The browser
console is at `/__sandbox__/ui` and uses `?token=<token>` for its first load;
its JavaScript then sends the token as a header. A browser will warn about the
sandbox CA until you accept the localhost exception or import `root.pem`.

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/__sandbox__/ui?token=...` | — | browser console: approve, sign, reject, revoke, settings, request log |
| GET | `/__sandbox__/status` | — | CSRs, certificates, modes, fingerprints |
| GET | `/__sandbox__/requests?limit=N` | — | recently captured requests (method, path, headers, body) |
| POST | `/__sandbox__/approve` | `{"id": 1001}` or `{"all": true}` | mark NEW/RENEW as APPROVED |
| POST | `/__sandbox__/sign` | `{"id": 1001}` or `{"all": true}` | issue certificate(s) |
| POST | `/__sandbox__/reject` | `{"id": 1001, "reason": "..."}` or `{"all": true}` | reject a pending CSR |
| POST | `/__sandbox__/revoke` | `{"id": 5000, "reason": "..."}` | revoke an issued certificate |
| POST | `/__sandbox__/reset` | `{}` | forget CSRs/certs/captured requests |
| POST | `/__sandbox__/settings` | see below | auto-sign, validity and fault-injection modes |
| GET | `/__sandbox__/ca.pem` | — | root + issuing CA PEM |

Example with the helper:

```sh
python3 -m sandbox_ca.admin --data-dir .sandbox-ca status
python3 -m sandbox_ca.admin --data-dir .sandbox-ca ui
python3 -m sandbox_ca.admin --data-dir .sandbox-ca approve 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca sign 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca reject 1001 --reason "wrong RA"
python3 -m sandbox_ca.admin --data-dir .sandbox-ca revoke 5000 --reason "Key compromise"
python3 -m sandbox_ca.admin --data-dir .sandbox-ca settings --valid-days 30
```

`settings` accepts `auto_approve` (bool), `sign_after_polls` (int),
`valid_days` / `host_valid_days` (certificate lifetime), and the fault-injection
modes `pppk_mode`, `lookup_mode`, `download_mode`, `info_mode` (the same modes
used by the pyCertWiz test suite: `no_challenge`, `opaque`, `bad_keyid`,
`bad_response`, `no_inline`, `csr_only`, `malformed`, `wrong_pem`, `bare_pem`,
`wrong_cert`, etc.).

### 16.3 Patch and run the Java client

The Java client pins its bundled CA certificates in
`BundledCaCertificates.class`. The kit replaces:

* `/escience-root.pem`, `/escience-2b.pem`, `/escience-root-2026.pem`,
  `/escience-3b.pem` with the sandbox root and issuing CA (the root/issuer are
  duplicated across the four historical slots);
* the four 64-character SHA-256 pin constants in the class file;
* every CA URL in `configure.properties`;
* `ngsca.issuer.dn` (so the GUI performs online status checks);
* `ngsca.cert.o` / `ngsca.cert.c` (cosmetic subject defaults);
* JAR signature files (the modified JAR cannot retain the original signature).

Patch a built JAR (no JDK needed for patching):

```sh
python3 -m sandbox_ca.java_kit \
  --server-info .sandbox-ca/sandbox.json \
  --jar /path/to/CertWizard-jar-with-dependencies.jar \
  --out /tmp/CertWizard-sandbox.jar

java -jar /tmp/CertWizard-sandbox.jar --self-test
java -jar /tmp/CertWizard-sandbox.jar /tmp/certwizard-sandbox-data
```

Open the admin-console URL printed by the sandbox (also in
`.sandbox-ca/sandbox.json`). In `--manual` mode, approve and sign each request
there; the Java GUI then picks the certificate up on its next status check. In
auto-sign mode the console is still useful for inspecting traffic, rejecting a
request or changing validity/fault settings.

`--self-test` is headless and verifies the patched pins and truststore. It does
not contact the network. The GUI then asks for a data directory; use a fresh
one, not your real `~/.ca` profile.

Or patch/build from source (Java 25+ and Maven required):

```sh
python3 -m sandbox_ca.java_kit \
  --server-info .sandbox-ca/sandbox.json \
  --source-dir /path/to/CertWizard \
  --out /tmp/CertWizard-sandbox \
  --build

java -jar /tmp/CertWizard-sandbox/target/CertWizard-jar-with-dependencies.jar --self-test
```

The README written next to the patched JAR repeats these commands.

### 16.4 Headless Java flow check

[`sandbox_ca/java/SandboxFlow.java`](../sandbox_ca/java/SandboxFlow.java) uses
public CertWizard classes to exercise user submission, status lookup,
download, host request, renewal and revocation against the sandbox:

```sh
javac -cp /tmp/CertWizard-sandbox.jar -d /tmp sandbox_ca/java/SandboxFlow.java
java -cp /tmp:/tmp/CertWizard-sandbox.jar SandboxFlow
```

It prints `SANDBOX-FLOW-OK` when all protocol paths succeed. Use auto-sign mode
(the default) so the post-submission status lookup issues the certificate.

### 16.5 Useful test modes

The sandbox shares the test suite's fault injection. For example:

```sh
# manual approval, then inspect the captured PPPK exchange
python3 -m sandbox_ca --data-dir /tmp/ca --manual --port 8443
python3 -m sandbox_ca.admin --data-dir /tmp/ca requests --limit 50

# make the next status lookup malformed
python3 -m sandbox_ca.admin --data-dir /tmp/ca settings --lookup-mode malformed

# omit the inline certificate (Java must download it separately)
python3 -m sandbox_ca.admin --data-dir /tmp/ca settings --lookup-mode no_inline

# force the opaque challenge for renew/revoke
python3 -m sandbox_ca.admin --data-dir /tmp/ca settings --pppk-mode opaque
```

`OnlineHostCertRequest` does **not** support the opaque challenge; use
`--pppk-mode normal` when exercising host requests.

## 17. Compatibility checklist

Use this when implementing a listener for the Java client:

- [ ] TLS certificate chains to a CA the client trusts; hostname matches.
- [ ] HTTP/1.1; no redirects; accepts `Content-Length` **and** chunked bodies.
- [ ] `Date`, `Accept`, `User-Agent`, `LocalHost` headers do not cause errors.
- [ ] `/pingservice` returns 200.
- [ ] `/CA` has at least one `<RAlist/ra>` with `<ou>` and `<l>`, and a
      `<certWizard><latestVersion>` matching the client.
- [ ] `/CA/motd/text` is XML with `/CA/Motd/text`.
- [ ] `POST /CSR` accepts the user XML and returns 201.
- [ ] `POST /CSRs` implements the 401 PPPK challenge, `serial`, and 201.
- [ ] `POST /CSR` with `PPPK` implements renewal (or `/CSRs` for old clients).
- [ ] PPPK `keyid` is the auth cert's modulus/exponent and `response` uses the
      client's nonce/timestamp scheme.
- [ ] Status lookup returns 404 for unknown keys and 200 with
      `<certificates>`/`<CSRs>` for known keys; dates are `dd/MM/yyyy`.
- [ ] `/certificate/<id>` returns `<certificate><X509Certificate>` PEM.
- [ ] `/revoke` implements PPPK and returns 201.
- [ ] 202 errors use `<error><status><major><text>...` and
      `<minor><text>message</text>` (two text nodes).
- [ ] `ngsca.issuer.dn` in the client matches the issuing CA.
- [ ] The client's bundled CA resources and pins are patched for a private CA.

## 18. Security notes

* The sandbox CA private keys are unencrypted in `--data-dir` (mode 0600).
  Protect or delete the directory; never commit it.
* Anyone with the admin token can issue certificates. Keep the listener on
  loopback, or use a firewall and a strong token; `--no-admin-auth` is only for
  isolated local tests.
* The browser console URL contains the token and the browser will warn about
  the sandbox CA until it is trusted. Avoid shared browser profiles and shared
  logs when using it.
* The sandbox issues certificates without identity proofing. Do not install
  them in a real trust store or use them outside the test host.
* When patching a JAR, the original signature is removed. Verify the patched
  JAR's SHA-256 yourself if that matters; do not distribute it as an official
  CertWizard build.
