# The CA protocol, as implemented

There is no public specification for the UK e-Science CA’s client API.
This document records the wire protocol pyCert implements, derived from
CertWizard’s source and verified against the live server where possible. If the
CA changes, this is the file to update.

## Transport

* HTTPS to `ca.base_url` (default `https://cwiz-live.ca.ngs.ac.uk:443`).
* HTTP/1.1, `Connection: close`, XML request and response bodies.
* Every request carries `LocalHost: <canonical hostname>` and
  `User-Agent: <ca.user_agent>`.
* Authenticated requests also carry `PPPK: this is pppk`.
* The live server’s certificate chains to `CN=UK e-Science CA 2B`, which chains
  to `CN=UK e-Science Root`; both are in the bundled chain.

## Transport policy

pyCert does not use a general-purpose HTTP library for CA calls.  The transport
(`pycert/transport.py`) enforces total deadlines, bounded DNS and connect
attempts, strict response framing (length/chunk validation, header and body
limits), retries only for idempotent requests, same-host redirects only, and
cancellation.  The status lookup is an idempotent POST; CSR submission and
revocation are not.  See the README for the configuration knobs and
`tests/test_transport.py` for the failure matrix.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/pingservice` | liveness; 200 with a short body |
| `GET` | `/CA` | CA certificates, RA list, preferred RA, policy |
| `GET` | `/CA/motd/text` | message of the day (returns XML, see below) |
| `POST` | `/CSR` | new user certificate request |
| `POST` | `/CSRs` | host request or renewal (PPPK authenticated) |
| `POST` | `/resources/resource/publickey/pk` | status lookup by public key |
| `GET` | `/certificate/<id>` | issued certificate |
| `POST` | `/revoke` | revocation (PPPK authenticated) |

### `GET /CA`

```xml
<CA>
  <certificates>
    <certificate>-----BEGIN CERTIFICATE-----...</certificate>
    <certificate>...</certificate>
  </certificates>
  <RAlist>
    <ra><ou>CLRC</ou><l>DL</l><operator><id>1</id></operator></ra>
    ...
  </RAlist>
  <PreferredRA><ra><ou>CLRC</ou><l>DL</l></ra></PreferredRA>
  <Policy>
    <MaxExpiredRekey>30</MaxExpiredRekey>
    <MaxPrivateKeyLifeTime>395</MaxPrivateKeyLifeTime>
  </Policy>
</CA>
```

Observed with the live server:

* the `<certificates>` list contains **historic** CA certificates (expired in
  2007 and 2011), not the ones currently issuing. Never use it as a trust
  source; pyCert only displays it (`pycert info`). Trust comes from the pinned
  chain in the configuration.
* `/CA/motd/text` returns an XML document (`<CA><Motd><text>…`), not plain text.
  pyCert extracts the `<text>` elements.

### `POST /CSR`

Request:

```xml
<CSR>
  <Request>-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
</Request>
  <PIN>3F2A…40 upper-case hex…</PIN>
  <Email>jane@example.org</Email>
  <Version>CertWizard 2.2.1</Version>
</CSR>
```

Responses:

* `201 Created` — accepted; the CSR is now `NEW`.
* `202 Accepted` — rejected. The body is an error document; pyCert reads the
  `<text>` element(s), preferring the ones under `<minor>`:

  ```xml
  <Response><minor><text>the reasons…</text></minor></Response>
  ```

  Other statuses (403, 404, 405, 5xx) are surfaced as an error with the status
  and any `<text>` found.

The PIN is hashed **client-side** and the RA compares the hash; the server never
sees the PIN. CertWizard’s `HashUtil` uses SHA-1 and upper-case hex, and so does
pyCert (`csr.pin_hash = "sha1"`).

The server enforces that the `<Email>` element matches the CSR’s e-mail SAN for
user requests; a mismatch comes back as a 202 with a message.

### `POST /CSRs` (host and renewal)

Two request shapes, both requiring PPPK client authentication:

```xml
<!-- host request (also sends header serial: <auth cert serial>) -->
<Bulk>
  <CSR>
    <Request>…</Request><PIN>…</PIN><Email>…</Email><Version>…</Version>
  </CSR>
</Bulk>

<!-- renewal (PublicKey = the *existing* certificate's RSA public key) -->
<CSR>
  <Request>…</Request><PIN>…</PIN><Email>…</Email>
  <PublicKey>modulus-hex.exponent-hex</PublicKey>
  <Version>…</Version>
</CSR>
```

A host request must be authenticated by an existing valid certificate; the
server finds it from the `serial` header. A renewal is identified by the
`<PublicKey>` element, which is the key that signs the PPPK challenge.

### PPPK

The server challenges with `401 Unauthorized` and three headers:

| Header | Meaning |
|---|---|
| `realm` | sent back unchanged |
| `nonce` | random string, sent back inside the response |
| `keyid` | `<modulus hex>.<public exponent hex>` of the certificate |
| `opaque` | alternative cookie mode; if present, resend it as a header |

The client response is:

```
text      = lower(nonce) + ":" + unix_time_millis
challenge = integer formed by reading the ASCII characters of text as hex digits
response  = challenge ^ d (mod modulus), formatted as lower-case hex
```

and is sent in the `response` header together with `realm` and `keyid`. The
server verifies it with the certificate’s public exponent and accepts a
timestamp within a few minutes.

Because this uses the private exponent, PPPK only works with RSA keys. ECDSA
certificates can be issued and used normally but cannot authenticate a renewal
or host request with this server.

pyCert checks that the `keyid` modulus equals the key it is about to use and
refuses to answer a challenge for a different key.

### `POST /resources/resource/publickey/pk`

```xml
<PublicKey>base64(DER SubjectPublicKeyInfo)</PublicKey>
```

Response `200`:

```xml
<resources><resource>
  <publickey>…</publickey>
  <certificates>
    <certificate>
      <id>3510</id>
      <status>VALID</status>
      <owner>CN=…</owner><role>RA Operator</role>
      <useremail>…</useremail>
      <startdate>23/04/2026</startdate><enddate>20/10/2027</enddate>
      <lifedays>171</lifedays><renew>20/10/2027</renew>
      <X509Certificate>-----BEGIN CERTIFICATE-----…</X509Certificate>
    </certificate>
  </certificates>
  <!-- or, while no certificate exists: -->
  <CSRs><CSR><id>…</id><status>NEW</status>…</CSR></CSRs>
</resource></resources>
```

* `404` (or an empty document) means the CA does not know the key yet; this is
  normal immediately after submission.
* Certificates take precedence over CSRs. If several of either are returned, the
  **last** is the latest.
* CSR statuses observed/understood: `NEW`, `RENEW`, `APPROVED`, `DELETED`.
* Certificate statuses: `VALID`, plus terminal states such as `REVOKED`,
  `EXPIRED`, `SUSPENDED`.

pyCert uses this endpoint as the single source of truth for progress: it *never*
relies on an ID returned by `/CSR` (there isn’t one), it polls by the public key
it generated.

### `GET /certificate/<id>`

```xml
<certificate><X509Certificate>-----BEGIN CERTIFICATE-----…</X509Certificate></certificate>
```

pyCert also accepts a bare PEM/DER body. Certificate IDs must match
`[A-Za-z0-9._-]+` before being placed in the URL.

### `POST /revoke`

```xml
<Revoke><id>3510</id><reason>superseded</reason></Revoke>
```

PPPK-authenticated with the key of the certificate being revoked (the server
challenges with that certificate’s key). Reasons offered by pyCert:
`unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`,
`superseded`, `cessationOfOperation`, `certificateHold`.

## Status model in pyCert

```
DRAFT ──submit──> SUBMITTED ──RA approves──> APPROVED ──CA signs──> SIGNED
                      │                                              │
                      │                              download+verify │
                      │                                              ▼
                      └────────── rejected ─────> FAILED        DOWNLOADED
                                                                     │
                                              revoke ────────────────┴──> REVOKED
```

* `SIGNED` means the certificate is stored but a PKCS#12 was not written (for
  example because the chain did not validate).
* `FAILED` keeps the key and CSR on disk so a status lookup can still be made
  (the submission may have reached the server despite a network error).
* A renewal sets `renewal = true` and stores `pending_*` public key/CSR hashes.
  Polling uses the pending key; the current certificate remains untouched until
  the new one has been verified, at which point the old files are archived.

## Deliberate deviations from CertWizard

* No automatic retry of a POST that may have reached the server.
* Certificate and chain are verified before a `.p12` is written; CertWizard
  exported whatever it downloaded.
* The server’s `/CA` certificate list is treated as informational only.
* XML is parsed with DOCTYPE/ENTITY rejected and a size cap.
* The `opaque` cookie mode is supported (CertWizard had it for revocation and
  renewal), but the nonce/realm/keyid mode is the default path.

## Testing the protocol

`tests/mock_ca.py` implements all of the above over real TLS, including PPPK
challenges, status transitions, revocation and AIA fetching. `tests/test_ca.py`
and `tests/test_workflow.py` assert the exact shapes and the PPPK arithmetic, so
a protocol change is visible as a test failure rather than a mysterious error in
production.
