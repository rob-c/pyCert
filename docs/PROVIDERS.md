# CA providers and plugins

pyCertWiz separates *what every certificate needs* from *how a particular CA is
spoken to*:

```text
 CLI / GUI ──► workflow (validate → key → CSR → store → verify chain → export → deploy)
                   │
                   ▼
            CAProvider interface  (providers/base.py)
            ├── ukca  – UK e-Science CA, CertWizard/OpenCA protocol  (providers/ukca.py)
            ├── acme  – RFC 8555 ACME with EAB, http-01 / dns-01     (providers/acme.py)
            └── …     – plugins via the "pycert.providers" entry point
```

Each `[cas.<name>]` profile in the configuration has a `kind` that selects a
provider. The primary `[ca]` is always `ukca`.

## What a provider implements

```python
from pycert.providers.base import CAProvider, Capabilities, PingResult, PollOutcome, SubmitResult

class MyCAProvider(CAProvider):
    kind = "myca"
    label = "My CA (REST API)"
    capabilities = Capabilities(
        user_certificates=False,
        host_certificates=True,
        pin=False, ra=False, host_authentication=False,
        domain_validation=True,
        revoke=True,
        manual_approval=False,
        organisation_subject=False,
    )

    def ping(self, *, stop_event=None) -> PingResult: ...
    def preflight(self, spec, *, progress, stop_event=None): ...      # optional
    def submit(self, state, csr, spec, *, prepared, progress, on_pin, stop_event) -> SubmitResult: ...
    def submit_renewal(self, state, csr, *, old_certificate, old_key, contact, pin,
                       progress, on_pin, stop_event) -> SubmitResult: ...
    def poll(self, state, *, progress, stop_event=None) -> PollOutcome: ...
    def revoke(self, state, reason, *, certificate, key, progress, stop_event=None) -> SubmitResult: ...
    def info(self, *, stop_event=None) -> dict: ...                   # optional
```

| Method | Responsibility |
|---|---|
| `capabilities` | Tells the CLI and GUI what to offer: personal and/or host certificates, an RA PIN, an RA choice, host authentication by an existing certificate, domain validation, revocation (and its reasons), whether issuance needs a human (`manual_approval`), and whether the subject carries organisation attributes. |
| `validate_request(spec)` | Reject requests this CA cannot handle *before* a key is generated. The base class checks the capabilities. |
| `subject_for(spec)` | The subject DN to request. The base class uses the full DN; ACME uses CN only. |
| `preflight(spec)` | Reachability and preparation (e.g. ensure an ACME account exists). The return value is passed to `submit`. |
| `submit(...)` | Submit the PKCS#10 request (already built and verified by the workflow). Keep any protocol state you need later in `state.provider` (a JSON-safe dict saved with the request). |
| `submit_renewal(...)` | Same, for a renewal with a new key. The old certificate and key are provided for CAs that authenticate renewals. |
| `poll(state)` | Report progress and return `PollOutcome(certificate=…, chain=[…])` once issued. Return `terminal=True` for rejected/revoked requests. Check that the certificate's public key matches `state.active_spki_b64`. |
| `revoke(...)` | Revoke at the CA. |

The workflow then does the rest for every provider: it checks the key
matches, verifies the chain against the profile's anchors (using the
provider's chain as hints), archives the previous files on renewal, writes
the PKCS#12 file, deploys to targets and records history.

Rules for providers:

* never log or return private keys, PINs, passphrases or HMAC keys;
* use `pycert.transport.Transport` for HTTP, so TLS pinning, deadlines, size
  limits and cancellation behave like the built-in providers;
* honour `stop_event` in every wait;
* raise `pycert.errors.CAError` for CA refusals and `ProtocolError` for
  responses that cannot be understood.

## Registering a plugin

In the plugin package's `pyproject.toml`:

```toml
[project.entry-points."pycert.providers"]
myca = "mypackage.myca:MyCAProvider"
```

Then, in the pyCertWiz configuration:

```toml
[cas.my-ca]
kind = "myca"
display_name = "My CA"
base_url = "https://ca.example.org/api"
```

`pycert ca list` shows the profile, `pycert request host.example.org --type
host --ca my-ca` uses it, and the GUI offers it in the request wizard. For
tests or embedding, `pycert.providers.register("myca", MyCAProvider)`
registers a class at runtime.
