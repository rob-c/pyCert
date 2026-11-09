# Proxy certificates and proxy bundles

pyCert can delegate a stored UK e-Science certificate to a short-lived
**RFC 3820 proxy certificate**.  The proxy is signed by the stored end-entity
certificate and private key, verified immediately, and written as a PEM bundle
that contains the proxy key, proxy certificate and issuer chain.

This is the traditional GSI/Grid delegation model.  It is deliberately separate
from the ACME listener: an ACME server issues certificates; a proxy is a local
delegation signed by a certificate you already hold.

> Proxy bundles contain an unencrypted private key by default (mode 0600) so
> that Grid tools can read them.  Use a password for an encrypted key, or remove
> the bundle immediately after the short-lived job.

## Create a proxy

```console
$ pycert proxy "Jane Doe" --hours 4
Proxy bundle created: ~/.local/share/pycert/requests/jane-doe/proxy.pem
  subject:   ...
  issuer:    ...
  valid:     2026-... .. 2026-...
```

The default output is `proxy.pem` inside the request directory.  A different
path can be used:

```console
$ pycert proxy jane-doe \
  --out /run/user/1000/jane.proxy.pem \
  --hours 2 \
  --path-length 0 \
  --limited
```

| Option | Meaning |
|---|---|
| `--hours N` | lifetime, 1–720 hours, clamped to the issuer certificate's expiry |
| `--path-length N` | RFC 3820 path-length constraint |
| `--limited` | use the limited-proxy policy (`id-ppl-limited`) instead of inherit-all |
| `--rsa-bits N` | proxy key size, minimum 2048 |
| `--password-file` / `--password-stdin` / `--password` | encrypt the proxy private key |
| `--remove` | verify the bundle and immediately delete it |
| `--json` | machine-readable result |

## Bundle layout

The PEM bundle is, in order:

1. proxy private key (PKCS#8, unencrypted unless a password was supplied);
2. proxy certificate;
3. issuer/end-entity certificate;
4. issuer chain (roots/intermediates as available), deduplicated.

`load_proxy_bundle()` verifies the proxy signature with the issuer certificate
and checks that the first certificate carries the RFC 3820 ProxyCertInfo
extension.  `create_proxy_bundle()` also verifies the bundle after writing it,
and checks that the proxy key matches the proxy certificate.

## Runtime test and removal

The test suite includes a runtime test that requests a real certificate from the
mock CA, signs a proxy bundle, verifies the signature and bundle contents, and
then removes the bundle:

```console
$ .venv/bin/pytest -q tests/test_proxy.py -k runtime
```

The same operation can be performed in a deployment job by using `--remove`:

```sh
pycert proxy my-service --hours 1 --remove
# The bundle is created, verified, and deleted before the command returns.
```

## Security notes

- The proxy is only as trustworthy as the issuing certificate and private key;
  protect the original key as usual.
- A proxy does not replace RA approval for the original certificate.
- A limited proxy restricts policy but does not magically limit every protocol;
  relying parties must understand the proxy policy.
- Use a short lifetime and remove the bundle when the delegated process exits.
- Do not copy proxy bundles between hosts or users.

## Standard references

- RFC 3820 — Internet X.509 Public Key Infrastructure Proxy Certificate Profile
- RFC 5280 — X.509 certificate and CRL profile
- IGTF/GSI proxy conventions for the Grid tooling that consumes the bundle
