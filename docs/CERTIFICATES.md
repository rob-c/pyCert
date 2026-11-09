# User and host certificate definitions

pyCert builds two certificate request types from the same CSR engine:

| Type | Subject/SAN definition | Authentication |
|---|---|---|
| **user** | personal name; contact e-mail is placed in the CSR `rfc822Name` SAN | unauthenticated `POST /CSR` |
| **host** | fully-qualified DNS name; DNS SAN; serverAuth profile | PPPK-authenticated `POST /CSRs` using an existing certificate/key |

The CA decides the final profile.  pyCert's request definition only selects the
CSR contents and the UK-CA submission flow.

## User certificates

```console
$ pycert request "Jane Doe" \
  --email jane@example.org \
  --ra "CLRC DL" \
  --type user
```

- The common name must contain at least two name parts.
- The contact e-mail is required and is also added to the CSR SAN; the CA checks
  that the XML `<Email>` matches it.
- `--san-email` adds extra e-mail SANs; `--san-dns` / `--san-ip` add extra names
  where policy permits.
- A user certificate cannot use `--auth`; use a host request for delegation.

## Host certificates

```console
$ pycert request host.example.org \
  --type host \
  --auth "Jane Doe" \
  --email host-admin@example.org \
  --ra "CLRC DL"
```

- The CN must be a fully-qualified DNS name (at least one dot, valid labels).
- The DNS name is placed in the CSR SAN; host certificates receive the
  serverAuth EKU from the CA.
- `--auth` is the alias of an already-issued, currently valid certificate whose
  private key signs the PPPK challenge.  The authenticating certificate must be
  RSA (the UK-CA PPPK requirement), even though the new host key may be EC.

## Changing the definition at renewal

UK-CA renewal is authenticated by the existing certificate's RSA key and
`PPPK`.  pyCert preserves the existing subject and certificate type, because
the CA renewal protocol identifies the request by the old key and does not
provide a standard way to change a user certificate into a host certificate (or
vice versa).

The parts that can be changed explicitly at renewal are:

- contact e-mail (`--email`);
- SANs: add/replace with `--san-dns`, `--san-email`, `--san-ip`;
- remove all SANs of a kind with `--clear-san-dns`, `--clear-san-email`,
  `--clear-san-ip`;
- key algorithm/size (`--key-algorithm`, `--rsa-bits`, `--ec-curve`);
- PIN (`--pin` / `--pin-file` / `--pin-stdin`).

```console
$ pycert renew jane-doe \
  --email new@example.org \
  --san-email new@example.org \
  --san-dns extra.example.org \
  --yes

$ pycert renew host.example.org \
  --san-dns new-host.example.org --clear-san-ip --yes
```

The certificate type is immutable during a renewal in pyCert.  To move a
service from a user-style request to a host request, create a new host request
with an existing authenticating certificate; do not pretend it is a renewal.
This is a deliberate safety rule, not a missing feature: the CA identifies
renewals by the old key, and silently changing the identity/profile would make
the audit trail misleading.
