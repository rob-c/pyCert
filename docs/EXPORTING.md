# Exporting certificates and keys

pyCertWiz can export a certificate in several formats. PKCS#12 is the default.
Anything that contains a private key is protected with a **new passphrase
that you choose for that export**.

```console
$ pycert export web1.example.ac.uk                     # PKCS#12 in the current folder; asks twice for a new passphrase
$ pycert export web1.example.ac.uk --format pem-bundle --out web1.pem
$ pycert export web1.example.ac.uk --format fullchain  # public: no passphrase
$ pycert export web1.example.ac.uk --encryption 3des --out web1-java8.p12 --password-file pw.txt
```

In the GUI, select the certificate and choose **Export…** (Ctrl/Cmd+E). The
dialog offers the same formats, encryption types and options.

## Formats

| `--format` | File | Contains | Passphrase |
|---|---|---|---|
| `p12` (default) | `<name>.p12` | key, certificate, chain | required |
| `pem-bundle` | `<name>.pem` | encrypted key, certificate, chain | required |
| `pem-files` | folder: `<name>.pem`, `<name>.key` | certificate (+ chain); key | required, or *none* after confirmation |
| `key` | `<name>.key` | the private key alone | required, or *none* after confirmation |
| `cert` | `<name>.crt` | the certificate (PEM) | none: public |
| `fullchain` | `<name>.fullchain.pem` | certificate and issuers (PEM) | none: public |
| `der` | `<name>.cer` | the certificate (DER, as Windows expects) | none: public |
| `p7b` | `<name>.p7b` | certificate and issuers (PKCS#7) | none: public |

`--no-chain` leaves the issuing CA certificates out of `p12`, `pem-bundle`
and `pem-files`. `--out` names the file, or a folder to put the default file
name in. Existing files are not replaced unless you pass `--force`. The GUI
asks before replacing them.

## Encryption types

| Format | `--encryption` | Use it for |
|---|---|---|
| PKCS#12 | `aes256` (default) | AES-256-CBC, PBES2 with PBKDF2-SHA256, SHA-256 MAC. OpenSSL 1.1+, Java 11+, current Windows and macOS. |
| PKCS#12 | `3des` | PBE-SHA1-3DES with a SHA-1 MAC. Weaker; for Java 8, CertWizard's bundled Java and older Windows/macOS. |
| PEM keys | `pkcs8` (default) | `ENCRYPTED PRIVATE KEY`, AES-256-CBC. Read by OpenSSL, Globus, nginx and Apache. |
| PEM keys | `traditional` | `RSA PRIVATE KEY` / `EC PRIVATE KEY` with `DEK-Info: AES-256-CBC`, for older tools. |

## The passphrase

* It must be **new**. pyCertWiz's own saved secret, which protects its store, is
  refused.
* It must be at least **8 characters**. Non-ASCII characters work, but some
  older software cannot open such files, and pyCertWiz says so.
* pyCertWiz does **not keep it**. Store it somewhere safe, because you need it
  to use the file.
* On a terminal pyCertWiz asks for it twice. Scripts give it for one command
  with `--password-file` or `--password-stdin`.

Bundles (`p12`, `pem-bundle`) are always encrypted. A single key file (`key`,
or the key in `pem-files`) may be written without a passphrase with
`--no-key-passphrase`, but only after you confirm by typing `unencrypted`.
There is no `--yes` shortcut, and it is refused when nobody is at a terminal
to confirm. `pycert install` (`~/.globus/userkey.pem`) follows the same rules.

## pyCertWiz's own copy

After issuance pyCertWiz also keeps a PKCS#12 copy in its store, protected with
the saved secret. `pycert export ALIAS --stored` re-writes that copy. It is
pyCertWiz's own file, not an export: use `pycert export` without `--stored` to
produce a file for someone else.

Deployment targets (`pycert deploy`) are separate as well. Services read
their keys unattended, so deployed keys use the saved secret. See
[OPERATIONS.md](OPERATIONS.md).

## Viewing keys and the chain

In the GUI, **More → View certificate, keys and chain…** (Ctrl/Cmd+K) opens a
viewer with three tabs:

* **Certificate chain**: every certificate from yours up to the root, with
  details, fingerprints and PEM. Copy one certificate or the full chain, or
  save the full chain as a file.
* **Public key**: algorithm, size, modulus or curve point, the SPKI
  fingerprint and the base64 form the UK CA looks certificates up by, and the
  PEM.
* **Private key**: where it is stored and how it is protected. **Show private
  key…** decrypts it and displays it only after you type `show`. It cannot be
  copied from the viewer, and it is cleared when you hide it or close the
  window.
