# Java keystores as a certificate store

CertWizard keeps every certificate in one Java keystore, `cakeystore.pkcs12`:
one *key entry* (private key, certificate and chain) per certificate, named by
an alias. pyCertWiz can use that file directly as a store. There is no need to
extract each entry and import it.

```console
$ pycert keystore link ~/.ca/cakeystore.pkcs12        # asks for the keystore passphrase
Linked keystore 'cakeystore': /home/jane/.ca/cakeystore.pkcs12 (6 key entries)
cakeystore: 5 imported, 1 pending imported
$ pycert list                                          # all of them, managed by pyCertWiz
```

In the GUI: **Link a Java keystore…** in the sidebar, or open the file in the
**Java bundle inspector** and click **Use as certificate store…**.

## What linking does

| When | What happens |
|---|---|
| You link the keystore | The passphrase is checked and used for this session only. Every key entry appears in pyCertWiz, named by its Java alias. |
| An entry is added by another Java tool | It is imported at the next sync. |
| pyCertWiz issues or renews a certificate in the keystore | The entry is written back: added, or replaced under its alias. |
| A certificate is renewed elsewhere (e.g. CertWizard) | The newer certificate is taken from the keystore, the previous one is archived, and deployment targets are refreshed. |
| An entry pyCertWiz wrote is deleted with keytool | The certificate stays managed by pyCertWiz but is no longer linked. pyCertWiz does not put it back. |
| An entry is imported | pyCertWiz asks the CA for its record of the certificate (status and contact e-mail) at the next background check in the GUI, or with `pycert status --refresh`. A renewal always asks again first. |
| You rename a certificate (`pycert edit ALIAS --name NEW --rename-keystore-entry`, or **Rename…** in the GUI) | The keystore entry gets the same name. Only that entry is re-encrypted; the others stay byte-for-byte identical. Without the option only pyCertWiz's name changes, and the link follows the entry's Java alias. |
| CertWizard has a request still waiting for the CA | CertWizard stores it as a key entry with a self-signed placeholder named `<CN> CSR cert`. pyCertWiz imports it as a *pending* request with the real CN and type (user or host), polls the CA by its public key, and replaces the placeholder with the issued certificate. |

## The passphrase is never stored

pyCertWiz never keeps a keystore's passphrase: not in the configuration, the
secret store, the environment or any file. It lives in memory for one session.

* The **GUI** asks for each linked keystore's passphrase every time it starts.
  **Cancel** leaves that keystore *locked* for the session. A locked keystore
  shows a padlock in the sidebar; right-click it and choose **Unlock…** to
  give the passphrase later.
* The **CLI** asks when a command needs it (`pycert keystore sync`, or writing
  a newly issued certificate back) if it is running in a terminal. Scripts can
  pass it for one command with `--password-file` or `--password-stdin`.
* While a keystore is locked, pyCertWiz does not read or write it. Issued and
  renewed certificates are kept safely in pyCertWiz's store, and `pycert check`
  warns "not yet written to Java keystore". The next sync after you unlock it
  writes them.

## When synchronisation happens

* In the GUI: once you unlock a keystore, on every background check, and
  whenever the file changes on disk.
* After pyCertWiz issues or renews a certificate in a keystore (if it is unlocked,
  or the CLI can ask you).
* On demand: `pycert keystore sync [NAME]`, or right-click the keystore in the
  GUI sidebar and choose **Synchronise now**.

To send a *new* request's certificate into the keystore:

```console
$ pycert request web3.example.ac.uk --type host --auth "jane doe" --keystore cakeystore --wait
```

The GUI request wizard has the same choice on its *Key and deployment* page.

## Commands

| Command | Purpose |
|---|---|
| `pycert keystore link PATH [--name N] [--ca CA] [--no-import] [--no-write] [--create]` | link a keystore and import its entries |
| `pycert keystore list` | linked keystores and how many certificates each holds |
| `pycert keystore sync [NAME] [--password-stdin]` | synchronise now (asks for the passphrase) |
| `pycert keystore unlink NAME` | stop synchronising; the file and the certificates are kept |
| `pycert keystore import PATH` | one-off: import every entry without linking |

`--ca` says which CA the keystore's certificates come from (default: the
primary UK e-Science CA), so renewals go to the right place. `--no-import`
keeps the keystore as a write-only destination, `--no-write` treats it as
read-only, and `--create` links a file that does not exist yet (it is
created when pyCertWiz writes the first certificate).

The links are recorded in the configuration:

```toml
[[keystores]]
name = "cakeystore"
path = "/home/jane/.ca/cakeystore.pkcs12"
ca = "uk-escience"
auto_import = true
write_back = true
# There is deliberately no passphrase setting: pyCertWiz asks for it each session.
```

## Keeping the file safe

* **Untouched entries stay byte-for-byte identical.** pyCertWiz edits one entry
  at a time and never decrypts or re-encrypts keys it is not changing. That
  includes entries encrypted under a different passphrase, which are reported
  and preserved.
* New entries use the PBE-SHA1-3DES profile that every Java release, including
  CertWizard's bundled JRE, can read.
* Every write keeps the previous file as `<file>.bak`, preserves the file's
  permissions, is atomic (temporary file and rename), and takes an advisory
  lock.
* pyCertWiz refuses to overwrite a keystore that another program changed while
  pyCertWiz was working on it. The next sync picks up the change instead.
* If writing to the keystore fails after a certificate is issued (keystore
  locked, read-only disk), the certificate is still stored by pyCertWiz, the
  failure is noted on the certificate, and the next sync retries.
* pyCertWiz also keeps its own encrypted copy of each key and certificate. That
  copy holds the request history, the CA status, pending renewal keys and
  deployment targets, and lets pyCertWiz keep working if the keystore is
  temporarily unavailable.

## Formats

PKCS#12 keystores are supported: CertWizard's RC2/3DES files, and modern
keytool or OpenSSL 3 files that use PBES2/AES. A JKS or JCEKS keystore can be
inspected but not linked. Convert it first with the bundle inspector's **Save
as Java PKCS#12…**, or with:

```console
$ keytool -importkeystore -srckeystore old.jks -destkeystore cakeystore.pkcs12 -deststoretype pkcs12
```
