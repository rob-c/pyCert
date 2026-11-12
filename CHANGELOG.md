# Changelog

## Unreleased

### Fixed

- The desktop application could hang on Python 3.10 and 3.11 when windows
  were destroyed, for example on quitting or after a first-run setup: Python's
  garbage collector could start inside a Qt destructor and deadlock on Qt's
  own locks. Pending garbage is now collected at a safe point first, and a
  window that fails to open (for example with no configuration yet) leaves
  nothing behind. The packaged builds (Python 3.13) were not affected.

## 2.0.1

### Fixed

- Every request to the UK CA looked up this computer's full name for the
  `LocalHost` header, a reverse DNS lookup that takes seconds where reverse
  DNS is slow. It is now looked up once per run. On GitHub's macOS runners
  this made the test suite crawl until it timed out.

## 2.0.0

**pyCert is now pyCertWiz.** The distribution (`pip install pyCertWiz`), the
application and the GitHub repository (rob-c/pyCertWiz) carry the new name, and
a `pycertwiz` command joins `pycert`. Nothing else moves: the `pycert` command,
the `pycert` Python package, the configuration and data folders
(`~/.config/pycert`, `~/.local/share/pycert`) and the Keychain/Secret Service
entry (`pyCert`) keep their names, so existing installations carry on working.

pyCertWiz becomes a manager for many personal and host certificates from several
CAs, with a new desktop application.

### New

- **Qt desktop application** (`pip install 'pyCertWiz[gui]'`, PySide6). It
  replaces the Tkinter GUI and includes:
  - a sidebar with views and per-CA reachability, summary cards, and
    renewal/unreachable banners;
  - a sortable, searchable table with status pills and days-left bars;
  - a detail panel with Overview, Chain, Deployment and History tabs;
  - a request wizard that adapts to the CA and requests many host names at
    once;
  - background collection of issued certificates, with tray/menu-bar
    notifications;
  - the Java bundle inspector;
  - live light/dark appearance.

  It is tested headless with pytest-qt.
- **Several CAs per configuration.** `[ca]` is the primary profile and
  `[cas.<name>]` tables add more. `default_ca` chooses the profile for new
  requests, and each request records its CA. Manage profiles with
  `pycert ca list|show|default|add-acme|add-ukca|remove|eab` or the GUI
  settings.
- **CA provider interface** (`pycert.providers`). It has two built-in
  providers, `ukca` (the CertWizard protocol, unchanged on the wire) and
  `acme`, plus third-party providers through the `pycert.providers` entry
  point.
- **ACME client** (RFC 8555) on pyCertWiz's hardened transport:
  - accounts, External Account Binding, and http-01 (standalone or webroot)
    or dns-01 (hook or manual) validation;
  - wildcards with dns-01, renewal, revocation, crash-safe resumption of
    orders, and cancellation;
  - tested end to end against the sandbox ACME server.
- **Java keystores as a live store** (`pycert keystore link|list|sync|password|unlink|import`,
  GUI *Link a Java keystore…* and the bundle inspector's *Use as certificate
  store…*):
  - every key entry of a CertWizard `cakeystore.pkcs12` (or a modern keytool or
    OpenSSL keystore) is managed by pyCertWiz;
  - issued and renewed certificates are written back, while other entries stay
    byte-for-byte unchanged;
  - certificates renewed elsewhere are picked up, and CertWizard's pending
    requests are finished by pyCertWiz.
- **Private keys are never written unprotected.** Deployed keys and bundles
  and proxy bundles use the saved secret or a passphrase you choose; exports
  and `~/.globus/userkey.pem` need a new passphrase (see below). A single
  exported key file may be left without a passphrase only after an
  interactive confirmation (type `unencrypted`); bundles never.
- **Exports in many formats, always with a new passphrase**:
  `pycert export --format p12|pem-bundle|pem-files|key|cert|fullchain|der|p7b`
  and `--encryption aes256|3des|pkcs8|traditional`, and an **Export…** dialog
  in the GUI. PKCS#12 with AES-256 is the default. Anything with a private key
  needs a new passphrase of at least 8 characters, entered twice; pyCertWiz's
  saved secret is refused. `pycert install` follows the same rule.
  `pycert export --stored` re-writes pyCertWiz's own copy (the old default
  behaviour). See [docs/EXPORTING.md](docs/EXPORTING.md).
- **Rename certificates**: `pycert edit ALIAS --name NEW`, and **Rename…** (F2)
  in the GUI. With `--rename-keystore-entry`, or the checkbox, the linked
  Java keystore entry is renamed too.
- **Certificate, keys and chain viewer** in the GUI (Ctrl/Cmd+K): the full
  chain with details and PEM, the public key, and the private key on request
  (type `show`; never copied; cleared on close).
- **User/host type is shown** in the certificate list (the Type column is on
  by default) and in the details.
- **Keystore passphrases are never stored.** They are asked for each session
  (the GUI asks at start-up), and locked keystores are reported by
  `pycert check`.
- **Bulk host requests**: `pycert request h1 h2 … --type host` or
  `--from-file hosts.txt`.
- **Deployment targets** (`pycert deploy list|add|remove|run|presets`, and in
  the GUI):
  - presets for grid-host, globus-user, nginx and Apache, or custom
    paths;
  - atomic writes with explicit modes, owner/group, `.bak` backups, symlink
    refusal and reload hooks;
  - automatic re-deployment after issuance and renewal.
- **Monitoring**:
  - `pycert check` is a Nagios/Icinga plugin (exit 0/1/2/3). It reports
    expiry, requests stuck at the RA, failed requests, unverified chains and
    deployment drift.
  - `pycert report` exports an inventory as a table, CSV or JSON.
  - `pycert doctor` now checks deployments and every CA.
- `pycert edit ALIAS --description … --auto-renew/--no-auto-renew`;
  `pycert renew --due` honours the flag and accepts `--ca` and
  `--include-manual`.
- `pycert ping --all` / `--ca`, and `pycert info --ca` (ACME directory
  metadata).
- Optional **`keyring` secret backend** (`pip install 'pyCertWiz[keyring]'`).
- `PYCERT_GUI_SETTINGS` keeps GUI preferences in an INI file;
  `XDG_CONFIG_HOME` is searched for the configuration.
- GitHub Actions CI on Linux and macOS for Python 3.10–3.14. The test suite
  runs in parallel (`pytest -n auto`).
- **Packages** that carry their own Python and Qt: a macOS app in a `.dmg`
  (Apple silicon and Intel), and for Linux an AppImage, `.deb`, `.rpm` and
  Arch package (x86_64 and aarch64), plus a Nix flake. They add a desktop
  entry, and the bundled executable is both the GUI and the command line.
  Each package is installed in clean containers of eleven distributions and
  tested end to end against the sandbox CA, including the GUI on X11. Tagged
  releases are published to GitHub Releases, with checksums and build
  provenance, and to PyPI. See [docs/PACKAGING.md](docs/PACKAGING.md).
- **First-run setup in the GUI.** With no configuration yet, the desktop
  application asks for the e-mail address, RA and where to keep the saved
  secret, and writes the same files as `pycert init`, which now shares its
  code. `pycert gui --check` renders a window once and exits, for package
  tests.

### Changed

- **Renewals start from the CA's record, as in CertWizard.** Before a UK-CA
  renewal pyCertWiz looks the certificate up by its public key. It refuses
  certificates the CA does not report as VALID, or that expired more than 30
  days ago, and checks any e-mail in the name against the one being sent. All
  of this happens before a key is generated. The contact e-mail defaults to
  the one the CA holds (previously the local or configured address); changing
  it is reported. Imported certificates get their record from
  `pycert status --refresh`, **Check now** or the GUI's background check.
- The sandbox CA issues subjects in production order (C, O, OU, L, CN) and
  challenges with the production PPPK realm.

- **Python 3.10+ is required** (was 3.6+). The hand-written TOML parser, the
  dataclasses backport and the compatibility layer have been removed in favour
  of `tomllib`/`tomli`, `dataclasses` and current `cryptography` (≥ 42) APIs.
- Packaging moved to PEP 621 metadata in `pyproject.toml` (`setup.cfg`
  removed). Extras: `gui`, `keyring`, `all`, `dev`.
- Configuration format version 2. Version 1 files load unchanged; `[ca]` gains
  `name` and `display_name`.
- Request state version 2 adds `ca`, `provider`, `deploy`, `auto_renew` and
  `description`. Older state files are read as before.
- Example automation now uses `pycert watch --once` (collect and deploy). New
  examples cover ACME renewal timers, Nagios/NRPE and cron.

### Fixed

- With PySide6 older than 6.10 (for example 6.9 on RHEL/AlmaLinux 8) every
  change of view or search in the GUI failed: Qt 6.9 has `beginFilterChange()`
  but not `endFilterChange()`. Both are now required, with a fallback.
- On current Fedora, pyCertWiz found no system trust anchors: OpenSSL there is
  configured with a hashed CA directory only, which Python does not list. ACME
  chains (Let's Encrypt and others) could therefore not be validated against
  system trust. pyCertWiz now falls back to the distribution's CA bundle
  (`$SSL_CERT_FILE`, then the usual Fedora/RHEL, Debian/Ubuntu/Arch, openSUSE
  and BSD locations).
- A deploy or dns-01 hook whose program is missing or not executable is now
  reported as such ("deploy hook not found", "could not be run (not
  executable)") on every platform; under emulation the exec error could be
  lost, leaving only "exit 127".

- The GUI crashed (segmentation fault) when the appearance changed after the
  new-certificate wizard had been opened and a background CA check had run.
  Wizards and dialogs are now disposed after use instead of living on as
  hidden children of the main window.
- CertWizard's pending-request placeholders (`<CN> CSR cert`) were imported
  as *user* certificates with that CN. A host renewal collected that way
  would have been renewed later with an extra e-mail SAN. The real CN and
  type are now used, and the issued certificate corrects older imports.
- Exporting onto a path that is a folder failed with a raw `IsADirectoryError`;
  write failures are now reported clearly.

- `pycert request --key-algorithm/--rsa-bits/--ec-curve`, and the GUI key
  choice, were silently ignored for new requests; the configuration defaults
  were always used. They are now honoured, and pyCertWiz warns that the UK
  e-Science CA cannot renew EC certificates in place.
- A host request with extra `--san-dns` names no longer omits the host's own
  name from the SANs.
- The GUI's busy indicator could clear before a background result had been
  delivered.
- A PKCS#12 bundle whose certificates are encrypted with PBES2 (modern keytool,
  OpenSSL 3) lost all but its first key entry when re-saved from the bundle
  inspector.
- Writing a file re-moded its existing parent directory to 0700. This affected
  deployment to `/etc/grid-security`, ACME webroots, and `export --out`.
- A failing secret backend (locked keychain, failing password-manager command)
  could make pyCertWiz generate and save a new passphrase.

### Removed

- The Tkinter GUI. `pycert gui` and `pycert-gui` start the Qt application.
- Python 3.6–3.9 support, `tools/check_py36.py` and the `vermin` check.
