# The GUI

```console
$ pycert gui
```

The window is laid out for the job: certificates on the left, details on the
right, and the actions you actually use on a toolbar.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ pyCert   profile default · https://cwiz-live.ca.ngs.ac.uk:443   CA online    │
├──────────────────────────────────────────────────────────────────────────────┤
│ [New request] [Refresh] [Wait for signing] [Download & export] [Re-export]   │
│ [Verify] │ [Renew...] [Revoke...] [Open folder]                    [Settings]│
├───────────────────────────────┬──────────────────────────────────────────────┤
│ ALIAS            TYPE STATUS  │ Overview │ Certificate │ History             │
│ jane doe         user DOWN…   │ Status        DOWNLOADED                     │
│ host.example.org host SUBM…   │ Common name   jane doe                       │
│                               │ Subject       C=UK,O=eScience,OU=CLRC,…      │
│                               │ Issuer        CN=UK e-Science CA 2B,…         │
│                               │ Validity      2026-11-06 .. 2027-11-06       │
│                               │ Days left     364                            │
│                               │ Key           RSA 3072                       │
│                               │ SANs          email:jane@example.org         │
│                               │ Chain verified yes                           │
│                               │ PKCS#12       …/jane_doe.p12                 │
│                               │                                              │
│                               │ [Verify] [Copy fingerprint] [Open folder]    │
├───────────────────────────────┴──────────────────────────────────────────────┤
│ Activity log                                                    [Copy][Clear] │
│ 14:02:11  CSR submitted; awaiting RA approval and CA signing                 │
│ 14:02:11  PIN for the RA: K7QF-2M9X-P4RT  (shown in a dialog, not logged)    │
├──────────────────────────────────────────────────────────────────────────────┤
│ Ready                                                  [progress]  server URL │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Appearance

The GUI follows the operating-system appearance at startup and while running.
Use **View → Appearance → System / Light / Dark** to override it. For automated
or remote launches, set `PYCERT_THEME=light`, `PYCERT_THEME=dark` or
`PYCERT_THEME=system`.

The theme covers ttk widgets, the certificate details, activity log, wait
dialog log and PIN field. In dark mode the log and certificate panes use a
dark text background with readable foreground and selection colours instead of
white blocks. System detection uses macOS `defaults`, the Windows personalise
registry key, or GTK/gsettings/terminal colour hints on Linux.

## Certificate list

* **Alias / common name**, type, pyCert status, expiry date, days remaining and
  whether a `.p12` exists.
* Rows are colour-coded by status *and* labelled: pending (amber), valid
  (green), expiring within 30 days (orange), expired (red), revoked (purple),
  failed (red). Colour is never the only signal.
* Click a column heading to sort; click again to reverse.
* The selection drives the details pane and which buttons are enabled.
* Double-click opens the Certificate tab.

## Details

**Overview** shows what you need before using a certificate:

| Field | Meaning |
|---|---|
| Status | pyCert state (`SUBMITTED`, `APPROVED`, `SIGNED`, `DOWNLOADED`, …) |
| Common name / subject / issuer | as issued |
| Validity / days remaining | local time is not used here; dates are UTC days |
| Key | algorithm and size, never the key itself |
| Serial, SHA-256 | certificate identifiers |
| SANs | DNS names, e-mail addresses, IPs |
| Chain verified | result of the last verification |
| PKCS#12 / Directory | absolute paths, click “Open folder” to reveal them |
| CA state | CSR id, certificate id, server status, last poll |
| Notes | chain problems, CN differences and other warnings |

**Certificate** renders everything from the certificate (subject, issuer, serial,
validity, key, signature algorithm, SHA-256, basic constraints, key usage, EKU,
SANs, AIA/CRL URLs, SKI/AKI) plus the full chain with per-certificate expiry and
fingerprints, and the file locations. PEM bodies are intentionally not shown in
this request view; the separate bundle inspector shows public certificate PEM
only.

**History** is the audit trail pyCert recorded: submission, status changes,
download, export, renewal, revocation, with timestamps and details.

## Actions

| Action | What it does |
|---|---|
| **New request** | Opens the request dialog (below). |
| **Refresh** | Re-reads the local store (no network). |
| **Wait for signing** | Polls the CA (default every 20 s) in a dialog with live progress; **Cancel** stops cleanly. |
| **Download & export** | Fetches an issued certificate, verifies the chain and writes the `.p12`. |
| **Re-export .p12** | Writes the bundle again with the saved secret (e.g. after changing the filename template). |
| **Verify** | Runs the same checks as `pycert verify` and shows a pass/fail list. |
| **Renew** | Creates a new key and a PPPK-authenticated renewal; offers to wait immediately. |
| **Revoke** | Reason picker plus an explicit confirmation checkbox. |
| **Open folder** | Reveals the request directory in Finder/Explorer/desktop. |
| **Java bundle...** | Opens the bundle viewer/editor from the toolbar. |
| **Bundles → Open old Java bundle...** | Opens a legacy Java/PKCS#12/PEM bundle with save and update actions. |

### Inspecting a legacy Java bundle

The **Java bundle** tab on the right is a permanent starting point with
**Open old Java bundle...**, **Save all certs (PEM)...**, **Save all certs
(Java PKCS#12)...** and **Update open Java bundle...** buttons. The same actions
are available from **Bundles**, **File → Open old Java bundle...**, the
**Java bundle...** toolbar button, or `Cmd/Ctrl+B`. The tab or button opens a
viewer for:

* CertWizard `cakeystore.pkcs12` / `.p12` / `.pfx` files;
* Java JKS and JCEKS trust stores (`.jks`, `.keystore`, `.jceks`);
* PEM, DER and PKCS#7 certificate bundles.

Select the file, enter the passphrase if the bundle is encrypted, and press
**Decode**. The table lists every certificate with its role (`leaf`, `chain`,
`trusted` or `certificate`), subject, issuer, expiry, key, SHA-256 fingerprint
and Java alias where available. Selecting a row shows the decoded fields and
the public certificate PEM.

The viewer never displays private keys. **Copy selected PEM**, **Copy all PEM**
and **Save all certs (PEM)...** operate on certificates only. The **Bundles**
menu repeats these actions and reports that a bundle must be opened first if
none is active.

**Save all certs (Java PKCS#12)...** writes a new bundle containing every certificate and,
when available, the original private key. It uses the legacy
PBE-SHA1-3DES/SHA-1 profile for compatibility with old Java CertWizard/keytool.
For CertWizard's multi-entry `cakeystore.pkcs12`, every raw key bag, alias and
localKeyID is preserved. Because those key bags stay encrypted with the source
passphrase, Save and Update use the passphrase entered to open the bundle rather
than prompting for a new one.

**Update Java bundle...** rewrites an existing PKCS#12 in place after creating a
`<name>.pkcs12.bak` backup. In-place update is intentionally not offered for
JKS/JCEKS, whose private-key protection pyCert does not reproduce; read those
and save a new Java PKCS#12 or PEM instead. **File → Import PKCS#12...** remains
the separate action for adding a key and certificate to pyCert's own store.

A real CertWizard file may use BER indefinite lengths and RC2-40 for the
certificate SafeContents. The raw keystore reader handles this; if the linked
OpenSSL does not expose legacy RC2, pyCert uses the local `openssl enc` legacy
fallback. A passphrase is required to decrypt the certificate contents.

JKS integrity is verified when a password is supplied; without one, the
certificates are still shown with a warning.

### New request dialog

* **Personal** or **Host** certificate. Host requests require choosing an
  existing valid certificate to authenticate the request (PPPK).
* Common name validation happens before anything is sent: host names must be
  fully qualified DNS names, personal names must contain at least two words,
  ASCII only (the RA’s rule), e-mail must look like an e-mail.
* **RA** is a combo box. **Fetch from CA** fills it from `/CA` (the preferred RA
  is listed by the server; the default comes from the configuration).
* **Organisation** fields prefill from the configuration and feed the subject
  (OU, L, O, C).
* **Key**: RSA 2048/3072/4096 or ECDSA P-256/384/521.
* **Extra SANs**: comma-separated DNS names, IPs or e-mail addresses.
* **PIN**: generate (default) or type your own; at least 10 characters; show/hide
  toggle; the generated PIN appears once in a modal dialog afterwards.
* **Wait for signing and export** is on by default.
* Errors stay in the dialog so you can correct the form without retyping.

## Settings

* **Server**: base URL, timeout, retries, TLS verification, trust source
  (`chain`/`system`/`both`), plaintext and SHA-1 opt-ins.
* **Identity**: O, OU, L, C, e-mail, default RA.
* **Keys & CSR**: algorithm, RSA bits, EC curve, CSR hash, PIN hash, requested
  extensions, PKCS#12 filename template and directory, include-chain toggle.
* **Secrets**: backend, service/account names, external command, backend test.
* **CA chain**: the certificates pyCert will trust, with expiry and SHA-256, plus
  **Add PEM file…** and **Remove selected**. New files are copied into
  `chain/` next to the configuration and pinned automatically.

Saving validates everything (including the chain pins) before writing; a bad
setting produces an error dialog and nothing is changed.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl/Cmd+N` | New request |
| `Ctrl/Cmd+R` | Refresh list |
| `Ctrl/Cmd+E` | Re-export `.p12` |
| `Ctrl/Cmd+B` | Open old Java bundle |
| `Ctrl/Cmd+Q` | Quit |
| `Enter` | Confirm in dialogs |
| `Esc` | Close a dialog |

## Behaviour notes

* Everything that touches the network or the disk runs in a worker thread; the
  window stays responsive and the progress bar is active while work is ongoing.
* The activity log is bounded (about 400 lines) and kept in memory only.
* Closing the window cancels a wait cooperatively; an in-flight HTTP request is
  allowed to time out (default 30 s).
* Starting the GUI pings the CA once and shows “CA online” or “CA unreachable”
  in the header. Use **Tools → Ping the CA** to retry, and **Tools → Run
  diagnostics (doctor)** for a full configuration/chain/TLS/permissions report.
* The GUI uses the same configuration, store and secret backend as the CLI, so
  you can start a request in one and finish it in the other.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| “Cannot start pyCert” on launch | no configuration; run `pycert init` or pass `--config` |
| “CA unreachable” | network/proxy, or `ca.base_url` wrong; try `pycert ping` |
| “No secret stored” when exporting | run `pycert secret set` or let the GUI generate one (it does on first export) |
| Chain not verified | missing intermediate; add it in Settings → CA chain, or check AIA connectivity |
| Wait dialog never completes | the RA has not approved yet; `pycert status --refresh` shows the server status |
| Rows missing after an import | press Refresh (the store is re-read on demand) |
