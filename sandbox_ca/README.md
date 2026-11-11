# sandbox_ca — a full mock CA for the Java CertWizard client

This directory contains two things:

* `mock_ca.py` — the protocol-level CA implementation shared with pyCertWiz's test
  suite (real TLS, PPPK, status transitions, fault injection);
* `server.py`, `__main__.py` and `admin.py` — a standalone, persistent sandbox
  with a browser admin console and JSON admin API;
* `java_kit.py` — a patcher that points a built (or source) CertWizard at the
  sandbox and replaces its pinned CA certificates.

It is a test double. It issues certificates without identity proofing and must
never be used as a real CA.

## Quick start

```sh
# 1. Start the sandbox (auto-sign mode is the default).
python3 -m sandbox_ca --data-dir .sandbox-ca --port 8443

# 2. In another terminal, patch a built CertWizard jar.
python3 -m sandbox_ca.java_kit \
  --data-dir .sandbox-ca \
  --jar /path/to/CertWizard-jar-with-dependencies.jar \
  --out /tmp/CertWizard-sandbox.jar

# 3. Check the patched pins/truststore (headless), then run the GUI.
java -jar /tmp/CertWizard-sandbox.jar --self-test
java -jar /tmp/CertWizard-sandbox.jar /tmp/certwizard-sandbox-data
```

Java 25+ is required by the current CertWizard `develop` branch. The patched
client will only trust the sandbox CA; do not use it against the real CA.

## Admin CLI

```sh
python3 -m sandbox_ca.admin --data-dir .sandbox-ca status
python3 -m sandbox_ca.admin --data-dir .sandbox-ca ui
python3 -m sandbox_ca.admin --data-dir .sandbox-ca approve 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca sign 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca reject 1001 --reason "wrong RA"
python3 -m sandbox_ca.admin --data-dir .sandbox-ca requests --limit 50
```

The token is in `.sandbox-ca/sandbox.json` (mode 0600) and is printed at
startup, along with the console URL. Open that URL in a browser to approve,
sign, reject or revoke requests, change validity, inspect captured traffic and
toggle fault modes. The browser will warn that the sandbox CA is not trusted;
accept the exception for `localhost` (or import `root.pem` into the browser's
trust store if you prefer). Admin endpoints are under `/__sandbox__/` on the
same HTTPS port; the CSR/certificate database is `state.json` and survives
restarts.

## ACME v2

```sh
python3 -m sandbox_ca --data-dir .sandbox-ca --acme-port 14000 --acme-challenge-mode auto
```

Point certbot at the printed `https://localhost:14000/acme/directory` (use
`--no-verify-ssl` locally, or trust `.sandbox-ca/root.pem`). The ACME front-end
maps orders to the same CA CSR/sign/download/revoke state and supports
`http-01`, `dns-01`, wildcard, auto and webroot validation. Use
`--acme-eab-kid`/`--acme-eab-hmac-key` for external account binding; ACME
accounts/orders are persisted in `<data-dir>/acme-state.json`. See
[`docs/ACME.md`](../docs/ACME.md) for certbot and nginx examples, and
[`docs/STFC-ACME-MODERNISATION.md`](../docs/STFC-ACME-MODERNISATION.md) for the
wider STFC architecture/policy/migration dossier.

## Headless Java flow

```sh
javac -cp /tmp/CertWizard-sandbox.jar -d /tmp sandbox_ca/java/SandboxFlow.java
java -cp /tmp:/tmp/CertWizard-sandbox.jar SandboxFlow
```

It prints `SANDBOX-FLOW-OK` after user submission, lookup, download, host
request, renewal and revocation.

The full listener contract, state machine, error-document quirk, PPPK details
and compatibility checklist are in
[`docs/CA_LISTENER.md`](../docs/CA_LISTENER.md).

## Notes

* Certificates are issued with the subject in the production CA's order
  (C, O, OU, L, CN), whatever order the CSR used, and the PPPK challenge uses
  the production realm, `UK e-Science CA`.

* The CA hierarchy (and the Java truststore pins) persists in `--data-dir`; the
  TLS leaf is regenerated on each start and is trusted through that hierarchy.
* The CA hierarchy, CSR queue and issued certificates are persisted in
  `--data-dir` (`state.json`), so a restart does not lose a certificate the
  Java client has already downloaded. The `--auto-sign`/`--manual` choice and
  fault modes are process options; pass the desired mode on restart.
* The patched Java URLs embed the listening port. Restart on the same `--port`
  (or repatch the jar) if you want to reuse a previously patched client.
* `state.json` can be removed (or cleared through the console) to reset the RA
  queue; remove the whole `--data-dir` only when you deliberately want a new
  CA (and repatch the Java client).
* `--auto-sign` issues after `--sign-after-polls` status lookups; `--manual`
  leaves approval/signing to the admin CLI.
* Do not bind to a public interface without a strong `--admin-token` and a
  firewall.
* The admin console URL contains the token, so avoid pasting it into shared
  logs or using a shared browser profile.
