# sandbox_ca — a CA listener for the Java CertWizard client

This directory contains two things:

* `mock_ca.py` — the protocol-level CA implementation shared with pyCert's test
  suite (real TLS, PPPK, status transitions, fault injection);
* `server.py`, `__main__.py` and `admin.py` — a standalone, persistent sandbox
  with an admin API;
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
python3 -m sandbox_ca.admin --data-dir .sandbox-ca approve 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca sign 1001
python3 -m sandbox_ca.admin --data-dir .sandbox-ca requests --limit 50
```

The token is in `.sandbox-ca/sandbox.json` (mode 0600) and is printed at
startup. Admin endpoints are under `/__sandbox__/` on the same HTTPS port.

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

* The CA hierarchy (and the Java truststore pins) persists in `--data-dir`; the
  TLS leaf is regenerated on each start and is trusted through that hierarchy.
* Issued requests/certificates are held in memory and are lost on restart;
  restarting is cheap, but resubmit if the Java client is still pointing at a
  certificate from a previous run.
* `--auto-sign` issues after `--sign-after-polls` status lookups; `--manual`
  leaves approval/signing to the admin CLI.
* Do not bind to a public interface without a strong `--admin-token` and a
  firewall.
