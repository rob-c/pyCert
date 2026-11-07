# CertWizard wire fixtures

These `.http` files are copied from the Java CertWizard repository
(`src/test/resources/golden/requests/`) at commit
`db447f5` ("Wire tests: allow the platform line separator inside generated
CSRs").

They were recorded from the original Restlet 3.0-M1 CertWizard implementation
and are the reference used by Java's `WireCompatibilityTest`.  The placeholders
(`${DATE}`, `${PORT}`, `${LOCALHOST}`, `${PPPK_RESPONSE}`,
`${RANDOM_PIN_HASH}`) are expanded by the test helpers in
`tests/test_certwizard_wire_parity.py`.

The fixtures are GPL-2.0-or-later, like both projects.
