"""Parity tests: pyCertWiz's CA requests match real CertWizard's golden wire fixtures.

The Java project records every request it sends in
``src/test/resources/golden/requests``.  These tests drive pyCertWiz through the
same application operations against the mock CA and compare the captured
requests after removing only transport/identity differences (framing,
User-Agent, compression negotiation and connection management).

The live Java-vs-pyCertWiz differential test at the bottom is opt-in: set
``CERTWIZARD_JAR`` (and optionally ``JAVA_HOME``/``JAVA_BIN``) to run the real
Java client against the same listener.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from certwizard_wire import (
    FIXTURES,
    assert_request_matches,
    canonical_path,
    canonical_request,
    load_fixtures,
    parse_fixture,
)

from pycert.workflow import RequestSpec, create_request, download_and_export, renew, revoke

PIN = "1234567890AB"
USER_EMAIL = "golden.test@example.org"
HOST_EMAIL = "host.admin@example.org"


def _issue_user(e2e, *, cn="golden test user", email=USER_EMAIL, wait=True):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    spec = RequestSpec.build(
        e2e.config,
        cn,
        email=email,
        pin=PIN,
        key_algorithm="rsa",
    )
    return create_request(e2e.ctx, spec, wait=wait, timeout=30, interval=0.05)


def _assert_captured(e2e, scenario):
    expected = load_fixtures(scenario)
    # create_request()/renew() perform a connectivity ping before submitting.
    # That is a pyCertWiz safety feature, not part of the CA operation under test;
    # keep only the paths named by this scenario's golden fixtures.
    wanted_paths = {canonical_path(item.path) for item in expected}
    actual = [item for item in e2e.ca.captured if canonical_path(item.path) in wanted_paths]
    assert len(actual) == len(expected), (
        "%s: expected %d request(s), captured %d (%s)"
        % (scenario, len(expected), len(actual), [item.path for item in actual])
    )
    for index, (request, fixture) in enumerate(zip(actual, expected), start=1):
        assert_request_matches(request, fixture, label="%s.%d" % (scenario, index))


def _clear(e2e):
    e2e.ca.captured.clear()


def test_every_golden_fixture_has_a_valid_application_shape():
    fixtures = sorted(FIXTURES.glob("*.http"))
    assert fixtures
    for path in fixtures:
        request = parse_fixture(path.read_text())
        canonical_request(request)


def test_ping_request_matches_certwizard(e2e):
    _clear(e2e)
    assert e2e.ctx.client().ping() is True
    _assert_captured(e2e, "ping")


def test_ping_with_empty_localhost_matches_certwizard(e2e):
    # The value is environment-specific; the canonical comparison checks that
    # the header is present, including the empty-value case in Java's fixture.
    _clear(e2e)
    assert e2e.ctx.client().ping() is True
    _assert_captured(e2e, "null-localhost")


def test_motd_request_matches_certwizard(e2e):
    _clear(e2e)
    assert e2e.ctx.client().motd()
    _assert_captured(e2e, "motd-text")


def test_ca_info_request_matches_certwizard(e2e):
    _clear(e2e)
    e2e.ctx.client().info()
    _assert_captured(e2e, "ca-info")
    # The same GET /CA is used by CAMotd.getLatestVersion(); its golden fixture
    # omits the optional PPPK header, which canonicalisation permits on GET.
    _clear(e2e)
    e2e.ctx.client().info()
    _assert_captured(e2e, "ca-latest-version")


def test_public_key_lookup_request_matches_certwizard(e2e):
    state = _issue_user(e2e)
    _clear(e2e)
    e2e.ctx.client().lookup_public_key(state.active_spki_b64)
    _assert_captured(e2e, "public-key-lookup")


def test_certificate_download_request_matches_certwizard(e2e):
    state = _issue_user(e2e)
    _clear(e2e)
    assert e2e.ctx.client().download_certificate(str(state.server.cert_id))
    _assert_captured(e2e, "certificate-download")


def test_user_csr_request_matches_certwizard(e2e):
    _clear(e2e)
    _issue_user(e2e, cn="golden test user", wait=False)
    _assert_captured(e2e, "csr-user")


def test_host_csr_request_matches_certwizard(e2e):
    user = _issue_user(e2e)
    _clear(e2e)
    spec = RequestSpec.build(
        e2e.config,
        "host.sandbox.test",
        type="host",
        auth_alias=user.alias,
        email=HOST_EMAIL,
        pin=PIN,
        key_algorithm="rsa",
    )
    create_request(e2e.ctx, spec, wait=False)
    _assert_captured(e2e, "csr-host-pppk")


def test_renewal_request_matches_certwizard(e2e):
    user = _issue_user(e2e)
    _clear(e2e)
    renew(e2e.ctx, user.alias, pin=PIN, email=USER_EMAIL, wait=False)
    _assert_captured(e2e, "renew-pppk")


def test_revocation_request_matches_certwizard(e2e):
    user = _issue_user(e2e)
    _clear(e2e)
    revoke(e2e.ctx, user.alias, "keyCompromise")
    _assert_captured(e2e, "revoke-pppk")


def test_opaque_renewal_request_matches_certwizard(e2e):
    user = _issue_user(e2e)
    e2e.ca.pppk_mode = "opaque"
    _clear(e2e)
    renew(e2e.ctx, user.alias, pin=PIN, email=USER_EMAIL, wait=False)
    _assert_captured(e2e, "renew-opaque")
    e2e.ca.pppk_mode = "normal"


def test_opaque_revocation_request_matches_certwizard(e2e):
    user = _issue_user(e2e)
    e2e.ca.pppk_mode = "opaque"
    _clear(e2e)
    revoke(e2e.ctx, user.alias, "superseded")
    _assert_captured(e2e, "revoke-opaque")
    e2e.ca.pppk_mode = "normal"


# ---------------------------------------------------------------------------
# Optional live differential: real Java CertWizard vs pyCertWiz
# ---------------------------------------------------------------------------


def _command_works(command):
    try:
        return subprocess.run(
            [command, "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _java_tools():
    jar = os.environ.get("CERTWIZARD_JAR")
    if not jar:
        default = Path.home() / "src" / "CertWizard" / "target" / "CertWizard-jar-with-dependencies.jar"
        jar = str(default) if default.exists() else None
    candidates = [
        os.environ.get("JAVA_BIN"),
        shutil.which("java"),
        str(Path(os.environ.get("JAVA_HOME", "")) / "bin" / "java") if os.environ.get("JAVA_HOME") else None,
        "/opt/homebrew/opt/openjdk/bin/java",
    ]
    java = next((item for item in candidates if item and Path(item).exists() and _command_works(item)), None)
    javac_candidates = [
        os.environ.get("JAVAC_BIN"),
        str(Path(java).parent / "javac") if java else None,
        shutil.which("javac"),
        "/opt/homebrew/opt/openjdk/bin/javac",
    ]
    javac = next(
        (item for item in javac_candidates if item and Path(item).exists() and _command_works(item)),
        None,
    )
    if not jar or not Path(jar).exists() or not java or not javac:
        pytest.skip("set CERTWIZARD_JAR and provide a working java/javac to run the live Java differential")
    return Path(jar), java, javac


def _sandbox_client(tmp_path):
    """A SandboxCA plus a pyCertWiz context configured to trust it."""
    from pycert.config import ChainEntry, init_config, load_config, write_config
    from pycert.workflow import AppContext
    from sandbox_ca.server import SandboxCA

    ca = SandboxCA(
        data_dir=tmp_path / "sandbox",
        port=0,
        auto_approve=True,
        sign_after_polls=0,
        admin_token="parity",
    )
    confdir = tmp_path / "conf"
    confdir.mkdir()
    config = init_config(confdir, copy_chain=False)
    pins = ca.chain_files(confdir / "chain")
    config.chain = [
        ChainEntry(label=name, file="chain/" + name, sha256=pin) for name, pin in pins.items()
    ]
    config.ca.base_url = ca.url
    config.ca.retries = 0
    config.ca.timeout = 10.0
    config.identity.email = "java.sandbox@example.org"
    config.identity.ra = "CLRC DL"
    config.paths.data_dir = str(tmp_path / "data")
    config.secrets.backend = "file"
    config.keys.rsa_bits = 2048
    write_config(config.path, config)
    config = load_config(config.path)
    return ca, config, AppContext.from_config(config)


@pytest.mark.skipif(
    not (
        os.environ.get("CERTWIZARD_JAR")
        or (Path.home() / "src" / "CertWizard" / "target" / "CertWizard-jar-with-dependencies.jar").exists()
    ),
    reason="real CertWizard jar is not available",
)
def test_real_java_and_pycert_send_the_same_application_requests(tmp_path):
    """Run both clients against one listener and compare their request shapes.

    Java's SandboxFlow does a complete user -> host -> renewal -> revocation
    lifecycle.  pyCertWiz is driven through the same operations, and every capture
    is canonicalised by endpoint; the two multisets must be equal.  The
    connectivity pings that pyCertWiz adds before submissions are filtered out
    because Java's flow does not make them.
    """
    from types import SimpleNamespace

    from sandbox_ca.java_kit import build_jar_kit

    jar, java, javac = _java_tools()
    ca, config, ctx = _sandbox_client(tmp_path)
    try:
        patched = tmp_path / "CertWizard-sandbox.jar"
        build_jar_kit(jar, patched, ca.info())
        compiled = tmp_path / "classes"
        compiled.mkdir()
        flow = Path(__file__).parent.parent / "sandbox_ca" / "java" / "SandboxFlow.java"
        subprocess.run(
            [javac, "-cp", str(patched), "-d", str(compiled), str(flow)],
            check=True,
            capture_output=True,
            text=True,
        )
        ca.captured.clear()
        subprocess.run(
            [java, "-cp", str(compiled) + os.pathsep + str(patched), "SandboxFlow"],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        java_requests = [
            canonical_request(_as_wire(item))
            for item in ca.captured
            if canonical_path(item.path) != "/pingservice"
        ]

        # Drive pyCertWiz through the same lifecycle.
        ca.captured.clear()
        e2e = SimpleNamespace(ca=ca, config=config, ctx=ctx)
        user = _issue_user(e2e, cn="java sandbox user", email="java.sandbox@example.org", wait=False)
        lookup = ctx.client().lookup_public_key(user.active_spki_b64)
        assert lookup.latest_certificate is not None
        user_cert = lookup.latest_certificate.certificate()
        assert user_cert is not None
        download_and_export(
            ctx, user, certificate=user_cert, cert_id=lookup.latest_certificate.id, export=False
        )
        ctx.client().download_certificate(lookup.latest_certificate.id)

        host_spec = RequestSpec.build(
            config,
            "host.sandbox.test",
            type="host",
            auth_alias=user.alias,
            email="java.sandbox@example.org",
            pin=PIN,
            key_algorithm="rsa",
        )
        host = create_request(ctx, host_spec, wait=False)
        ctx.client().lookup_public_key(host.active_spki_b64)

        renewed = renew(ctx, user.alias, pin=PIN, email="java.sandbox@example.org", wait=False)
        renewal_lookup = ctx.client().lookup_public_key(renewed.active_spki_b64)
        assert renewal_lookup.latest_certificate is not None
        renewal_cert = renewal_lookup.latest_certificate.certificate()
        assert renewal_cert is not None
        download_and_export(
            ctx,
            renewed,
            certificate=renewal_cert,
            cert_id=renewal_lookup.latest_certificate.id,
            export=False,
        )
        revoke(ctx, user.alias, "keyCompromise")

        pycert_requests = [
            canonical_request(_as_wire(item))
            for item in ca.captured
            if canonical_path(item.path) != "/pingservice"
        ]
        assert sorted(map(repr, java_requests)) == sorted(map(repr, pycert_requests)), (
            "Java requests:\n%s\npyCert requests:\n%s"
            % ("\n".join(map(repr, java_requests)), "\n".join(map(repr, pycert_requests)))
        )
    finally:
        ca.stop()


def _as_wire(captured):
    from certwizard_wire import WireRequest

    return WireRequest(captured.method, captured.path, captured.headers, captured.body)
