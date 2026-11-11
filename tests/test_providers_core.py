"""The provider interface, the plugin registry and multi-CA workflow dispatch."""

from types import SimpleNamespace

import pytest

from pycert import providers, workflow
from pycert.ca import CAClient
from pycert.config import CAConfig, CAProfile, new_acme_profile, new_ukca_profile, validate_config
from pycert.errors import CAError, ConfigError, PyCertError
from pycert.providers.base import (
    Capabilities,
    CAProvider,
    PingResult,
    PollOutcome,
    SubmitResult,
    timed_ping,
)


class _Minimal(CAProvider):
    """A provider that only implements the abstract methods."""

    kind = "minimal-user"
    label = "Minimal"
    capabilities = Capabilities(user_certificates=True, host_certificates=False, revoke=False)
    reachable = True

    def ping(self, *, stop_event=None):
        return PingResult(ok=self.reachable, latency_ms=1.0, detail="" if self.reachable else "refused", url=self.url)

    def submit(self, state, csr, spec, *, prepared=None, progress=None, on_pin=None, stop_event=None):
        return SubmitResult(True, "accepted")

    def submit_renewal(self, state, csr, **kwargs):
        return SubmitResult(True, "renewal accepted")

    def poll(self, state, *, progress=None, stop_event=None):
        return PollOutcome(state, "NEW", True, "waiting")


class _HostOnly(_Minimal):
    kind = "minimal-host"
    capabilities = Capabilities(user_certificates=False, host_certificates=True)


@pytest.fixture
def plugin_kinds():
    providers.register(_Minimal.kind, _Minimal)
    providers.register(_HostOnly.kind, _HostOnly)
    yield
    providers.unregister(_Minimal.kind)
    providers.unregister(_HostOnly.kind)


def _add(config, name, kind, url="https://plugin.example.org"):
    profile = CAProfile(None, name, kind=kind, display_name=name.title(), ca=CAConfig(base_url=url, tls_trust="system"))
    config.add_ca(profile)
    validate_config(config)
    return profile


# ---------------------------------------------------------------------------
# Registry and plugins
# ---------------------------------------------------------------------------


def test_registry_register_unregister_and_unknown(plugin_kinds):
    assert {"ukca", "acme", "minimal-user"} <= providers.known_kinds()
    assert providers.provider_class("minimal-user") is _Minimal
    assert providers.capabilities_for("minimal-host").user_certificates is False
    providers.unregister("minimal-user")
    assert "minimal-user" not in providers.known_kinds()
    with pytest.raises(ConfigError, match="unknown CA kind 'minimal-user'"):
        providers.provider_class("minimal-user")
    providers.unregister("never-registered")  # harmless


def test_entry_point_plugins_are_discovered(monkeypatch):
    entry = SimpleNamespace(name="plugin-ca", load=lambda: _Minimal)
    monkeypatch.setattr(providers, "_entry_points", lambda: {"plugin-ca": entry})
    assert "plugin-ca" in providers.known_kinds()
    assert providers.provider_class("plugin-ca") is _Minimal


def test_real_entry_point_scan_is_cached_and_harmless():
    providers._entry_points.cache_clear()
    found = providers._entry_points()
    assert isinstance(found, dict)
    assert providers._entry_points() is found


def test_unknown_kind_in_configuration_is_rejected(config):
    profile = CAProfile(None, "mystery", kind="mystery", ca=CAConfig(base_url="https://x.example.org"))
    config.add_ca(profile)
    with pytest.raises(ConfigError, match="unknown CA kind 'mystery'"):
        validate_config(config)


# ---------------------------------------------------------------------------
# Base class defaults
# ---------------------------------------------------------------------------


def test_base_provider_defaults(ctx, config, plugin_kinds):
    _add(config, "people", "minimal-user")
    provider = ctx.provider("people")
    assert isinstance(provider, _Minimal)
    described = provider.describe()
    assert described["name"] == "people" and described["kind"] == "minimal-user"
    assert described["capabilities"]["host_certificates"] is False
    assert provider.preflight(SimpleNamespace()) is None
    assert provider.info() == {}
    assert provider.forget(object()) is None
    with pytest.raises(PyCertError, match="does not support revocation"):
        provider.revoke(object(), "unspecified", certificate=None, key=None)
    provider.reachable = False
    with pytest.raises(CAError, match="cannot reach the CA server at https://plugin.example.org .refused."):
        provider.ensure_reachable()
    spec = SimpleNamespace(type="host", auth_alias="", cn="x")
    with pytest.raises(PyCertError, match="only issues personal certificates"):
        provider.validate_request(spec)
    with pytest.raises(PyCertError, match="does not authenticate"):
        provider.validate_request(SimpleNamespace(type="user", auth_alias="someone"))
    host_only = _HostOnly(ctx, provider.profile)
    with pytest.raises(PyCertError, match="only issues host certificates"):
        host_only.validate_request(SimpleNamespace(type="user", auth_alias=""))


def test_result_objects_serialise():
    tls = SimpleNamespace(as_dict=lambda: {"subject": "CN=x"})
    assert PingResult(ok=True, latency_ms=12.345, detail="", tls=tls, url="u").as_dict() == {
        "ok": True,
        "latency_ms": 12.3,
        "detail": "",
        "url": "u",
        "tls": {"subject": "CN=x"},
    }
    assert PingResult(ok=False).as_dict()["tls"] is None
    assert SubmitResult(False, "no", "detail", 403).as_dict() == {
        "success": False,
        "message": "no",
        "detail": "detail",
        "status": 403,
    }
    caps = Capabilities().as_dict()
    assert caps["revocation_reasons"][0] == "unspecified"
    result = timed_ping(lambda: (True, "fine", None), "https://ca.example.org")
    assert result.ok and result.detail == "fine" and result.url == "https://ca.example.org" and result.latency_ms >= 0


# ---------------------------------------------------------------------------
# Workflow dispatch for providers with other capabilities
# ---------------------------------------------------------------------------


def test_requests_are_checked_against_capabilities(ctx, config, plugin_kinds):
    _add(config, "people", "minimal-user")
    with pytest.raises(PyCertError, match="only issues personal certificates"):
        workflow.RequestSpec.build(config, "host.example.org", type="host", ca="people")
    spec = workflow.RequestSpec.build(config, "Jane Doe", ca="people", pin="1234567890AB")
    assert spec.ca == "people" and spec.pin == ""  # this CA does not use RA PINs


def test_revocation_needs_a_capable_provider(ctx, config, plugin_kinds):
    _add(config, "people", "minimal-user")
    state = ctx.store.new_state(alias="plugin user", type="user", cn="plugin user", email="x@example.org")
    state.ca = "people"
    ctx.store.save(state)
    with pytest.raises(PyCertError, match="does not support revocation"):
        workflow.revoke(ctx, "plugin user")


def test_acme_profiles_take_wildcards_and_refuse_user_and_auth(ctx, config):
    config.add_ca(new_acme_profile("public", "https://acme.example.org/directory", contact=["ops@example.org"]))
    validate_config(config)
    spec = workflow.RequestSpec.build(config, "*.Example.org", type="host", ca="public", san_dns=["www.example.org"])
    assert spec.cn == "*.example.org"
    assert spec.san_dns == ["*.example.org", "www.example.org"]  # the CN is always a SAN, first
    assert spec.o == spec.ou == spec.ra == ""  # ACME subjects carry only the CN
    with pytest.raises(PyCertError, match="only issues host certificates"):
        workflow.RequestSpec.build(config, "Jane Doe", type="user", ca="public")
    with pytest.raises(PyCertError, match="does not authenticate"):
        workflow.RequestSpec.build(config, "web.example.org", type="host", ca="public", auth_alias="jane doe")
    with pytest.raises(ConfigError, match="not a CertWizard-protocol CA"):
        ctx.client("public")
    with pytest.raises(PyCertError, match="does not use Registration Authorities"):
        workflow.list_ras(ctx, "public")


def test_host_spec_gains_its_own_name_as_first_san(config):
    spec = workflow.RequestSpec.build(
        config, "web.example.org", type="host", auth_alias="someone", san_dns=["alias.example.org"]
    )
    assert spec.san_dns == ["web.example.org", "alias.example.org"]


def test_public_key_match_helper(ctx, issued):
    state = issued("key match person")
    certificate = ctx.store.load_certificate(state)
    assert workflow._public_key_matches(certificate, state, ctx) is True
    state.spki_b64 = "different"
    assert workflow._public_key_matches(certificate, state, ctx) is False


# ---------------------------------------------------------------------------
# UK-CA provider on a second (non-primary) profile
# ---------------------------------------------------------------------------


@pytest.fixture
def second(config, ca):
    profile = new_ukca_profile("second", ca.url, display_name="Second UK-CA", chain=list(config.chain))
    profile.ca.retries = 0
    config.add_ca(profile)
    validate_config(config)
    return profile


def test_second_ukca_profile_uses_its_own_client(ctx, second, monkeypatch):
    provider = ctx.provider("second")
    client = provider.client()
    assert isinstance(client, CAClient) and client.config is second
    assert isinstance(ctx.client("second"), CAClient)
    assert provider.ping().ok
    info = provider.info()
    assert info["ras"] and "motd" in info and info["certificates"]
    assert [ra.label for ra in provider.ras()] == info["ras"]
    monkeypatch.setattr(CAClient, "motd", lambda self: (_ for _ in ()).throw(PyCertError("no motd")))
    assert provider.info()["motd"] == ""
    anchors = ctx.anchors("second")
    assert anchors and ctx.build_chain(anchors[0], "second").chain


def test_ukca_provider_validation_messages(ctx):
    provider = ctx.provider("")
    with pytest.raises(PyCertError, match="must be authenticated"):
        provider.validate_request(SimpleNamespace(type="host", auth_alias="", ou="CLRC", l="DL"))
    with pytest.raises(PyCertError, match="an RA is required"):
        provider.validate_request(SimpleNamespace(type="user", auth_alias="", ou="", l=""))
