"""Named CA profiles: live views, management, dotted settings and the [cas.*] TOML schema."""

import pytest

from pycert.config import (
    IdentityConfig,
    default_config_paths,
    load_config,
    new_acme_profile,
    new_ukca_profile,
    validate_config,
    write_config,
)
from pycert.errors import ConfigError


def _chain_toml(config, prefix):
    blocks = []
    for entry in config.chain:
        blocks.append(f'\n[[{prefix}]]\nlabel = "{entry.label}"\nfile = "{entry.file}"\nsha256 = "{entry.sha256}"\n')
    return "".join(blocks)


def _write(config, tmp_path, extra, name="profiles.toml"):
    path = config.path.parent / name
    path.write_text(config.path.read_text() + extra)
    return path


# ---------------------------------------------------------------------------
# Live views and management
# ---------------------------------------------------------------------------


def test_primary_profile_is_a_live_view(config):
    primary = config.primary_profile
    assert primary.primary and primary.name == config.ca.name == config.default_ca
    assert primary.config is config and primary.csr is config.csr and primary.identity is config.identity
    assert primary.own_identity is None and primary.directory_url == config.ca.base_url
    assert primary.contact_emails() == [config.identity.email]
    primary.display_name = "Renamed CA"
    assert config.ca.display_name == "Renamed CA" and primary.display_name == "Renamed CA"
    bundle = primary.bundle
    assert bundle is config.bundle
    primary.chain = config.chain[:1]
    assert len(config.chain) == 1 and config.bundle is not bundle  # cache invalidated
    data = primary.as_dict()
    assert data["primary"] is True and "chain" not in data and "acme" not in data
    assert config.default_profile() is primary


def test_extra_profiles_own_identity_chain_and_bundle_cache(config):
    identity = IdentityConfig(ou="PPD", l="RAL", email="hosts@example.org")
    second = new_ukca_profile("second", "https://second.example.org", display_name="", chain=list(config.chain), identity=identity)
    config.add_ca(second)
    assert second.identity is identity and second.own_identity is identity
    assert second.display_name == "second"  # falls back to the name
    second.display_name = "Second CA"
    assert second.display_name == "Second CA"
    bundle = second.bundle
    assert bundle.anchors and second.bundle is bundle
    second.invalidate()
    assert second.bundle is not bundle
    second.chain = config.chain[:1]
    assert len(second.chain) == 1 and len(config.chain) > 1 and len(second.bundle.anchors) == 1
    config.default_ca = "second"
    assert config.default_profile() is second
    assert [item["file"] for item in second.as_dict()["chain"]] == [entry.file for entry in second.chain]
    acme = new_acme_profile("public", "https://acme.example.org/directory", contact=["ops@example.org"])
    config.add_ca(acme)
    assert acme.as_dict()["acme"]["contact"] == ["ops@example.org"]
    assert acme.contact_emails() == ["ops@example.org"]
    assert not acme.tls_trust_pem() and acme.use_system_trust()


def test_profile_lookup_add_and_remove(config):
    with pytest.raises(ConfigError, match="no CA profile called 'nope'"):
        config.profile_for("nope")
    config.add_ca(new_acme_profile("public", "https://acme.example.org/directory"))
    with pytest.raises(ConfigError, match="already exists"):
        config.add_ca(new_acme_profile("public", "https://other.example.org/directory"))
    config.set("default_ca", "public")
    assert config.default_profile().name == "public"
    with pytest.raises(ConfigError, match="primary CA"):
        config.remove_ca(config.ca.name)
    with pytest.raises(ConfigError, match="no CA profile called 'ghost'"):
        config.remove_ca("ghost")
    config.remove_ca("public")
    assert config.default_ca == config.ca.name  # the default falls back to the primary CA


def test_dotted_settings_for_profiles(config):
    config.add_ca(new_ukca_profile("second", "https://second.example.org"))
    config.add_ca(new_acme_profile("public", "https://acme.example.org/directory"))
    with pytest.raises(ConfigError, match="no CA profile called 'nope'"):
        config.set("default_ca", "nope")
    config.set("default_ca", "second")
    assert config.default_ca == "second"
    with pytest.raises(ConfigError, match="no CA profile 'nope'"):
        config.set("cas.nope.timeout", "5")
    config.set("cas.second.display_name", "Second")
    config.set("cas.second.timeout", "12")
    config.set("cas.second.endpoints.csr", "/alt/CSR")
    config.set("cas.second.identity.ou", "PPD")
    config.set("cas.public.acme.http_port", "8080")
    config.set("cas.public.webroot", "/var/www")
    config.set("cas.public.terms_agreed", "yes")
    second, public = config.profile_for("second"), config.profile_for("public")
    assert second.display_name == "Second" and second.ca.timeout == 12.0
    assert second.ca.endpoints.csr == "/alt/CSR"
    assert second.own_identity.ou == "PPD" and second.own_identity.l == config.identity.l
    assert public.acme.http_port == 8080 and public.acme.webroot == "/var/www" and public.acme.terms_agreed
    with pytest.raises(ConfigError, match="unknown setting"):
        config.set("cas.second.colour", "blue")
    with pytest.raises(ConfigError, match="unknown setting"):
        config.set("data_dir", "/tmp/x")  # a computed property, not a setting
    with pytest.raises(ConfigError, match="expected int"):
        config.set("ca.retries", 1.5)
    config.set("ca.timeout", 45)  # integers are accepted for float settings
    assert config.ca.timeout == 45.0 and isinstance(config.ca.timeout, float)
    validate_config(config)


def test_search_path_honours_xdg_config_home(monkeypatch, tmp_path):
    monkeypatch.delenv("PYCERT_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    paths = default_config_paths()
    assert paths[0] == tmp_path / "xdg" / "pycert" / "pycert.toml"
    assert len(paths) == len(set(paths))


def test_profile_factories_validate_names():
    with pytest.raises(ConfigError, match="invalid CA profile name"):
        new_acme_profile("Lets Encrypt", "https://acme.example.org/directory")
    with pytest.raises(ConfigError, match="invalid CA profile name"):
        new_ukca_profile("-bad", "https://ca.example.org")


# ---------------------------------------------------------------------------
# The [cas.*] schema
# ---------------------------------------------------------------------------


def test_load_render_and_reload_profiles(config, tmp_path):
    extra = f'''
[cas.letsencrypt]
kind = "acme"
display_name = "Let's Encrypt"
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["ops@example.org"]
terms_agreed = true
eab_kid = "kid-1"
eab_hmac_env = "PYCERT_EAB"
account_key = "rsa"
challenge = "dns-01"
http_mode = "webroot"
http_port = 8080
http_bind = "127.0.0.1"
webroot = "/var/www/html"
dns_hook = "/usr/local/bin/dns-hook"
dns_propagation_seconds = 30.0
validation_timeout = 120.0
poll_interval = 5.0
timeout = 20.0

[cas.staging]
kind = "acme"
base_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

[cas.sandbox]
kind = "ukca"
display_name = "Sandbox"
base_url = "https://sandbox.example.org:8443"
retries = 0
tls_pin_sha256 = ["{"ab" * 32}"]

[cas.sandbox.endpoints]
csr = "/alt/CSR"

[cas.sandbox.identity]
ou = "PPD"
l = "RAL"
''' + _chain_toml(config, "cas.sandbox.chain")
    loaded = load_config(_write(config, tmp_path, extra))
    assert list(loaded.cas) == [loaded.ca.name, "letsencrypt", "staging", "sandbox"]
    le, staging, sandbox = (loaded.profile_for(n) for n in ("letsencrypt", "staging", "sandbox"))
    assert le.kind == "acme" and le.ca.tls_trust == "system" and le.ca.timeout == 20.0
    assert le.acme.account_key == "rsa" and le.acme.dns_hook and le.acme.dns_propagation_seconds == 30.0
    assert staging.directory_url.endswith("staging-v02.api.letsencrypt.org/directory")
    assert sandbox.ca.endpoints.csr == "/alt/CSR" and sandbox.own_identity.ou == "PPD"
    assert sandbox.own_identity.c == loaded.identity.c and sandbox.bundle.anchors
    rendered = write_config(tmp_path / "out" / "pycert.toml", loaded)
    text = rendered.read_text()
    assert "[cas.letsencrypt]" in text and "[cas.sandbox.endpoints]" in text and "[[cas.sandbox.chain]]" in text
    (tmp_path / "out" / "chain").symlink_to(config.path.parent / "chain")
    again = load_config(rendered)
    for name in ("letsencrypt", "staging", "sandbox"):
        assert again.profile_for(name).as_dict() == loaded.profile_for(name).as_dict()
    assert again.profile_for("letsencrypt").acme == le.acme
    assert again.profile_for("sandbox").ca.tls_pin_sha256 == ["ab" * 32]


@pytest.mark.parametrize(
    "extra, match",
    [
        ("\n[cas]\nbroken = 1\n", r"cas\.broken: expected a table"),
        ('\n[cas."Bad Name"]\nkind = "ukca"\n', "CA profile names must be lower-case"),
        ('\n[cas.public]\nkind = "acme"\n', "the ACME directory URL is required"),
        ('\n[cas.uk-escience]\nkind = "ukca"\n', "already used by the primary CA"),
        ('\n[cas.odd]\nkind = "carrier-pigeon"\nbase_url = "https://x.example.org"\n', "unknown CA kind"),
        ('\n[cas.second]\nbase_url = "https://x.example.org"\n[cas.second.identity]\nc = "GBR"\n', "identity.c must be"),
        ('\ndefault_ca = "missing"\n', "default_ca"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\nchallenge = "tls-alpn-01"\n', "challenge must be"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\nhttp_mode = "proxy"\n', "http_mode must be"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\naccount_key = "dsa"\n', "account_key must be"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\nhttp_port = 70000\n', "http_port must be"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\nhttp_mode = "webroot"\n', "webroot is required"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\ndns_propagation_seconds = -1.0\n', "dns_propagation_seconds"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\nvalidation_timeout = 0.0\n', "validation_timeout"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\npoll_interval = 0.0\n', "poll_interval"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\ncontact = ["not an address"]\n', "not an e-mail"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "https://a.example.org/d"\neab_hmac_env = "1BAD-NAME"\n', "environment variable name"),
        ('\n[cas.public]\nkind = "acme"\ndirectory = "http://a.example.org/d"\n', "allow_plaintext"),
    ],
)
def test_profile_schema_errors(config, tmp_path, extra, match):
    text = config.path.read_text()
    if extra.startswith("\ndefault_ca"):
        text = text.replace(f'default_ca = "{config.ca.name}"', extra.strip())
        extra = ""
    path = config.path.parent / "bad.toml"
    path.write_text(text + extra)
    with pytest.raises(ConfigError, match=match):
        load_config(path)


def test_primary_ca_name_is_validated(config, tmp_path):
    path = config.path.parent / "bad-name.toml"
    path.write_text(config.path.read_text().replace(f'name = "{config.ca.name}"', 'name = "UK eScience"'))
    with pytest.raises(ConfigError, match="ca.name must be lower-case"):
        load_config(path)
