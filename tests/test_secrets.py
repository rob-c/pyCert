import stat
import sys

import pytest

from pycert.config import SecretConfig
from pycert.errors import SecretError
from pycert.secrets_store import SecretStore, generate_secret


def test_file_backend_roundtrip(tmp_path, capsys):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "test")
    value = store.ensure()
    assert len(value) >= 32
    assert store.exists()
    assert store.get() == value
    path = tmp_path / "secrets.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "plaintext at rest" in capsys.readouterr().err
    assert store.delete() is True
    assert not store.exists()
    assert store.delete() is False


def test_missing_secret_message(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "test")
    with pytest.raises(SecretError, match="no saved secret"):
        store.get()
    assert store.get(allow_missing=True) is None


def test_empty_secret_refused(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "test")
    with pytest.raises(SecretError):
        store.set("")


def test_env_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("PYCERT_TEST_SECRET", "s3cret")
    store = SecretStore(SecretConfig(backend="env", env_var="PYCERT_TEST_SECRET"), tmp_path, "test")
    assert store.get() == "s3cret"
    with pytest.raises(SecretError):
        store.set("x")


def test_command_backend(tmp_path):
    storage = tmp_path / "store.txt"
    script = tmp_path / "secret.py"
    script.write_text(
        "import pathlib, sys\n"
        "p = pathlib.Path(sys.argv[1])\n"
        "data = sys.stdin.read()\n"
        "p.write_text(data) if data else print(p.read_text().strip())\n"
    )
    command = f"{sys.executable} {script} {storage}"
    store = SecretStore(SecretConfig(backend="command", command=command), tmp_path, "test")
    store.set("from-a-password-manager")
    assert storage.read_text() == "from-a-password-manager"
    assert store.get() == "from-a-password-manager"


def test_generate_secret_shape():
    value = generate_secret()
    assert len(value) >= 40
    assert '"' not in value and "\\" not in value and "\n" not in value
    assert generate_secret() != value


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS keychain")
def test_keychain_backend(tmp_path):
    config = SecretConfig(backend="keychain", service="pyCertWiz-pytest", account="probe")
    store = SecretStore(config, tmp_path, "pytest")
    if not store.exists():
        store.set(generate_secret())
    value = store.get()
    assert value
    assert store.delete() in (True, False)


def test_auto_backend_resolves(tmp_path):
    store = SecretStore(SecretConfig(backend="auto"), tmp_path, "auto")
    assert store.backend in ("keychain", "secret-service", "file")


@pytest.mark.parametrize(
    "value", ['has "quotes" and \\ backslash', "pa*ss wörd €", "tab\there", "0xdeadbeef", "deadbeef", " lead"]
)
def test_keychain_stores_any_characters_as_hex_on_stdin(tmp_path, monkeypatch, value):
    from types import SimpleNamespace

    import pycert.secrets_store as module

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/" + name)
    store = SecretStore(SecretConfig(backend="keychain"), tmp_path, "test")
    calls = []

    def fake(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(store, "_subprocess", fake)
    store.set(value, "acct")
    args, kwargs = calls[0]
    assert args == ["security", "-i"]  # the secret is never in argv
    assert f"-X {value.encode('utf-8').hex()}" in kwargs["input"]
    assert value not in kwargs["input"]


@pytest.mark.parametrize(
    "output, expected",
    [
        ('keychain: "x"\npassword: "pa*ss"\n', "pa*ss"),
        ('password: "deadbeef"\n', "deadbeef"),
        ('password: "0xabc"\n', "0xabc"),
        ('password: "x""\n', 'x"'),
        ('password: 0x77C3B67264E282AC  "w\\303\\266rd\\342\\202\\254"\n', "wörd€"),
        ("password: \n", ""),
    ],
)
def test_keychain_password_output_is_parsed_unambiguously(output, expected):
    from pycert.secrets_store import _keychain_password

    assert _keychain_password(output) == expected


@pytest.mark.parametrize("output", ["nothing useful", "password: garbage", 'password: 0xZZ  "?"'])
def test_keychain_password_output_errors(output):
    from pycert.secrets_store import _keychain_password

    with pytest.raises(SecretError):
        _keychain_password(output)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS keychain")
def test_keychain_round_trips_awkward_passphrases(tmp_path):
    store = SecretStore(SecretConfig(backend="keychain", service="pyCertWiz-pytest-chars"), tmp_path, "test")
    try:
        for value in ('pa*ss wörd "q" \\ €', "tab\there", "deadbeef", "0xabc", "trailing "):
            store.set(value, "probe")
            assert store.get("probe") == value
    finally:
        store.delete("probe")
