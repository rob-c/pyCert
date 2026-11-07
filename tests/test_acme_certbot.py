"""Optional end-to-end certbot check for the ACME front-end.

Skipped unless ``CERTBOT_BIN`` points at a certbot executable.  It exercises
the exact public ACME/TLS surface certbot uses: directory discovery, JWS
account/order/challenge/finalize requests, and certificate download.
"""

import os
import socket
import subprocess

import pytest

from sandbox_ca.server import SandboxCA


def _free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


@pytest.mark.skipif(not os.environ.get("CERTBOT_BIN"), reason="set CERTBOT_BIN to run certbot")
def test_certbot_obtains_and_revokes_a_certificate(tmp_path):
    certbot = os.environ["CERTBOT_BIN"]
    ca = SandboxCA(data_dir=tmp_path / "ca", port=0, auto_approve=True, sign_after_polls=0)
    try:
        acme = ca.start_acme(port=0, challenge_mode="auto")
        http_port = _free_port()
        config = tmp_path / "certbot-config"
        work = tmp_path / "certbot-work"
        logs = tmp_path / "certbot-logs"
        common = [
            "--server",
            acme.directory_url(),
            "--no-verify-ssl",
            "--config-dir",
            str(config),
            "--work-dir",
            str(work),
            "--logs-dir",
            str(logs),
            "--non-interactive",
        ]
        obtain = subprocess.run(
            [
                certbot,
                "certonly",
                "--standalone",
                "--agree-tos",
                "-m",
                "test@example.org",
                "--http-01-port",
                str(http_port),
                "-d",
                "sandbox.example",
                *common,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert obtain.returncode == 0, obtain.stdout + obtain.stderr
        fullchain = config / "live" / "sandbox.example" / "fullchain.pem"
        privkey = config / "live" / "sandbox.example" / "privkey.pem"
        assert fullchain.is_file() and privkey.is_file()
        assert fullchain.read_text().count("BEGIN CERTIFICATE") == 2
        revoke = subprocess.run(
            [certbot, "revoke", "--cert-path", str(fullchain), "--reason", "keycompromise", *common],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert revoke.returncode == 0, revoke.stdout + revoke.stderr
    finally:
        ca.stop()
