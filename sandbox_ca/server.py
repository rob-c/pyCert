"""Standalone sandbox CA for exercising the Java CertWizard client.

The protocol implementation is shared with the pyCert test suite
(``sandbox_ca.mock_ca``); this module adds a small authenticated admin API and
persists the CA hierarchy in a data directory so a patched Java client keeps
trusting the same CA across restarts.
"""

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .mock_ca import MockCA, _der_cert, _pem


class SandboxCA(MockCA):
    """A :class:`MockCA` with persistence and an admin API.

    Admin endpoints live under ``/__sandbox__/`` on the same HTTPS listener.
    They are protected by a bearer token supplied in ``X-Sandbox-Token`` (or
    ``Authorization: Bearer ...``); the CLI generates one by default.  These
    endpoints are for a local test sandbox only.
    """

    def __init__(
        self,
        *,
        data_dir: "str | Path",
        host: str = "127.0.0.1",
        port: int = 8443,
        public_hosts: "list[str] | tuple[str, ...] | None" = None,
        auto_approve: bool = True,
        sign_after_polls: int = 1,
        admin_token: "str | None" = None,
        motd: str = "pyCert sandbox CA: certificates issued here are for testing only.",
    ):
        self.data_dir_path = Path(data_dir).expanduser().resolve()
        self.admin_token = admin_token
        self.started_at = time.time()
        super().__init__(
            auto_approve=auto_approve,
            sign_after_polls=sign_after_polls,
            host=host,
            port=port,
            data_dir=self.data_dir_path,
            public_hosts=public_hosts,
            motd=motd,
        )
        self.info_path = self.data_dir_path / "sandbox.json"
        self.ca_bundle_path = self.data_dir_path / "ca-chain.pem"
        self.ca_bundle_path.write_text(_pem(self.root) + _pem(self.intermediate))
        self.write_info()

    # -- persisted sandbox metadata ---------------------------------------
    def _fingerprint(self, cert) -> str:
        return hashlib.sha256(_der_cert(cert)).hexdigest()

    def info(self) -> dict:
        from pycert.certs import name_to_string

        return {
            "format": 1,
            "url": self.url,
            "hostname": self.hostname,
            "bind_host": self.host,
            "port": self.port,
            "root_pem": str(self.data_dir_path / "root.pem"),
            "issuing_pem": str(self.data_dir_path / "issuing-ca.pem"),
            "ca_bundle_pem": str(self.ca_bundle_path),
            "root_sha256": self._fingerprint(self.root),
            "issuing_sha256": self._fingerprint(self.intermediate),
            "root_subject": name_to_string(self.root.subject),
            "issuing_subject": name_to_string(self.intermediate.subject),
            "issuer_dn": name_to_string(self.intermediate.subject),
            "auto_approve": self.auto_approve,
            "sign_after_polls": self.sign_after_polls,
            "admin_token": self.admin_token,
            "data_dir": str(self.data_dir_path),
            "started_at": self.started_at,
        }

    def write_info(self) -> None:
        self.info_path.write_text(json.dumps(self.info(), indent=2, sort_keys=True) + "\n")
        try:
            self.info_path.chmod(0o600)
        except OSError:
            pass

    # -- admin HTTP API ----------------------------------------------------
    def _handler_class(self):
        base = super()._handler_class()
        sandbox = self

        class Handler(base):
            def _admin_ok(self) -> bool:
                if sandbox.admin_token is None:
                    return True
                supplied = self.headers.get("X-Sandbox-Token")
                if supplied is None:
                    authorization = self.headers.get("Authorization") or ""
                    if authorization.lower().startswith("bearer "):
                        supplied = authorization[7:].strip()
                if supplied == sandbox.admin_token:
                    return True
                self._send_json(403, {"error": "missing or invalid sandbox admin token"})
                return False

            def _send_json(self, status: int, payload) -> None:
                body = (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode()
                self._send(status, body, "application/json")

            def _read_json(self) -> dict:
                body = self._read_body()
                if not body:
                    return {}
                try:
                    value = json.loads(body.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    self._send_json(400, {"error": "invalid JSON body: %s" % exc})
                    return {"_invalid": True}
                if not isinstance(value, dict):
                    self._send_json(400, {"error": "the JSON body must be an object"})
                    return {"_invalid": True}
                return value

            def do_GET(self):
                path = urlsplit(self.path).path
                if path.startswith("/__sandbox__/"):
                    if not self._admin_ok():
                        return None
                    return self._admin_get(path)
                return super().do_GET()

            def do_POST(self):
                path = urlsplit(self.path).path
                if path.startswith("/__sandbox__/"):
                    if not self._admin_ok():
                        return None
                    return self._admin_post(path)
                return super().do_POST()

            def _admin_get(self, path: str):
                if path in ("/__sandbox__/status", "/__sandbox__/status/"):
                    payload = sandbox.status_snapshot()
                    payload.update(
                        {
                            "root_sha256": sandbox._fingerprint(sandbox.root),
                            "issuing_sha256": sandbox._fingerprint(sandbox.intermediate),
                            "issuer_dn": sandbox.info()["issuer_dn"],
                            "data_dir": str(sandbox.data_dir_path),
                            "requests": len(sandbox.captured),
                        }
                    )
                    return self._send_json(200, payload)
                if path in ("/__sandbox__/requests", "/__sandbox__/requests/"):
                    query = parse_qs(urlsplit(self.path).query)
                    try:
                        limit = int(query.get("limit", ["50"])[0])
                    except ValueError:
                        limit = 50
                    limit = max(1, min(limit, 500))
                    with sandbox.lock:
                        items = list(sandbox.captured[-limit:])
                    return self._send_json(
                        200,
                        [
                            {
                                "method": item.method,
                                "path": item.path,
                                "headers": item.headers,
                                "body": item.body.decode("utf-8", "replace"),
                            }
                            for item in items
                        ],
                    )
                if path in ("/__sandbox__/ca.pem", "/__sandbox__/ca.pem/"):
                    return self._send(
                        200, (_pem(sandbox.root) + _pem(sandbox.intermediate)).encode(), "application/x-pem-file"
                    )
                return self._send_json(404, {"error": "unknown sandbox admin endpoint"})

            def _admin_post(self, path: str):
                payload = self._read_json()
                if payload.get("_invalid"):
                    return None
                if path in ("/__sandbox__/approve", "/__sandbox__/approve/"):
                    changed = sandbox.approve(payload.get("id"), all_records=bool(payload.get("all")))
                    return self._send_json(200, {"changed": changed})
                if path in ("/__sandbox__/sign", "/__sandbox__/sign/"):
                    changed = sandbox.sign(payload.get("id"), all_records=bool(payload.get("all")))
                    return self._send_json(200, {"changed": changed})
                if path in ("/__sandbox__/revoke", "/__sandbox__/revoke/"):
                    try:
                        cert_id = int(payload["id"])
                    except (KeyError, TypeError, ValueError):
                        return self._send_json(400, {"error": "revoke needs an integer 'id'"})
                    reason = str(payload.get("reason") or "unspecified")
                    if not sandbox.revoke_certificate(cert_id, reason):
                        return self._send_json(404, {"error": "unknown certificate id"})
                    return self._send_json(200, {"revoked": cert_id})
                if path in ("/__sandbox__/reset", "/__sandbox__/reset/"):
                    sandbox.clear_state()
                    return self._send_json(200, {"reset": True})
                if path in ("/__sandbox__/settings", "/__sandbox__/settings/"):
                    allowed_modes = {
                        "pppk_mode": {"normal", "no_challenge", "opaque", "bad_keyid", "bad_response"},
                        "lookup_mode": {
                            "normal",
                            "no_inline",
                            "csr_only",
                            "malformed",
                            "empty_200",
                            "wrong_pem",
                            "multiple",
                            "no_id",
                            "bad_status",
                            "csr_approved",
                            "csr_deleted",
                            "csr_unknown",
                        },
                        "download_mode": {
                            "normal",
                            "bare_pem",
                            "bare_der",
                            "xml_no_cert",
                            "malformed",
                            "wrong_cert",
                        },
                        "info_mode": {"normal", "bad_xml", "empty", "malformed_cert", "one_cert", "huge_ra", "no_preferred", "no_policy", "no_motd", "no_version"},
                    }
                    with sandbox.lock:
                        if "auto_approve" in payload:
                            if not isinstance(payload["auto_approve"], bool):
                                return self._send_json(400, {"error": "auto_approve must be a boolean"})
                            sandbox.auto_approve = payload["auto_approve"]
                        if "sign_after_polls" in payload:
                            try:
                                value = int(payload["sign_after_polls"])
                            except (TypeError, ValueError):
                                return self._send_json(400, {"error": "sign_after_polls must be an integer"})
                            if value < 0 or value > 10000:
                                return self._send_json(400, {"error": "sign_after_polls is out of range"})
                            sandbox.sign_after_polls = value
                        for key, modes in allowed_modes.items():
                            if key in payload:
                                value = str(payload[key])
                                if value not in modes:
                                    return self._send_json(400, {"error": "%s must be one of %s" % (key, sorted(modes))})
                                setattr(sandbox, key, value)
                        if "motd" in payload:
                            sandbox.motd = str(payload["motd"])
                    return self._send_json(200, {"settings": sandbox.status_snapshot()})
                return self._send_json(404, {"error": "unknown sandbox admin endpoint"})

        return Handler
