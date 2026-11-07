"""End-to-end harness that drives the real CLI against the mock CA listener."""

import json
from dataclasses import dataclass


@dataclass
class Result:
    code: int
    out: str
    err: str
    json: object = None


class E2E:
    PIN = "1234567890AB"

    def __init__(self, config, ctx, ca, capsys):
        self.config = config
        self.ctx = ctx
        self.ca = ca
        self.capsys = capsys

    # -- basic invocation --------------------------------------------------
    def run(self, *args, json_mode=False):
        from pycert.cli import main

        argv = ["--config", str(self.config.path), *args]
        if json_mode and "--json" not in argv:
            argv.append("--json")
        try:
            code = main(argv)
        except SystemExit as exc:  # argparse --help/--version
            code = int(exc.code or 0)
        captured = self.capsys.readouterr()
        payload = None
        text = captured.out.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
        return Result(code, captured.out, captured.err, payload)

    def run_json(self, *args):
        return self.run(*args, json_mode=True)

    # -- CA state helpers --------------------------------------------------
    def request_user(self, cn="e2e user", *, alias=None, wait=False, extra=(), key_algorithm="ec"):
        args = ["request", cn, "--pin", self.PIN, "--key-algorithm", key_algorithm, *extra]
        if alias:
            args += ["--alias", alias]
        if wait:
            args += ["--wait", "--interval", "0.2", "--timeout", "30"]
        return self.run_json(*args)

    def request_host(self, cn="host.example.org", *, auth, wait=False):
        args = [
            "request",
            cn,
            "--type",
            "host",
            "--auth",
            auth,
            "--pin",
            self.PIN,
            "--key-algorithm",
            "ec",
        ]
        if wait:
            args += ["--wait", "--interval", "0.2", "--timeout", "30"]
        return self.run_json(*args)

    def state(self, alias):
        return self.ctx.store.get(alias)

    def record(self, state):
        return self.ca.csrs[state.active_spki_b64]

    def approve(self, state):
        with self.ca.lock:
            self.record(state).status = "APPROVED"

    def sign(self, state):
        with self.ca.lock:
            self.ca._sign_csr(self.record(state))

    def set_certificate_status(self, state, status):
        with self.ca.lock:
            record = self.record(state)
            if record.cert_id is None:
                self.ca._sign_csr(record)
            self.ca.certificates[record.cert_id].status = status

    def set_expiry(self, alias, days):
        import datetime as dt

        state = self.state(alias)
        state.cert.not_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()
        self.ctx.store.save(state)
        return state

    def configure(self, **ca_attrs):
        for key, value in ca_attrs.items():
            setattr(self.config.ca, key, value)
        self.config.save()

    def setup_pending(self, cn="fault pending"):
        self.ca.auto_approve = False
        result = self.request_user(cn, wait=False)
        assert result.code == 0, result.err
        return result.json["alias"]

    def setup_issued(self, cn="fault issued"):
        self.ca.auto_approve = True
        self.ca.sign_after_polls = 0
        result = self.request_user(cn, wait=True)
        assert result.code == 0, result.err
        return result.json["alias"]

    def captured(self, path, method=None):
        return self.ca.requests_for(path, method)

    def last(self, path, method=None):
        return self.ca.last_request(path, method)
