"""Small CLI for the sandbox CA admin API."""

import argparse
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _load_server(data_dir: str) -> dict:
    path = Path(data_dir).expanduser() / "sandbox.json"
    if not path.exists():
        raise SystemExit("sandbox admin: %s does not exist; start the server first" % path)
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        raise SystemExit("sandbox admin: cannot parse %s: %s" % (path, exc))


def _context(cafile: "str | None", server: "dict | None" = None):
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    root_pem = (server or {}).get("root_pem")
    if root_pem and Path(root_pem).exists():
        # The sandbox writes its root CA next to sandbox.json; use it so the
        # admin CLI verifies the listener instead of disabling TLS checks.
        return ssl.create_default_context(cafile=root_pem)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _call(server: dict, args, method: str, path: str, payload=None):
    url = server["url"].rstrip("/") + path
    body = None if payload is None else (json.dumps(payload) + "\n").encode()
    request = Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if server.get("admin_token"):
        request.add_header("X-Sandbox-Token", server["admin_token"])
    try:
        with urlopen(request, context=_context(args.cafile, server), timeout=args.timeout) as response:
            data = response.read()
    except HTTPError as exc:
        data = exc.read()
        print(data.decode("utf-8", "replace"), file=sys.stderr)
        return 1
    except (URLError, OSError) as exc:
        print("sandbox admin: %s" % exc, file=sys.stderr)
        return 1
    if data:
        try:
            print(json.dumps(json.loads(data), indent=2, sort_keys=True))
        except ValueError:
            print(data.decode("utf-8", "replace"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect or control a running pyCert sandbox CA.")
    parser.add_argument("--data-dir", default=".sandbox-ca", help="directory containing sandbox.json")
    parser.add_argument("--url", help="override the server URL (default: from sandbox.json)")
    parser.add_argument("--cafile", help="trust this PEM file instead of disabling verification")
    parser.add_argument("--timeout", type=float, default=10.0)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="show pending CSRs and issued certificates")
    requests = sub.add_parser("requests", help="show recently captured protocol requests")
    requests.add_argument("--limit", type=int, default=20)

    for name in ("approve", "sign"):
        cmd = sub.add_parser(name, help="%s one CSR or all pending CSRs" % name)
        cmd.add_argument("id", nargs="?", type=int)
        cmd.add_argument("--all", action="store_true")

    revoke = sub.add_parser("revoke", help="revoke an issued certificate")
    revoke.add_argument("id", type=int)
    revoke.add_argument("--reason", default="unspecified")

    sub.add_parser("reset", help="forget CSRs, certificates and captured requests")

    settings = sub.add_parser("settings", help="change auto-sign or fault-injection settings")
    settings.add_argument("--auto-approve", choices=("true", "false"))
    settings.add_argument("--sign-after-polls", type=int)
    settings.add_argument(
        "--pppk-mode",
        choices=("normal", "no_challenge", "opaque", "bad_keyid", "bad_response"),
    )
    settings.add_argument(
        "--lookup-mode",
        choices=(
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
        ),
    )
    settings.add_argument(
        "--download-mode",
        choices=("normal", "bare_pem", "bare_der", "xml_no_cert", "malformed", "wrong_cert"),
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    server = _load_server(args.data_dir)
    if args.url:
        server["url"] = args.url
    if args.command == "status":
        return _call(server, args, "GET", "/__sandbox__/status")
    if args.command == "requests":
        return _call(server, args, "GET", "/__sandbox__/requests?limit=%d" % args.limit)
    if args.command in ("approve", "sign"):
        if args.id is None and not args.all:
            print("sandbox admin: give a CSR id or --all", file=sys.stderr)
            return 2
        return _call(
            server,
            args,
            "POST",
            "/__sandbox__/%s" % args.command,
            {"id": args.id, "all": bool(args.all)},
        )
    if args.command == "revoke":
        return _call(
            server, args, "POST", "/__sandbox__/revoke", {"id": args.id, "reason": args.reason}
        )
    if args.command == "reset":
        return _call(server, args, "POST", "/__sandbox__/reset", {})
    if args.command == "settings":
        payload = {}
        if args.auto_approve is not None:
            payload["auto_approve"] = args.auto_approve == "true"
        if args.sign_after_polls is not None:
            payload["sign_after_polls"] = args.sign_after_polls
        for key in ("pppk_mode", "lookup_mode", "download_mode"):
            value = getattr(args, key)
            if value is not None:
                payload[key] = value
        if not payload:
            print("sandbox admin: no settings given", file=sys.stderr)
            return 2
        return _call(server, args, "POST", "/__sandbox__/settings", payload)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
