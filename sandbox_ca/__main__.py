"""Run the standalone sandbox CA: ``python -m sandbox_ca``."""

import argparse
import secrets
import sys
from pathlib import Path

from .server import SandboxCA


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a local HTTPS CA that the Java CertWizard client can be pointed at.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="address to bind")
    parser.add_argument("--port", type=int, default=8443, help="TLS port (0 chooses a free port)")
    parser.add_argument(
        "--public-host",
        action="append",
        default=[],
        help="hostname/IP to put in the server certificate SAN (repeatable; required for remote clients)",
    )
    parser.add_argument(
        "--data-dir",
        default=".sandbox-ca",
        help="directory holding the persistent CA and sandbox metadata",
    )
    parser.add_argument("--motd", default="pyCert sandbox CA: certificates issued here are for testing only.")
    parser.add_argument(
        "--sign-after-polls",
        type=int,
        default=1,
        help="in auto-sign mode, issue after this many status lookups (0 = immediately)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--auto-sign",
        dest="auto_approve",
        action="store_true",
        help="approve and issue automatically (the easy end-to-end mode)",
    )
    mode.add_argument(
        "--manual",
        dest="auto_approve",
        action="store_false",
        help="leave requests pending until approved/signed through the admin API",
    )
    parser.set_defaults(auto_approve=True)
    token = parser.add_mutually_exclusive_group()
    token.add_argument("--admin-token", help="admin bearer token (default: a random token)")
    token.add_argument(
        "--no-admin-auth",
        action="store_true",
        help="disable the admin token (only safe on a loopback-only listener)",
    )
    parser.add_argument("--java-jar", help="optional CertWizard jar to patch immediately after starting")
    parser.add_argument("--java-kit-out", help="output path for --java-jar (default: <jar>-sandbox.jar)")
    parser.add_argument(
        "--acme-port",
        type=int,
        help="start the ACME v2 front-end on this TLS port (0 picks a free port)",
    )
    parser.add_argument(
        "--acme-challenge-mode",
        choices=("auto", "http", "manual"),
        default="auto",
        help="ACME challenge validation: auto, certbot webroot HTTP fetch, or manual",
    )
    parser.add_argument(
        "--acme-http-port",
        type=int,
        default=80,
        help="port used when fetching http-01 challenges",
    )
    parser.add_argument(
        "--acme-public-url",
        help="public ACME base URL (for a reverse proxy; default https://<hostname>:<acme-port>)",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.port < 0 or args.port > 65535:
        print("sandbox: --port must be between 0 and 65535", file=sys.stderr)
        return 2
    if args.sign_after_polls < 0:
        print("sandbox: --sign-after-polls must be >= 0", file=sys.stderr)
        return 2
    if args.host in ("0.0.0.0", "::") and not args.public_host:
        print(
            "sandbox: warning: binding all interfaces without --public-host; the certificate "
            "will only name localhost/loopback addresses",
            file=sys.stderr,
        )
    token = None if args.no_admin_auth else (args.admin_token or secrets.token_hex(16))
    try:
        ca = SandboxCA(
            data_dir=Path(args.data_dir),
            host=args.host,
            port=args.port,
            public_hosts=args.public_host,
            auto_approve=args.auto_approve,
            sign_after_polls=args.sign_after_polls,
            admin_token=token,
            motd=args.motd,
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary: report and exit
        print("sandbox: could not start: %s" % exc, file=sys.stderr)
        return 1

    if args.acme_port is not None:
        try:
            ca.start_acme(
                port=args.acme_port,
                challenge_mode=args.acme_challenge_mode,
                http_port=args.acme_http_port,
                public_url=args.acme_public_url,
            )
        except Exception as exc:  # noqa: BLE001
            print("sandbox: could not start ACME front-end: %s" % exc, file=sys.stderr)
            ca.stop()
            return 1

    info = ca.info()
    print("pyCert sandbox CA")
    print("  URL:              %s" % info["url"])
    print("  data directory:   %s" % info["data_dir"])
    print("  root SHA-256:     %s" % info["root_sha256"])
    print("  issuing SHA-256:  %s" % info["issuing_sha256"])
    print("  issuer DN:        %s" % info["issuer_dn"])
    print("  mode:             %s (issue after %d status lookup(s))" % (
        "auto-sign" if ca.auto_approve else "manual", ca.sign_after_polls
    ))
    print("  admin token:      %s" % (token or "(disabled)"))
    print("  admin console:    %s" % info["ui_url"])
    if info.get("acme_directory"):
        print("  ACME directory:   %s" % info["acme_directory"])
    print("  metadata:         %s" % ca.info_path)
    print()
    print("Point the Java client at %s (see docs/CA_LISTENER.md)." % info["url"])
    if token:
        print("  python -m sandbox_ca.admin --data-dir %s status" % info["data_dir"])
    if args.java_jar:
        from .java_kit import build_jar_kit

        out = args.java_kit_out or (str(Path(args.java_jar).with_suffix("")) + "-sandbox.jar")
        try:
            build_jar_kit(Path(args.java_jar), Path(out), ca.info())
        except Exception as exc:  # noqa: BLE001
            print("sandbox: could not build the Java kit: %s" % exc, file=sys.stderr)
            ca.stop()
            return 1
        print("  patched Java client: %s" % out)
    print("Press Ctrl-C to stop.")
    try:
        ca.httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nsandbox: stopping")
    finally:
        ca.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
