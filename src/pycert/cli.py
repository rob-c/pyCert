"""pycert command line interface.

Design goals: scriptable (``--json``, meaningful exit codes), quiet by default,
never print a secret unless it is the point of the command, and make the
common case one line::

    pycert request "Jane Doe" --wait
    pycert request web1.example.ac.uk web2.example.ac.uk --type host --auth "jane doe"
    pycert check --warn 30 --crit 7          # Nagios/Icinga probe

Exit codes
----------
0   success
1   error (configuration, cryptographic, CA rejection, not found)
2   command line usage error (argparse)
3   timed out waiting for the CA to sign (the request is still stored)
4   certificate chain did not validate

``pycert check`` uses the monitoring-plugin convention instead: 0 OK,
1 WARNING, 2 CRITICAL, 3 UNKNOWN.
"""

import argparse
import csv
import getpass
import json
import sys
from pathlib import Path

from . import __version__, certs
from .config import (
    ConfigError,
    load_config,
    new_acme_profile,
    new_ukca_profile,
    validate_config,
    write_config,
)
from .errors import ChainError, PyCertError, TimeoutWaiting
from .proxy import create_proxy_bundle
from .secrets_store import SecretStore, generate_secret
from .store import PENDING_STATUSES, RequestState
from .util import parse_duration
from .workflow import (
    DEFAULT_WAIT_INTERVAL,
    DEFAULT_WAIT_TIMEOUT,
    AppContext,
    RequestSpec,
    create_configuration,
    create_request,
    download_and_export,
    expiry_warning,
    export_p12,
    import_p12,
    install_pem,
    poll_once,
    refresh_all,
    refresh_records,
    renew,
    renew_due,
    revoke,
    verify,
    watch,
)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


class Console:
    def __init__(self, *, json_mode: bool = False, quiet: bool = False, verbose: bool = False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose

    def progress(self, message: str) -> None:
        if self.quiet or self.json_mode:
            return
        print(f"  {message}", file=sys.stderr, flush=True)

    def info(self, message: str = "") -> None:
        if self.json_mode:
            return
        print(message)

    def warning(self, message: str) -> None:
        print(f"warning: {message}", file=sys.stderr, flush=True)

    def error(self, message: str) -> None:
        print(f"error: {message}", file=sys.stderr, flush=True)

    def result(self, payload: dict) -> None:
        if self.json_mode:
            print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        else:
            self.info(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _context(args) -> AppContext:
    config = load_config(args.config)
    ctx = AppContext.from_config(config)
    if sys.stdin.isatty() and not getattr(args, "json", False):
        ctx.confirm = _terminal_confirm
        ctx.ask_keystore_password = _terminal_keystore_password
    return ctx


def _terminal_keystore_password(link) -> "str | None":
    """Ask for a Java keystore passphrase; it is used for this command only and never stored."""
    return getpass.getpass(f"Passphrase for Java keystore '{link.name}' ({link.path}, never stored): ") or None


def _terminal_confirm(title: str, instructions: str) -> bool:
    print(f"\n{title}\n{instructions}\n", file=sys.stderr, flush=True)
    answer = input("Press Enter when done (or type 'no' to cancel): ").strip().lower()
    return answer not in ("n", "no", "cancel", "abort")


def _read_secret_option(args, *, what: str, prompt_label: str, required: bool = True) -> "str | None":
    """Resolve --password / --password-file / --password-stdin / interactive prompt."""
    value = getattr(args, "password", None)
    if value:
        print(
            "warning: --password is visible in the process list; prefer --password-file, "
            "--password-stdin or the saved secret",
            file=sys.stderr,
        )
    path = getattr(args, "password_file", None)
    stdin = getattr(args, "password_stdin", False)
    if value:
        return value
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise PyCertError(f"cannot read {what} from {path}: {exc}") from exc
    if stdin:
        line = sys.stdin.readline()
        if not line:
            raise PyCertError(f"no {what} supplied on stdin")
        return line.rstrip("\r\n")
    if required:
        if not sys.stdin.isatty():
            raise PyCertError(f"{what} required: use --password-file, --password-stdin, or the saved secret")
        return getpass.getpass(f"{prompt_label}: ")
    return None


def _read_pin(args, *, required: bool = False) -> str:
    pin = getattr(args, "pin", None)
    if pin:
        print(
            "warning: --pin is visible in the process list; prefer --pin-file, --pin-stdin "
            "or the interactive prompt",
            file=sys.stderr,
        )
        return pin
    path = getattr(args, "pin_file", None)
    if path:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    if getattr(args, "pin_stdin", False):
        line = sys.stdin.readline()
        if not line:
            raise PyCertError("no PIN supplied on stdin")
        return line.rstrip("\r\n")
    if getattr(args, "generate_pin", False) or not sys.stdin.isatty():
        return ""
    first = getpass.getpass("PIN for the RA (it is shown to them for verification): ")
    if not first:
        return ""
    second = getpass.getpass("Confirm PIN: ")
    if first != second:
        raise PyCertError("the PINs do not match")
    return first


UNENCRYPTED_CONFIRMATION = "unencrypted"


def _confirm_unencrypted(what: str) -> None:
    """The explicit, interactive override for writing one private key without a passphrase."""
    if not sys.stdin.isatty():
        raise PyCertError(
            "refusing to write a private key without a passphrase: this needs an interactive confirmation"
        )
    print(
        f"\nYou asked to write {what} WITHOUT a passphrase.\n"
        "Anyone who can read that file can use the key and impersonate the certificate's owner.",
        file=sys.stderr,
    )
    answer = input(f"Type '{UNENCRYPTED_CONFIRMATION}' to confirm: ").strip()
    if answer != UNENCRYPTED_CONFIRMATION:
        raise PyCertError("aborted: the key was not written")


def _new_passphrase(args, what: str) -> str:
    """A new passphrase for an export: from --password[-file|-stdin], or typed twice on a terminal."""
    from .exporter import MIN_PASSPHRASE

    value = _read_secret_option(args, what="export passphrase", prompt_label="", required=False)
    if value:
        return value
    if not sys.stdin.isatty():
        raise PyCertError(
            f"a new passphrase for {what} is required: use --password-file or --password-stdin, or run interactively"
        )
    first = getpass.getpass(f"New passphrase for {what} (at least {MIN_PASSPHRASE} characters): ")
    second = getpass.getpass("Repeat the new passphrase: ")
    if first != second:
        raise PyCertError("the passphrases do not match")
    return first


def _key_passphrase_choice(args, what: str) -> "tuple[str | None, bool]":
    """(a new passphrase, no_passphrase) for an individual key file; never the saved secret."""
    if getattr(args, "no_key_passphrase", False):
        if getattr(args, "password", None) or getattr(args, "password_file", None) or getattr(args, "password_stdin", False):
            raise PyCertError("--no-key-passphrase cannot be combined with a passphrase option")
        _confirm_unencrypted(what)
        return None, True
    return _new_passphrase(args, what), False


def _confirm(args, prompt: str, expected: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        raise PyCertError("refusing to continue without --yes in a non-interactive context")
    answer = input(f"{prompt} Type '{expected}' to confirm: ").strip()
    if answer != expected:
        raise PyCertError("aborted")
    return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(args) -> int:
    console = Console(json_mode=getattr(args, "json", False), quiet=getattr(args, "quiet", False))
    directory = getattr(args, "directory", None)
    ctx = create_configuration(
        Path(directory) if directory else None,
        profile=getattr(args, "profile", "default"),
        email=getattr(args, "email", None) or "",
        ra=getattr(args, "ra", None) or "",
        base_url=getattr(args, "base_url", None) or "",
        backend=getattr(args, "backend", None) or "",
        force=bool(getattr(args, "force", False)),
    )
    config = ctx.config
    payload = {
        "config": str(config.path),
        "data_dir": str(config.data_dir),
        "secret_backend": ctx.secrets.backend,
        "secret_stored": True,
        "chain": [str(entry.file) for entry in config.chain],
        "base_url": config.ca.base_url,
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return 0
    console.info(f"Configuration written to {config.path}")
    console.info(f"Data directory:        {config.data_dir}")
    console.info(f"Saved secret backend: {ctx.secrets.backend} (p12 account '{config.secrets.account}')")
    console.info(f"CA server:            {config.ca.base_url}")
    console.info("")
    console.info("Next steps:")
    console.info("  1. pycert config check          # verify the CA chain and settings")
    console.info("  2. pycert ras                   # list available RAs")
    console.info('  3. pycert request "Jane Doe" --wait')
    return 0


def cmd_config(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    if args.action == "path":
        from .config import find_config

        path = find_config(args.config)
        if args.json:
            print(json.dumps({"path": str(path)}, indent=2))
        else:
            print(path)
        return 0
    if args.action == "set":
        config = load_config(args.config)
        for assignment in args.assignments:
            if "=" not in assignment:
                raise PyCertError(f"expected key=value, got {assignment!r}")
            key, value = assignment.split("=", 1)
            config.set(key.strip(), value.strip())
        from .config import validate_config

        validate_config(config)
        write_config(config.path, config)
        console.info(f"Updated {config.path}")
        return 0
    config = load_config(args.config)
    bundle = config.bundle
    if args.action == "show":
        if args.json:
            print(
                json.dumps(
                    {
                        **config.as_dict(),
                        "secret_backend": str(SecretStore(config.secrets, config.data_dir, config.profile)),
                    },
                    indent=2,
                    default=str,
                )
            )
            return 0
        data = config.as_dict()
        console.info(f"Configuration: {data['path']} (profile {data['profile']})")
        console.info("")
        console.info("Server")
        console.info(f"  base URL        {data['ca']['base_url']}")
        console.info(f"  version string  {data['ca']['version_string']}")
        console.info(
            f"  TLS verify      {_yes_no(data['ca']['tls_verify'])} (trust: {data['ca']['tls_trust']})"
        )
        if data["ca"]["tls_pin_sha256"]:
            console.info(f"  TLS pin(s)      {', '.join(data['ca']['tls_pin_sha256'])}")
        console.info("")
        console.info("Identity defaults")
        console.info(
            f"  O / OU / L / C  {config.identity.o} / {config.identity.ou} / {config.identity.l} / {config.identity.c}"
        )
        console.info(f"  e-mail          {config.identity.email or '(not set)'}")
        console.info(f"  RA              {config.identity.ra or '(not set - pass --ra)'}")
        console.info(
            f"  key             {config.keys.algorithm} {config.keys.rsa_bits if config.keys.algorithm == 'rsa' else config.keys.ec_curve}"
        )
        console.info(
            f"  CSR hash        {config.csr.hash}, PIN hash {config.csr.pin_hash}, extensions {', '.join(config.csr.extensions)}"
        )
        console.info("")
        console.info(f"CA chain ({len(bundle.certificates)} certificates, {len(bundle.anchors)} anchors)")
        for index, cert in enumerate(bundle.certificates):
            description = certs.describe_certificate(cert)
            console.info(
                f"  [{index}] {description.subject}\n"
                f"      expires {description.not_after.date()}  {description.key}  "
                f"SHA-256 {description.fingerprint_sha256}"
            )
        console.info("")
        console.info(f"Data directory   {config.data_dir}")
        console.info(f"Secret backend   {SecretStore(config.secrets, config.data_dir, config.profile)}")
        if config.warnings:
            console.info("")
            for warning in config.warnings:
                console.warning(warning)
        return 0
    if args.action == "check":
        problems: "list[str]" = []
        for warning in config.warnings:
            console.warning(warning)
        try:
            bundle = config.load_chain()
        except ConfigError as exc:
            console.error(str(exc))
            return 1
        if not bundle.anchors:
            problems.append("no trust anchors configured (certificate chains cannot validate)")
        for entry in config.chain:
            if not entry.sha256:
                problems.append(f"chain entry {entry.label or entry.file or 'inline'} has no SHA-256 pin")
        if not config.ca.tls_verify:
            problems.append("ca.tls_verify is false")
        if config.ca.allow_plaintext:
            problems.append("ca.allow_plaintext is true")
        if config.csr.pin_hash == "sha256":
            problems.append("csr.pin_hash = sha256 is not understood by the current CA server")
        for cert in bundle.certificates:
            names = cert.subject.rfc4514_string()
            days = certs.describe_certificate(cert).days_remaining
            if days <= 0:
                problems.append(f"CA certificate has expired: {names}")
            elif days < 180:
                console.warning(f"CA certificate expires in {days} days: {names}")
        payload = {
            "config": str(config.path),
            "ok": not problems,
            "problems": problems,
            "chain_certificates": len(bundle.certificates),
            "anchors": len(bundle.anchors),
            "data_dir": str(config.data_dir),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            if problems:
                for problem in problems:
                    console.error(problem)
            else:
                console.info(
                    f"OK: {len(bundle.certificates)} CA certificates loaded, "
                    f"{len(bundle.anchors)} trust anchors, all pins verified."
                )
                console.info(
                    f"Data directory {config.data_dir} is {oct(config.data_dir.stat().st_mode & 0o777)}"
                )
        return 0 if not problems else 1
    raise PyCertError(f"unknown config action: {args.action}")


def cmd_ping(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    names = list(ctx.config.cas) if getattr(args, "all", False) else [getattr(args, "ca", None) or ""]
    ok_all = True
    payloads = []
    for name in names:
        provider = ctx.provider(name)
        result = provider.ping()
        ok_all = ok_all and result.ok
        payload = {
            "ok": result.ok,
            "ca": provider.name,
            "kind": provider.kind,
            "base_url": provider.url,
            "latency_ms": round(result.latency_ms, 1),
            "tls": result.tls.as_dict() if result.tls is not None else None,
            "error": result.detail or None,
        }
        payloads.append(payload)
        if args.json:
            continue
        if result.ok:
            console.info(f"pong from {provider.url} in {payload['latency_ms']} ms ({provider.display_name})")
            if result.tls:
                tls = result.tls
                console.info(f"TLS peer: {tls.subject}")
                console.info(f"  issued by {tls.issuer}")
                console.info(f"  SHA-256   {tls.fingerprint}")
                console.info(f"  expires   {tls.not_after.date()}")
        else:
            detail = f": {result.detail}" if result.detail else ""
            console.error(f"no response from {provider.url}{detail}")
    if args.json:
        print(json.dumps(payloads if len(payloads) > 1 else payloads[0], indent=2, default=str))
    return 0 if ok_all else 1


def _ukca_client(ctx: AppContext, args):
    name = getattr(args, "ca", None) or ""
    profile = ctx.profile(name)
    if profile.kind != "ukca":
        raise PyCertError(f"'{profile.name}' is an {profile.kind} CA; this command needs a CertWizard-protocol CA")
    return (ctx.client(name) if name else ctx.client()), profile


def cmd_ras(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    client, profile = _ukca_client(ctx, args)
    info = client.info()
    for problem in info.problems:
        console.warning(problem)
    if args.json:
        print(
            json.dumps(
                {
                    "ras": [{"ou": ra.ou, "l": ra.l} for ra in info.ras],
                    "preferred": {"ou": info.preferred_ra.ou, "l": info.preferred_ra.l}
                    if info.preferred_ra
                    else None,
                    "policy": info.policy,
                    "certificates": [certs.describe_certificate(c).as_dict() for c in info.certificates],
                },
                indent=2,
                default=str,
            )
        )
        return 0
    console.info(f"{len(info.ras)} RAs on {profile.ca.base_url}:")
    for ra in info.ras:
        marker = (
            " *"
            if info.preferred_ra and (ra.ou, ra.l) == (info.preferred_ra.ou, info.preferred_ra.l)
            else "  "
        )
        console.info(f" {marker} {ra.label}")
    if info.preferred_ra:
        console.info(f"\n* = server-preferred RA ({info.preferred_ra.label})")
    if info.policy:
        console.info("\nPolicy: " + ", ".join(f"{k}={v}" for k, v in info.policy.items()))
    return 0


def cmd_info(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    profile = ctx.profile(getattr(args, "ca", None) or "")
    if profile.kind != "ukca":
        data = ctx.provider(profile.name).info()
        if args.json:
            print(json.dumps({"ca": profile.name, "base_url": profile.ca.base_url, **data}, indent=2, default=str))
        else:
            console.info(f"{profile.display_name} ({profile.kind}) at {profile.ca.base_url}")
            for key, value in data.items():
                console.info(f"  {key:<24} {value}")
        return 0
    name = getattr(args, "ca", None) or ""
    client = ctx.client(name) if name else ctx.client()
    info = client.info()
    motd = ""
    try:
        motd = client.motd()
    except PyCertError:
        pass
    if args.json:
        print(
            json.dumps(
                {
                    "base_url": profile.ca.base_url,
                    "motd": motd,
                    "policy": info.policy,
                    "ras": [{"ou": ra.ou, "l": ra.l} for ra in info.ras],
                    "certificates": [certs.describe_certificate(c).as_dict() for c in info.certificates],
                    "problems": info.problems,
                },
                indent=2,
                default=str,
            )
        )
        return 0
    if motd:
        console.info(f"Message of the day:\n{motd}\n")
    console.info(f"RA count: {len(info.ras)}")
    if info.policy:
        console.info("Policy: " + ", ".join(f"{k}={v}" for k, v in info.policy.items()))
    if info.certificates:
        console.info("")
        console.info("CA certificates served by the CA:")
        for cert in info.certificates:
            description = certs.describe_certificate(cert)
            console.info(f"  {description.subject}")
            console.info(
                f"    expires {description.not_after.date()}  SHA-256 {description.fingerprint_sha256}"
            )
    for problem in info.problems:
        console.warning(problem)
    return 0


def _request_names(args) -> "list[str]":
    names = [name for name in (args.cn or []) if name.strip()]
    if getattr(args, "from_file", None):
        try:
            lines = Path(args.from_file).expanduser().read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise PyCertError(f"cannot read {args.from_file}: {exc}") from exc
        names += [line.split("#", 1)[0].strip() for line in lines if line.split("#", 1)[0].strip()]
    if not names:
        raise PyCertError("give at least one common name (or --from-file FILE)")
    if len(names) > 1 and args.alias:
        raise PyCertError("--alias can only be used with a single common name")
    if len(names) > 1 and args.type != "host":
        raise PyCertError("several names at once are only supported for host certificates (--type host)")
    duplicates = {name for name in names if names.count(name) > 1}
    if duplicates:
        raise PyCertError(f"duplicate names: {', '.join(sorted(duplicates))}")
    return names


def _request_payload(ctx: AppContext, state: RequestState, pin: "str | None") -> dict:
    return {
        "alias": state.alias,
        "common_name": state.cn,
        "type": state.type,
        "ca": state.ca,
        "status": state.status,
        "subject": state.subject,
        "p12": state.p12_path,
        "certificate": str(ctx.store.cert_path(state)) if state.cert.sha256 else None,
        "pin": pin,
        "days_remaining": state.days_remaining,
    }


def cmd_request(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    names = _request_names(args)
    pin = _read_pin(args)
    specs = []
    for name in names:
        # Validate every name before submitting anything.
        specs.append(
            RequestSpec.build(
                ctx.config,
                name,
                type=args.type,
                email=args.email,
                alias=args.alias,
                ra=args.ra,
                ou=args.ou,
                l=args.l,
                o=args.o,
                c=args.c,
                key_algorithm=args.key_algorithm,
                rsa_bits=args.rsa_bits,
                ec_curve=args.ec_curve,
                pin=pin,
                san_dns=args.san_dns if len(names) == 1 else [],
                san_email=args.san_email,
                san_ip=args.san_ip if len(names) == 1 else [],
                csr_extensions=args.extensions,
                csr_hash=args.hash,
                auth_alias=args.auth,
                ca=getattr(args, "ca", None) or "",
                description=getattr(args, "description", None) or "",
                keystore=getattr(args, "keystore", None) or "",
            )
        )
    for spec in specs:
        alias = spec.alias or spec.cn
        if ctx.store.exists(alias):
            raise PyCertError(f"a certificate request called '{alias}' already exists (use --alias)")
    deploy_target = getattr(args, "deploy_preset", None)
    payloads = []
    failures = 0
    for spec in specs:
        pins: "list[str]" = [spec.pin] if spec.pin else []
        if len(specs) > 1:
            console.progress(f"--- {spec.cn} ---")
        try:
            state = create_request(
                ctx,
                spec,
                progress=console.progress,
                on_pin=pins.append,
                wait=False,
                export=not args.no_export,
                require_verified_chain=not args.allow_unverified_chain,
            )
            if deploy_target:
                from .deploy import add_target, target_from_preset

                add_target(
                    ctx,
                    state,
                    target_from_preset(
                        deploy_target,
                        directory=getattr(args, "deploy_dir", None) or "",
                        alias=state.alias,
                        hook=getattr(args, "deploy_hook", None),
                        per_certificate_dir=len(specs) > 1,
                    ),
                )
            if args.wait:
                from .workflow import wait_for_certificate

                state = wait_for_certificate(
                    ctx,
                    state,
                    progress=console.progress,
                    timeout=parse_duration(args.timeout),
                    interval=parse_duration(args.interval),
                    export=not args.no_export,
                    require_verified_chain=not args.allow_unverified_chain,
                )
        except PyCertError as exc:
            if len(specs) == 1:
                raise
            failures += 1
            console.error(f"{spec.cn}: {exc}")
            payloads.append({"common_name": spec.cn, "error": str(exc)})
            continue
        payloads.append(_request_payload(ctx, state, pins[0] if pins else None))
    if args.json:
        print(json.dumps(payloads[0] if len(payloads) == 1 else payloads, indent=2, default=str))
    else:
        for payload in payloads:
            console.info("")
            if payload.get("error"):
                console.info(f"Request '{payload['common_name']}' FAILED: {payload['error']}")
                continue
            if payload["pin"]:
                console.info(f"PIN for the RA: {payload['pin']}")
            console.info(f"Request '{payload['alias']}' is {payload['status']}.")
            console.info(f"  certificate: {payload['certificate'] or '(not issued yet)'}")
            console.info(f"  PKCS#12:     {payload['p12'] or '(not exported yet)'}")
            if payload["days_remaining"] is not None:
                state = ctx.store.get(payload["alias"])
                console.info(f"  valid until: {state.cert.not_after} ({state.days_remaining} days)")
    return 1 if failures else 0


def _print_states(
    console: Console, states: "list[RequestState]", *, verbose: bool = False, primary: str = "", show_ca: bool = False
) -> None:
    if not states:
        console.info("No certificate requests in the local store.")
        return
    ca_header = f" {'CA':<14}" if show_ca else ""
    console.info(f"{'ALIAS':<28} {'TYPE':<5}{ca_header} {'STATUS':<11} {'EXPIRES':<12} {'DAYS':>5}  P12")
    for state in states:
        expires = state.cert.not_after[:10] if state.cert.not_after else "-"
        days = "" if state.days_remaining is None else f"{state.days_remaining}"
        p12 = "yes" if state.p12_path else "no"
        ca_column = f" {(state.ca or primary)[:14]:<14}" if show_ca else ""
        console.info(
            f"{state.alias[:28]:<28} {state.type:<5}{ca_column} {state.status:<11} {expires:<12} {days:>5}  {p12}"
        )
        warning = expiry_warning(state)
        if warning:
            console.info(f"{'':28} ! {warning}")
        if verbose and state.description:
            console.info(f"{'':28}   {state.description}")


def cmd_list(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    from .monitor import select

    states = select(ctx, ca=getattr(args, "ca", None) or "", cert_type=getattr(args, "type", None) or "")
    if args.json:
        print(json.dumps([state.to_dict() for state in states], indent=2, default=str))
        return 0
    _print_states(
        console,
        states,
        verbose=args.verbose,
        primary=ctx.config.primary_profile.name,
        show_ca=len(ctx.config.cas) > 1,
    )
    if not getattr(args, "no_audit", False):
        for problem in ctx.store.audit():
            console.warning(problem)
    return 0


def cmd_status(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    if args.refresh:
        if args.alias:
            state = ctx.store.get(args.alias)
            if state.status in PENDING_STATUSES:
                outcome = poll_once(ctx, state, progress=console.progress)
                state = outcome.state
                if outcome.certificate is not None:
                    console.info(
                        f"{state.alias}: certificate is available; run 'pycert download {state.alias}'"
                    )
                else:
                    console.info(f"{state.alias}: {outcome.server_status or 'unknown'} — {outcome.message}")
            else:
                records = refresh_records(ctx, aliases={state.alias})
                if records:
                    console.info(f"{state.alias}: {state.status}; {records[0][1]}")
                else:
                    console.info(f"{state.alias}: {state.status} (no need to poll)")
        else:
            for state, status in refresh_all(ctx, progress=console.progress):
                console.info(f"{state.alias}: {status}")
            # Certificates the CA has not been asked about yet (e.g. imported ones).
            for state, message in refresh_records(ctx, only_missing=True):
                console.info(f"{state.alias}: {message}")
        if args.json:
            print(json.dumps([s.to_dict() for s in ctx.store.list()], indent=2, default=str))
            return 0
        return 0
    if args.alias:
        state = ctx.store.get(args.alias)
        payload = {**state.to_dict(), "days_remaining": state.days_remaining}
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
            return 0
        _print_state(console, ctx, state)
        return 0
    return cmd_list(args)


def _print_state(console: Console, ctx: AppContext, state: RequestState) -> None:
    console.info(f"Alias           {state.alias}")
    console.info(f"Common name     {state.cn} ({state.type} certificate)")
    profile_name = state.ca or ctx.config.primary_profile.name
    try:
        profile_label = ctx.profile(state.ca).display_name
    except ConfigError:
        profile_label = "(profile not configured)"
    console.info(f"CA              {profile_name} - {profile_label}")
    if state.description:
        console.info(f"Description     {state.description}")
    console.info(f"Status          {state.status}")
    console.info(f"Subject         {state.subject or '(not recorded)'}")
    console.info(f"Key             {state.key_algorithm or '(unknown)'}")
    console.info(f"Key SHA-256     {state.public_key_sha256 or '(unknown)'}")
    console.info(f"Created         {state.created_at}")
    if state.submitted_at:
        console.info(f"Submitted       {state.submitted_at}")
    if state.server.csr_id or state.server.status:
        console.info(
            f"Server          CSR {state.server.csr_id or '-'} / status {state.server.status or '-'}"
        )
        if state.server.cert_id:
            console.info(f"                certificate id {state.server.cert_id}")
    if state.cert.not_after:
        console.info(f"Certificate     {state.cert.subject}")
        console.info(f"  issuer        {state.cert.issuer}")
        console.info(f"  serial        {state.cert.serial}")
        console.info(
            f"  validity      {state.cert.not_before} .. {state.cert.not_after} ({state.days_remaining} days)"
        )
        console.info(f"  key           {state.cert.key}")
        console.info(f"  SANs          {', '.join(state.cert.sans) or '(none)'}")
        console.info(f"  SHA-256       {state.cert.sha256}")
        console.info(f"  chain verified {_yes_no(state.cert.verified)}")
    if state.p12_path:
        console.info(f"PKCS#12         {state.p12_path}")
        console.info(f"  SHA-256       {state.p12_sha256}")
    console.info(f"Directory       {ctx.store.path(state)}")
    console.info(f"Auto-renew      {_yes_no(state.auto_renew)}")
    for target in state.deploy:
        files = ", ".join(str(target[k]) for k in ("cert", "key", "chain", "fullchain", "bundle", "p12") if target.get(k))
        console.info(f"Deploy '{target.get('name')}'  {files}")
        if target.get("hook"):
            console.info(f"  hook          {target['hook']}")
        if target.get("last_deployed"):
            console.info(f"  last deployed {target['last_deployed']}")
        if target.get("last_error"):
            console.info(f"  last error    {target['last_error']}")
    if state.notes:
        console.info("Notes")
        for note in state.notes[-10:]:
            console.info(f"  - {note}")
    if state.history:
        console.info("History")
        for entry in state.history[-10:]:
            detail = f" — {entry.get('detail')}" if entry.get("detail") else ""
            console.info(f"  {entry.get('at')}  {entry.get('status')}{detail}")
    warning = expiry_warning(state)
    if warning:
        console.warning(warning)


def cmd_show(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    if args.json:
        print(
            json.dumps(
                {**state.to_dict(), "days_remaining": state.days_remaining}, indent=2, default=str
            )
        )
        return 0
    _print_state(console, ctx, state)
    return 0


def cmd_wait(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    if not state.is_pending and state.status != "SIGNED":
        if args.json:
            print(
                json.dumps(
                    {**state.to_dict(), "days_remaining": state.days_remaining},
                    indent=2,
                    default=str,
                )
            )
        else:
            console.info(f"{state.alias} is {state.status}; nothing to wait for.")
        return 0
    from .workflow import wait_for_certificate

    state = wait_for_certificate(
        ctx,
        state,
        progress=console.progress,
        timeout=parse_duration(args.timeout),
        interval=parse_duration(args.interval),
        export=not args.no_export,
        require_verified_chain=not args.allow_unverified_chain,
    )
    payload = {
        "alias": state.alias,
        "status": state.status,
        "certificate": str(ctx.store.cert_path(state)),
        "p12": state.p12_path,
        "not_after": state.cert.not_after,
        "days_remaining": state.days_remaining,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        console.info(
            f"Certificate for '{state.alias}' is ready ({state.cert.not_after}, {state.days_remaining} days)."
        )
        if state.p12_path:
            console.info(f"PKCS#12: {state.p12_path}")
    return 0


def cmd_download(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    state = download_and_export(
        ctx,
        state,
        progress=console.progress,
        export=not args.no_export,
        require_verified_chain=not args.allow_unverified_chain,
        password=_read_secret_option(
            args, what="PKCS#12 passphrase", prompt_label="PKCS#12 passphrase", required=False
        ),
    )
    payload = {
        "alias": state.alias,
        "status": state.status,
        "certificate": str(ctx.store.cert_path(state)),
        "chain": str(ctx.store.file(state, "chain.pem")),
        "p12": state.p12_path,
        "not_after": state.cert.not_after,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        console.info(f"Certificate stored: {payload['certificate']}")
        if state.p12_path:
            console.info(f"PKCS#12 written:   {state.p12_path}")
    return 0


def cmd_export(args) -> int:
    from .exporter import get_format
    from .workflow import export_certificate

    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    if args.stored:
        # Re-write pyCertWiz's own copy in its store (protected with the saved secret).
        if args.format or args.pem or args.no_key_passphrase or args.encryption:
            raise PyCertError("--stored re-writes pyCertWiz's own PKCS#12 copy; it takes no format options")
        path = export_p12(ctx, state, out=None, progress=console.progress)
        if args.json:
            print(json.dumps({"alias": state.alias, "p12": str(path)}, indent=2))
        else:
            console.info(str(path))
        return 0
    fmt = get_format("pem-files" if args.pem else (args.format or "p12"))
    password, no_passphrase = None, False
    if fmt.has_key:
        if args.no_key_passphrase and fmt.bundle:
            raise PyCertError(f"a {fmt.label} is always protected with a passphrase")
        password, no_passphrase = _key_passphrase_choice(args, f"the export of '{state.alias}'")
    elif args.no_key_passphrase:
        raise PyCertError(f"a {fmt.label} holds no private key; there is no passphrase to leave out")
    destination = Path(args.out).expanduser() if args.out else Path.cwd()
    result = export_certificate(
        ctx,
        state.alias,
        destination,
        format=fmt.name,
        encryption=args.encryption or "",
        password=password,
        no_passphrase=no_passphrase,
        include_chain=not args.no_chain,
        overwrite=args.force,
        progress=console.progress,
    )
    if args.json:
        print(json.dumps({"alias": state.alias, **result.as_dict()}, indent=2))
    else:
        for name, path in result.files.items():
            console.info(f"{name}: {path}")
    return 0


def cmd_verify(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    report = verify(ctx, args.alias, check_p12=not args.no_p12)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
    else:
        console.info(f"Verifying '{args.alias}'")
        for name, passed, detail in report.checks:
            mark = "OK  " if passed else "FAIL"
            console.info(f"  [{mark}] {name}" + (f": {detail}" if detail else ""))
        for warning in report.warnings:
            console.info(f"  [WARN] {warning}")
        if report.chain:
            console.info("")
            for index, cert in enumerate(report.chain.chain):
                description = certs.describe_certificate(cert)
                role = (
                    "leaf"
                    if index == 0
                    else ("root" if index == len(report.chain.chain) - 1 else "intermediate")
                )
                console.info(f"  [{index}] {role}: {description.subject}")
                console.info(f"      expires {description.not_after.date()}  {description.key}")
    return 0 if report.ok else 4


def cmd_renew(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    pins: "list[str]" = [args.pin] if args.pin else []
    if args.due is not None:
        if args.alias:
            raise PyCertError("use either an alias or --due, not both")
        if args.due < 0:
            raise PyCertError("--due must be zero or more days")
        if not args.dry_run:
            _confirm(args, "Renew all certificates due for renewal?", "all")
        results = renew_due(
            ctx,
            args.due,
            dry_run=args.dry_run,
            ca=getattr(args, "ca", None) or "",
            include_manual=getattr(args, "include_manual", False),
            progress=console.progress,
            on_pin=pins.append,
            wait=args.wait,
            timeout=parse_duration(args.timeout),
            interval=parse_duration(args.interval),
            export=not args.no_export,
            require_verified_chain=not args.allow_unverified_chain,
            key_algorithm=args.key_algorithm,
            rsa_bits=args.rsa_bits,
            ec_curve=args.ec_curve,
            email=args.email,
            san_dns=[] if args.clear_san_dns else args.san_dns,
            san_email=[] if args.clear_san_email else args.san_email,
            san_ip=[] if args.clear_san_ip else args.san_ip,
        )
        payload = {
            "dry_run": args.dry_run,
            "renewed": [
                {
                    "alias": state.alias,
                    "status": state.status,
                    "renewal": state.renewal,
                    "not_after": state.cert.not_after,
                    "error": error,
                }
                for state, error in results
            ],
            "pins": pins,
        }
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
        else:
            if not results:
                console.info("No certificates are due for renewal.")
            for state, error in results:
                if error:
                    console.info(f"{state.alias}: FAILED — {error}")
                elif args.dry_run:
                    console.info(f"{state.alias}: would renew ({state.days_remaining} days remaining)")
                else:
                    console.info(f"{state.alias}: {state.status}")
        return 1 if any(error for _state, error in results) else 0
    if not args.alias:
        raise PyCertError("an alias or --due DAYS is required")
    state = ctx.store.get(args.alias)
    _confirm(args, f"Renew '{state.alias}' ({state.cn})?", state.alias)
    pin = _read_pin(args)
    pins = [pin] if pin else []
    state = renew(
        ctx,
        args.alias,
        progress=console.progress,
        on_pin=pins.append,
        wait=args.wait,
        timeout=parse_duration(args.timeout),
        interval=parse_duration(args.interval),
        export=not args.no_export,
        require_verified_chain=not args.allow_unverified_chain,
        key_algorithm=args.key_algorithm,
        rsa_bits=args.rsa_bits,
        ec_curve=args.ec_curve,
        email=args.email,
        san_dns=[] if args.clear_san_dns else args.san_dns,
        san_email=[] if args.clear_san_email else args.san_email,
        san_ip=[] if args.clear_san_ip else args.san_ip,
        pin=pin,
    )
    payload = {
        "alias": state.alias,
        "status": state.status,
        "renewal": state.renewal,
        "pin": pins[0] if pins else None,
        "p12": state.p12_path,
        "not_after": state.cert.not_after,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        console.info(f"Renewal for '{state.alias}' is {state.status}.")
        if state.renewal:
            console.info(f"Run 'pycert wait {state.alias}' once the RA has approved it.")
    return 0


def cmd_proxy(args) -> int:
    """Create a short-lived RFC 3820 proxy bundle from a stored certificate."""
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    out = Path(args.out).expanduser() if args.out else ctx.store.path(state) / "proxy.pem"
    password = _read_secret_option(
        args, what="proxy key password", prompt_label="Proxy key password", required=False
    )
    result = create_proxy_bundle(
        ctx,
        args.alias,
        out,
        hours=args.hours,
        path_length=args.path_length,
        limited=args.limited,
        rsa_bits=args.rsa_bits,
        password=password,
        remove=args.remove,
    )
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, default=str))
    else:
        action = "created and removed" if result.removed else "created"
        console.info(f"Proxy bundle {action}: {result.path}")
        console.info(f"  subject:   {result.subject}")
        console.info(f"  issuer:    {result.issuer}")
        console.info(f"  valid:     {result.not_before} .. {result.not_after}")
    return 0


def cmd_watch(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    if args.max_cycles is not None and args.max_cycles < 1:
        raise PyCertError("--max-cycles must be at least 1")
    ctx = _context(args)
    max_cycles = 1 if args.once else args.max_cycles
    report = watch(
        ctx,
        interval=parse_duration(args.interval),
        export=not args.no_export,
        max_cycles=max_cycles,
        progress=console.progress,
        require_verified_chain=not args.allow_unverified_chain,
    )
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        console.info(
            "watch finished: %d cycle(s), %d polled, %d downloaded, %d error(s)"
            % (report.cycles, report.polled, report.downloaded, len(report.errors))
        )
        for alias, error in report.errors:
            console.info(f"  {alias}: {error}")
    return 1 if report.errors else 0


def cmd_revoke(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    _confirm(args, f"Revoke '{state.alias}' ({state.cn})?", state.alias)
    state = revoke(ctx, args.alias, reason=args.reason, progress=console.progress)
    if args.json:
        print(json.dumps({"alias": state.alias, "status": state.status}, indent=2))
    else:
        console.info(f"'{state.alias}' is now {state.status}.")
    return 0


def cmd_import(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    password = _read_secret_option(
        args, what="PKCS#12 passphrase", prompt_label="Passphrase of the file to import"
    )
    state = import_p12(
        ctx,
        Path(args.path).expanduser(),
        password or "",
        alias=args.alias,
        progress=console.progress,
        require_verified_chain=not args.allow_unverified_chain,
        ca=getattr(args, "ca", None) or "",
    )
    path = export_p12(ctx, state, progress=console.progress)
    if args.json:
        print(json.dumps({"alias": state.alias, "p12": str(path)}, indent=2))
    else:
        console.info(f"Imported '{state.alias}'; re-exported as {path}")
    return 0


def cmd_delete(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    _confirm(args, f"Delete the local copy of '{state.alias}'?", state.alias)
    directory = ctx.store.path(state)
    p12 = Path(state.p12_path) if state.p12_path else None
    if args.keep_p12 and p12 and p12.is_file() and directory not in p12.parents:
        # The .p12 lives outside the request directory; leave it alone.
        ctx.store.delete(state)
        console.info(f"Deleted {directory}; kept {p12}")
    else:
        ctx.store.delete(state)
        if args.json:
            print(json.dumps({"alias": state.alias, "deleted": str(directory)}, indent=2))
        else:
            console.info(f"Deleted {directory}")
    return 0


def cmd_install(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    password, no_passphrase = _key_passphrase_choice(args, "userkey.pem")
    paths = install_pem(
        ctx,
        args.alias,
        Path(args.dir).expanduser(),
        include_chain=args.with_chain,
        password=password,
        no_passphrase=no_passphrase,
        progress=console.progress,
    )
    if args.json:
        print(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))
    else:
        for name, path in paths.items():
            console.info(f"{name}: {path}")
    return 0


def cmd_secret(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    config = load_config(args.config)
    store = SecretStore(config.secrets, config.data_dir, config.profile)
    account = args.account or config.secrets.account
    if args.action == "test":
        if not store.exists(account):
            console.error(f"no secret stored for '{account}' ({store})")
            return 1
        console.info(f"Secret backend OK: {store}")
        return 0
    if args.action == "set":
        if args.generate:
            value = generate_secret(args.length)
        else:
            if not sys.stdin.isatty():
                value = sys.stdin.readline().rstrip("\r\n")
                if not value:
                    raise PyCertError("no secret supplied on stdin")
            else:
                first = getpass.getpass(f"New secret for '{account}': ")
                second = getpass.getpass("Confirm: ")
                if first != second:
                    raise PyCertError("the secrets do not match")
                if not first:
                    raise PyCertError("refusing to store an empty secret")
                value = first
        store.set(value, account)
        if args.json:
            print(json.dumps({"backend": store.backend, "account": account, "stored": True}, indent=2))
        else:
            console.info(f"Stored a secret for '{account}' in {store}")
            if args.generate:
                console.info(f"Generated secret: {value}")
                console.info("Record it somewhere safe; it is also stored in the backend above.")
        return 0
    if args.action == "get":
        value = store.get(account, allow_missing=True)
        if value is None:
            console.error(f"no secret stored for '{account}' in {store}")
            return 1
        if args.show:
            print(value)
        else:
            console.info(f"stored in {store} (use --show to print it)")
        return 0
    if args.action == "rm":
        removed = store.delete(account)
        console.info("removed" if removed else "nothing to remove")
        return 0
    if args.action == "list":
        if store.backend == "file":
            data = store._read_file()  # noqa: SLF001 - listing is best effort
            prefix = f"{store.service}/"
            accounts = sorted(k[len(prefix) :] for k in data if k.startswith(prefix))
            if args.json:
                print(json.dumps({"backend": store.backend, "accounts": accounts}, indent=2))
            else:
                console.info(f"Backend: {store}")
                for name in accounts:
                    console.info(f"  {name}")
                if not accounts:
                    console.info("  (none)")
        else:
            console.info(f"Backend: {store} (the backend cannot enumerate accounts)")
        return 0
    raise PyCertError(f"unknown secret action: {args.action}")


def cmd_doctor(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    from .diagnostics import FAIL, run_doctor

    results = run_doctor(ctx, offline=args.offline)
    if args.json:
        print(json.dumps([result.as_dict() for result in results], indent=2))
    else:
        for result in results:
            console.info("  [%-4s] %-26s %s" % (result.status.upper(), result.name, result.detail))
    return 1 if any(result.status == FAIL for result in results) else 0


def cmd_selftest(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    from .diagnostics import FAIL, run_selftest

    results = run_selftest()
    if args.json:
        print(json.dumps([result.as_dict() for result in results], indent=2))
    else:
        for result in results:
            console.info("  [%-4s] %-24s %s" % (result.status.upper(), result.name, result.detail))
    return 1 if any(result.status == FAIL for result in results) else 0


# ---------------------------------------------------------------------------
# CA profiles
# ---------------------------------------------------------------------------


def cmd_ca(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    config = load_config(args.config)
    action = args.action
    if action == "list":
        from .providers import capabilities_for

        rows = []
        for name, profile in config.cas.items():
            caps = capabilities_for(profile.kind)
            rows.append(
                {
                    "name": name,
                    "kind": profile.kind,
                    "display_name": profile.display_name,
                    "url": profile.ca.base_url,
                    "default": name == config.default_ca,
                    "primary": profile.primary,
                    "user_certificates": caps.user_certificates,
                    "host_certificates": caps.host_certificates,
                }
            )
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        width = max([len("NAME"), *(len(row["name"]) for row in rows)]) + 1
        console.info(f"{'NAME':<{width}} {'KIND':<6} {'ISSUES':<11} URL")
        for row in rows:
            issues = "/".join(k for k, v in (("user", row["user_certificates"]), ("host", row["host_certificates"])) if v)
            marker = " (default)" if row["default"] else ""
            console.info(f"{row['name']:<{width}} {row['kind']:<6} {issues:<11} {row['url']}{marker}")
            console.info(f"{'':{width}} {row['display_name']}")
        return 0
    if action == "show":
        profile = config.profile_for(args.name or config.default_ca)
        data = profile.as_dict()
        data["default"] = profile.name == config.default_ca
        if args.json:
            print(json.dumps(data, indent=2, default=str))
        else:
            for key, value in data.items():
                console.info(f"{key:<14} {value}")
        return 0
    if action == "default":
        if not args.name:
            raise PyCertError("give the name of the CA profile to use by default")
        config.set("default_ca", args.name)
        validate_config(config)
        write_config(config.path, config)
        console.info(f"Default CA is now '{args.name}'.")
        return 0
    if action == "remove":
        if not args.name:
            raise PyCertError("give the name of the CA profile to remove")
        ctx = AppContext.from_config(config)
        users = [s.alias for s in ctx.store.list() if s.ca == args.name]
        if users and not args.force:
            raise PyCertError(
                f"{len(users)} stored certificate(s) belong to '{args.name}' ({', '.join(users[:5])}); "
                "use --force to remove the profile anyway"
            )
        _confirm(args, f"Remove CA profile '{args.name}' from {config.path}?", args.name)
        config.remove_ca(args.name)
        validate_config(config)
        write_config(config.path, config)
        console.info(f"Removed CA profile '{args.name}'.")
        return 0
    if action in ("add-acme", "add-ukca"):
        if not args.name:
            raise PyCertError("give a name for the new CA profile (e.g. letsencrypt)")
        if action == "add-acme":
            if not args.directory:
                raise PyCertError("--directory URL is required for an ACME CA")
            profile = new_acme_profile(
                args.name,
                args.directory,
                display_name=args.display_name or "",
                contact=args.contact or ([config.identity.email] if config.identity.email else []),
                eab_kid=args.eab_kid or "",
                challenge=args.challenge,
                http_mode=args.http_mode,
                webroot=args.webroot or "",
                http_port=args.http_port,
                dns_hook=args.dns_hook or "",
                terms_agreed=args.agree_tos,
                tls_trust=args.tls_trust or "system",
            )
        else:
            if not args.url:
                raise PyCertError("--url is required for a CertWizard-protocol CA")
            profile = new_ukca_profile(
                args.name,
                args.url,
                display_name=args.display_name or "",
                tls_trust=args.tls_trust or "chain",
            )
            for path in args.chain or []:
                from .config import ChainEntry

                source = Path(path).expanduser().resolve()
                if not source.is_file():
                    raise PyCertError(f"chain file not found: {source}")
                entry = ChainEntry(label=source.name, file=str(source))
                entry.sha256 = certs.fingerprint(certs.load_certificates(source.read_bytes())[0])
                profile.chain.append(entry)
        config.add_ca(profile)
        if args.make_default:
            config.set("default_ca", profile.name)
        validate_config(config)
        write_config(config.path, config)
        if args.json:
            print(json.dumps(profile.as_dict(), indent=2, default=str))
        else:
            console.info(f"Added CA profile '{profile.name}' ({profile.kind}) to {config.path}.")
            if profile.kind == "acme" and not profile.acme.terms_agreed:
                console.info(
                    "Read the CA's terms of service ('pycert info --ca %s') and then run "
                    "'pycert config set cas.%s.terms_agreed=true'." % (profile.name, profile.name)
                )
            if profile.kind == "acme" and profile.acme.eab_kid:
                console.info(f"Store the EAB HMAC key with: pycert ca eab {profile.name} --kid {profile.acme.eab_kid}")
        return 0
    if action == "eab":
        if not args.name:
            raise PyCertError("give the name of the ACME CA profile")
        profile = config.profile_for(args.name)
        if profile.kind != "acme":
            raise PyCertError(f"'{args.name}' is not an ACME CA profile")
        if args.kid:
            profile.acme.eab_kid = args.kid
        if not profile.acme.eab_kid:
            raise PyCertError("--kid is required (the key identifier issued by the CA)")
        if sys.stdin.isatty():
            key = getpass.getpass("EAB HMAC key (base64url, from the CA): ").strip()
        else:
            key = sys.stdin.readline().strip()
        if not key:
            raise PyCertError("no EAB HMAC key supplied")
        from .providers.acme import store_eab_key

        ctx = AppContext.from_config(config)
        store_eab_key(ctx, profile.name, key)
        validate_config(config)
        write_config(config.path, config)
        console.info(f"Stored the EAB key for '{profile.name}' (kid {profile.acme.eab_kid}) in {ctx.secrets}.")
        return 0
    raise PyCertError(f"unknown ca action: {action}")  # pragma: no cover - argparse choices


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------


def cmd_deploy(args) -> int:
    from . import deploy as deploy_module

    console = Console(json_mode=args.json, quiet=args.quiet)
    if args.action == "presets":
        if args.json:
            print(json.dumps(deploy_module.PRESETS, indent=2))
        else:
            for name, preset in deploy_module.PRESETS.items():
                console.info(f"{name:<12} {preset['description']}")
        return 0
    if not args.alias:
        raise PyCertError("give the alias of a stored certificate")
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    if args.action == "list":
        if args.json:
            print(json.dumps(state.deploy, indent=2))
        elif not state.deploy:
            console.info(f"'{state.alias}' has no deployment targets.")
        else:
            for target in state.deploy:
                console.info(f"[{target['name']}]")
                for key, value in target.items():
                    if key != "name":
                        console.info(f"  {key:<14} {value}")
        return 0
    if args.action == "add":
        if args.preset:
            target = deploy_module.target_from_preset(
                args.preset,
                name=args.name or "",
                directory=args.dir or "",
                alias=state.alias,
                hook=args.hook,
                owner=args.owner or "",
                group=args.group or "",
            )
        else:
            target = {"name": args.name or "custom"}
            for kind in deploy_module.FILE_KINDS:
                value = getattr(args, kind, None)
                if value:
                    target[kind] = str(Path(value).expanduser().resolve())
            for key in ("cert_mode", "key_mode", "owner", "group", "hook"):
                value = getattr(args, key, None)
                if value:
                    target[key] = value
        if args.no_key_passphrase:
            if not target.get("key"):
                raise PyCertError("--no-key-passphrase applies to a single --key file; bundles are always encrypted")
            _confirm_unencrypted(f"the private key of '{state.alias}' to {target['key']} on every deployment")
            target["unencrypted_key"] = True
            from .util import iso

            target["unencrypted_key_confirmed"] = iso()
        target = deploy_module.add_target(ctx, state, target)
        console.info(f"Added deployment target '{target['name']}' to '{state.alias}'.")
        if args.now:
            state = ctx.store.get(state.alias)
            deploy_module.deploy_state(ctx, state, names=[target["name"]], progress=console.progress)
            console.info("Deployed.")
        return 0
    if args.action == "remove":
        if not args.name:
            raise PyCertError("--name is required")
        deploy_module.remove_target(ctx, state, args.name)
        console.info(f"Removed deployment target '{args.name}' (deployed files were left in place).")
        return 0
    if args.action == "run":
        results = deploy_module.deploy_state(
            ctx, state, names=[args.name] if args.name else None, progress=console.progress, run_hooks=not args.no_hook
        )
        if args.json:
            print(json.dumps([r.as_dict() for r in results], indent=2))
        else:
            for result in results:
                console.info(f"{result.target}: wrote {len(result.written)} file(s)" + (f", ran '{result.hook}'" if result.hook else ""))
        return 0
    raise PyCertError(f"unknown deploy action: {args.action}")  # pragma: no cover - argparse choices


# ---------------------------------------------------------------------------
# Monitoring and reporting
# ---------------------------------------------------------------------------


def cmd_check(args) -> int:
    from .monitor import UNKNOWN, check

    try:
        ctx = _context(args)
        report = check(
            ctx,
            warn_days=args.warn,
            crit_days=args.crit,
            stale_pending_days=args.stale_pending,
            aliases=args.alias or None,
            ca=getattr(args, "ca", None) or "",
            cert_type=args.type or "",
            check_deployments=not args.no_deploy_check,
        )
    except (PyCertError, ValueError) as exc:
        print(f"PYCERT {UNKNOWN} - {exc}")
        return 3
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return report.exit_code
    print(report.summary())
    if args.verbose:
        for finding in report.findings:
            if finding.level != "OK":
                print(f"  [{finding.level}] {finding.alias}: {finding.message}")
    return report.exit_code


def cmd_report(args) -> int:
    from .monitor import inventory

    ctx = _context(args)
    rows = inventory(ctx, ca=getattr(args, "ca", None) or "", cert_type=args.type or "")
    if args.json or args.format == "json":
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if args.format == "csv":
        fields = list(rows[0]) if rows else ["alias"]
        writer = csv.DictWriter(sys.stdout, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return 0
    if not rows:
        print("No certificates.")
        return 0
    print(f"{'ALIAS':<28} {'TYPE':<5} {'CA':<14} {'HEALTH':<8} {'EXPIRES':<11} {'DAYS':>5}  NOTE")
    for row in rows:
        days = "" if row["days_remaining"] is None else str(row["days_remaining"])
        print(
            f"{row['alias'][:28]:<28} {row['type']:<5} {row['ca'][:14]:<14} {row['health']:<8} "
            f"{row['not_after'] or '-':<11} {days:>5}  {row['note'] or row['status']}"
        )
    return 0


def cmd_edit(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    changed = []
    if args.rename_keystore_entry and not args.name:
        raise PyCertError("--rename-keystore-entry needs --name")
    if args.name is not None:
        from .workflow import rename_certificate

        if args.rename_keystore_entry and (args.password_file or args.password_stdin):
            from . import keystore as keystore_module

            if not state.keystore.get("name"):
                raise PyCertError(f"'{state.alias}' is not linked to a Java keystore")
            link = ctx.config.keystore(state.keystore["name"])
            keystore_module.unlock(ctx, link, _keystore_password(args, f"Passphrase for keystore '{link.name}'"))
        state = rename_certificate(
            ctx, state.alias, args.name, keystore_entry=args.rename_keystore_entry, progress=console.progress
        )
        changed.append("name")
    with ctx.store.lock(state):
        state = ctx.store.get(state.alias)
        if args.description is not None:
            state.description = args.description.strip()
            changed.append("description")
        if args.auto_renew is not None:
            state.auto_renew = args.auto_renew
            changed.append("auto-renew")
        if not changed:
            raise PyCertError("nothing to change (use --name, --description or --auto-renew/--no-auto-renew)")
        state.touch()
        ctx.store.save(state)
    if args.json:
        print(json.dumps({"alias": state.alias, "description": state.description, "auto_renew": state.auto_renew}, indent=2))
    else:
        console.info(f"Updated {', '.join(changed)} for '{state.alias}'.")
    return 0


# ---------------------------------------------------------------------------
# Java keystores as a store
# ---------------------------------------------------------------------------


def _keystore_password(args, prompt: str) -> str:
    if getattr(args, "password_file", None) or getattr(args, "password_stdin", False) or getattr(args, "password", None):
        return _read_secret_option(args, what="keystore passphrase", prompt_label=prompt) or ""
    if sys.stdin.isatty():
        return getpass.getpass(f"{prompt}: ")
    line = sys.stdin.readline()
    if not line:
        raise PyCertError("the keystore passphrase is required (stdin, --password-file or a terminal)")
    return line.rstrip("\r\n")


def _print_sync(console: Console, reports) -> None:
    for report in reports:
        console.info(report.summary())
        for problem in report.problems:
            console.warning(f"{report.keystore}: {problem}")


def cmd_keystore(args) -> int:
    from . import keystore as keystore_module

    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    action = args.action
    if action == "list":
        rows = []
        for link in ctx.config.keystores:
            path = ctx.config.resolve(link.path)
            linked = [s.alias for s in ctx.store.list() if s.keystore.get("name") == link.name]
            rows.append({**vars(link), "exists": path.exists(), "linked_certificates": linked})
        if args.json:
            print(json.dumps(rows, indent=2))
        elif not rows:
            console.info("No keystores are linked. Link one with: pycert keystore link PATH")
        for row in rows if not args.json else []:
            flags = ", ".join(k for k, v in (("import", row["auto_import"]), ("write-back", row["write_back"])) if v)
            console.info(f"{row['name']:<16} {row['path']}{'' if row['exists'] else '  (missing)'}")
            console.info(f"{'':16} CA {row['ca'] or ctx.config.primary_profile.name} · {flags or 'read-only'} · "
                         f"{len(row['linked_certificates'])} certificate(s) · passphrase asked each session")
        return 0
    if action == "link":
        if not args.target:
            raise PyCertError("give the keystore file to link, e.g. ~/.ca/cakeystore.pkcs12")
        password = _keystore_password(args, "Keystore passphrase (never stored)")
        link, keystore = keystore_module.link_keystore(
            ctx,
            args.target,
            password,
            name=args.name or "",
            ca=getattr(args, "ca", None) or "",
            auto_import=not args.no_import,
            write_back=not args.no_write,
            create=args.create,
        )
        console.info(f"Linked keystore '{link.name}': {link.path} ({len(keystore.entries)} key entr{'y' if len(keystore.entries) == 1 else 'ies'})")
        reports = [keystore_module.sync(ctx, link, progress=console.progress)]
        if args.json:
            print(json.dumps({"link": vars(link), "sync": [r.as_dict() for r in reports]}, indent=2))
        else:
            _print_sync(console, reports)
        return 0
    if action == "sync":
        links = [ctx.config.keystore(args.target)] if args.target else ctx.config.keystores
        if not links:
            raise PyCertError("no keystores are linked (pycert keystore link PATH)")
        if getattr(args, "password_file", None) or getattr(args, "password_stdin", False) or getattr(args, "password", None):
            if len(links) != 1:
                raise PyCertError("give the keystore name when supplying its passphrase")
            keystore_module.unlock(ctx, links[0], _keystore_password(args, "Keystore passphrase"))
        reports = []
        for link in links:
            try:
                reports.append(keystore_module.sync(ctx, link, progress=console.progress))
            except PyCertError as exc:
                reports.append(keystore_module.SyncReport(keystore=link.name, error=str(exc)))
        if args.json:
            print(json.dumps([r.as_dict() for r in reports], indent=2))
        else:
            _print_sync(console, reports)
        return 1 if any(report.error for report in reports) else 0
    if action == "unlink":
        if not args.target:
            raise PyCertError("give the name of the linked keystore")
        count = keystore_module.unlink_keystore(ctx, args.target)
        console.info(f"Unlinked keystore '{args.target}' ({count} certificate(s) stay managed by pyCertWiz; the file is untouched).")
        return 0
    if action == "import":
        if not args.target:
            raise PyCertError("give the keystore file to import from")
        password = _keystore_password(args, "Keystore passphrase")
        states, problems = keystore_module.import_keystore(
            ctx, args.target, password, ca=getattr(args, "ca", None) or "", progress=console.progress
        )
        if args.json:
            print(json.dumps({"imported": [s.alias for s in states], "problems": problems}, indent=2))
        else:
            for state in states:
                console.info(f"Imported '{state.alias}' ({state.status})")
            for problem in problems:
                console.warning(problem)
            if not states:
                console.info("Nothing new to import.")
        return 0
    raise PyCertError(f"unknown keystore action: {action}")  # pragma: no cover - argparse choices


def cmd_gui(args) -> int:
    from .gui import gui_available, run_gui

    problem = gui_available()
    if problem:
        raise PyCertError(problem)
    if getattr(args, "check", False):
        from .gui.app import check

        return check(args.config)
    return run_gui(config_path=args.config)  # pragma: no cover - starts the Qt event loop


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    """Add the global options.

    On subparsers the defaults are suppressed so that ``pycert --json status``
    is not overwritten by the subparser's default None (a well-known argparse
    foot-gun).
    """
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument("--config", metavar="PATH", default=default, help="configuration file to use")
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="machine-readable JSON output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="suppress progress messages",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="more detail",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="show a traceback on error",
    )


def _add_wait_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--wait", action="store_true", help="wait for signing and export the .p12")
    parser.add_argument(
        "--timeout", default=str(DEFAULT_WAIT_TIMEOUT), help="give up after this long (default 24h)"
    )
    parser.add_argument("--interval", default=str(DEFAULT_WAIT_INTERVAL), help="poll interval (default 60s)")
    parser.add_argument("--no-export", action="store_true", help="do not write a PKCS#12 file")
    parser.add_argument(
        "--allow-unverified-chain",
        action="store_true",
        help="accept a certificate whose chain does not reach a configured trust anchor",
    )


def _add_pin_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pin", help="PIN (visible in the process list; prefer --pin-file)")
    parser.add_argument("--pin-file", metavar="PATH", help="read the PIN from a file")
    parser.add_argument("--pin-stdin", action="store_true", help="read the PIN from stdin")
    parser.add_argument("--generate-pin", action="store_true", help="generate a random PIN and print it")


def _add_password_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--password", help="PKCS#12 passphrase (visible in the process list)")
    parser.add_argument("--password-file", metavar="PATH", help="read the passphrase from a file")
    parser.add_argument("--password-stdin", action="store_true", help="read the passphrase from stdin")


def _program_name() -> str:
    """'pycertwiz' when run under that name, otherwise 'pycert' (both are installed)."""
    return "pycertwiz" if Path(sys.argv[0]).name.lower().startswith("pycertwiz") else "pycert"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_program_name(),
        description=(
            "Manage user and host certificates from the UK e-Science CA (and ACME CAs): "
            "request, track, renew, deploy, monitor and export them."
        ),
        epilog="Run 'pycert <command> --help' for details. Documentation: docs/",
    )
    parser.add_argument("--version", action="version", version=f"pyCertWiz {__version__}")
    _add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_ca_option(command: argparse.ArgumentParser, help_text: str = "CA profile (default: default_ca)") -> None:
        command.add_argument("--ca", metavar="NAME", help=help_text)

    init = sub.add_parser("init", help="create a configuration directory and a saved secret")
    _add_common(init, suppress=True)
    init.add_argument("directory", nargs="?", default=str(Path.home() / ".config" / "pycert"))
    init.add_argument("--profile", default="default")
    init.add_argument("--email")
    init.add_argument("--ra", help="default RA as 'OU L'")
    init.add_argument("--base-url", help="CA server base URL")
    init.add_argument("--backend", help="secret backend (auto, keychain, file, command, ...)")
    init.add_argument("--force", action="store_true", help="overwrite an existing configuration")
    init.set_defaults(func=cmd_init)

    config = sub.add_parser("config", help="inspect and verify the configuration")
    _add_common(config, suppress=True)
    config.add_argument("action", choices=["show", "check", "path", "set"])
    config.add_argument("assignments", nargs="*", help="key=value assignments for 'set'")
    config.set_defaults(func=cmd_config)

    ping = sub.add_parser("ping", help="check connectivity to the CA server")
    _add_common(ping, suppress=True)
    add_ca_option(ping, "CA profile (default: the primary CA)")
    ping.add_argument("--all", action="store_true", help="ping every configured CA")
    ping.set_defaults(func=cmd_ping)

    ras = sub.add_parser("ras", help="list the RAs published by the CA")
    _add_common(ras, suppress=True)
    add_ca_option(ras, "CertWizard-protocol CA profile (default: the primary CA)")
    ras.set_defaults(func=cmd_ras)

    info = sub.add_parser("info", help="show CA information and the message of the day")
    _add_common(info, suppress=True)
    add_ca_option(info, "CA profile (default: the primary CA)")
    info.set_defaults(func=cmd_info)

    ca_cmd = sub.add_parser("ca", help="list, add and remove CA profiles")
    _add_common(ca_cmd, suppress=True)
    ca_cmd.add_argument("action", choices=["list", "show", "default", "add-acme", "add-ukca", "remove", "eab"])
    ca_cmd.add_argument("name", nargs="?", help="CA profile name")
    ca_cmd.add_argument("--display-name", help="human-friendly name shown in listings and the GUI")
    ca_cmd.add_argument("--directory", help="ACME directory URL (add-acme)")
    ca_cmd.add_argument("--url", help="CertWizard-protocol base URL (add-ukca)")
    ca_cmd.add_argument("--chain", action="append", metavar="PEM", help="CA certificate to pin (add-ukca, repeatable)")
    ca_cmd.add_argument("--contact", action="append", help="ACME account contact e-mail (repeatable)")
    ca_cmd.add_argument("--agree-tos", action="store_true", help="accept the ACME CA's terms of service")
    ca_cmd.add_argument("--eab-kid", help="ACME External Account Binding key id")
    ca_cmd.add_argument("--kid", help="EAB key id (eab)")
    ca_cmd.add_argument("--challenge", choices=["http-01", "dns-01"], default="http-01")
    ca_cmd.add_argument("--http-mode", choices=["standalone", "webroot"], default="standalone")
    ca_cmd.add_argument("--http-port", type=int, default=80)
    ca_cmd.add_argument("--webroot", help="web server document root for http-01 webroot mode")
    ca_cmd.add_argument("--dns-hook", help="command that adds/removes dns-01 TXT records")
    ca_cmd.add_argument("--tls-trust", choices=["chain", "system", "both"])
    ca_cmd.add_argument("--make-default", action="store_true", help="use the new profile for new requests")
    ca_cmd.add_argument("--force", action="store_true", help="remove a profile that still has certificates")
    ca_cmd.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ca_cmd.set_defaults(func=cmd_ca)

    request = sub.add_parser("request", help="create a key, build a CSR and submit it")
    _add_common(request, suppress=True)
    request.add_argument(
        "cn", nargs="*", help="common name (host name for --type host); several host names request several certificates"
    )
    request.add_argument("--from-file", metavar="PATH", help="read host names from a file, one per line")
    add_ca_option(request)
    request.add_argument("--description", help="free-text note stored with the request")
    request.add_argument("--keystore", metavar="NAME", help="store the issued certificate in this linked Java keystore")
    request.add_argument(
        "--deploy-preset",
        choices=["grid-host", "globus-user", "nginx", "apache"],
        help="deploy the issued certificate with this layout (see 'pycert deploy presets')",
    )
    request.add_argument("--deploy-dir", help="directory for --deploy-preset (default: the preset's)")
    request.add_argument("--deploy-hook", help="command to run after deployment (e.g. 'systemctl reload nginx')")
    request.add_argument("--type", choices=["user", "host"], default="user")
    request.add_argument("--email", help="contact e-mail (default: identity.email)")
    request.add_argument("--alias", help="local name for this request (default: the common name)")
    request.add_argument("--ra", help="RA as 'OU L'")
    request.add_argument("--ou")
    request.add_argument("--l")
    request.add_argument("--o")
    request.add_argument("--c")
    request.add_argument("--key-algorithm", choices=["rsa", "ec"])
    request.add_argument("--rsa-bits", type=int)
    request.add_argument("--ec-curve", choices=["P-256", "P-384", "P-521"])
    request.add_argument("--san-dns", action="append", default=[], help="extra DNS SAN (repeatable)")
    request.add_argument("--san-email", action="append", default=[], help="extra e-mail SAN")
    request.add_argument("--san-ip", action="append", default=[], help="IP SAN")
    request.add_argument(
        "--extensions", nargs="+", help="CSR extensions (san key_usage extended_key_usage basic_constraints)"
    )
    request.add_argument("--hash", help="CSR signature hash (default sha256)")
    request.add_argument("--auth", help="alias of the certificate used to authenticate a host request")
    _add_pin_options(request)
    _add_wait_options(request)
    request.set_defaults(func=cmd_request)

    wait = sub.add_parser("wait", help="poll the CA until the certificate is signed")
    _add_common(wait, suppress=True)
    wait.add_argument("alias")
    _add_wait_options(wait)
    wait.set_defaults(func=cmd_wait)

    status = sub.add_parser("status", help="show local status (and optionally refresh it)")
    _add_common(status, suppress=True)
    status.add_argument("alias", nargs="?")
    status.add_argument("--refresh", action="store_true", help="ask the CA for the current status")
    status.set_defaults(func=cmd_status)

    listing = sub.add_parser("list", help="list local certificate requests")
    _add_common(listing, suppress=True)
    listing.add_argument("--no-audit", action="store_true", help="skip the permission audit")
    add_ca_option(listing, "only certificates from this CA profile")
    listing.add_argument("--type", choices=["user", "host"], help="only user or host certificates")
    listing.set_defaults(func=cmd_list)

    show = sub.add_parser("show", help="show one certificate request in detail")
    _add_common(show, suppress=True)
    show.add_argument("alias")
    show.set_defaults(func=cmd_show)

    download = sub.add_parser("download", help="download and store an issued certificate")
    _add_common(download, suppress=True)
    download.add_argument("alias")
    download.add_argument("--no-export", action="store_true")
    download.add_argument("--allow-unverified-chain", action="store_true")
    _add_password_options(download)
    download.set_defaults(func=cmd_download)

    from .exporter import FORMATS, KEY_ENCRYPTIONS, P12_ENCRYPTIONS

    export = sub.add_parser(
        "export", help="export a certificate (PKCS#12 by default; a key needs a new passphrase)"
    )
    _add_common(export, suppress=True)
    export.add_argument("alias")
    export.add_argument(
        "--format", choices=list(FORMATS), help="what to write (default p12): " + ", ".join(FORMATS)
    )
    export.add_argument(
        "--encryption",
        choices=[*P12_ENCRYPTIONS, *KEY_ENCRYPTIONS],
        help="p12: aes256 (default) or 3des (legacy Java/Windows); PEM keys: pkcs8 (default) or traditional",
    )
    export.add_argument("--out", help="output file, or directory (default: the current directory)")
    export.add_argument("--no-chain", action="store_true", help="leave the issuing chain out (p12 and PEM formats)")
    export.add_argument("--force", action="store_true", help="overwrite existing files")
    export.add_argument("--pem", action="store_true", help="the same as --format pem-files")
    export.add_argument(
        "--stored", action="store_true", help="re-write pyCertWiz's own PKCS#12 copy in its store (saved secret)"
    )
    export.add_argument(
        "--no-key-passphrase",
        action="store_true",
        help="key and pem-files only: write the key without a passphrase (asks you to confirm)",
    )
    _add_password_options(export)
    export.set_defaults(func=cmd_export)

    verify_cmd = sub.add_parser("verify", help="verify key, certificate, chain and PKCS#12")
    _add_common(verify_cmd, suppress=True)
    verify_cmd.add_argument("alias")
    verify_cmd.add_argument("--no-p12", action="store_true", help="skip the PKCS#12 check")
    verify_cmd.set_defaults(func=cmd_verify)

    renew_cmd = sub.add_parser("renew", help="request a renewal authenticated by the current key")
    _add_common(renew_cmd, suppress=True)
    renew_cmd.add_argument("alias", nargs="?")
    renew_cmd.add_argument(
        "--due", type=int, metavar="DAYS", help="renew every certificate expiring within DAYS"
    )
    renew_cmd.add_argument("--dry-run", action="store_true", help="only list what --due would renew")
    add_ca_option(renew_cmd, "with --due: only certificates from this CA profile")
    renew_cmd.add_argument(
        "--include-manual", action="store_true", help="with --due: include certificates with auto-renew switched off"
    )
    renew_cmd.add_argument(
        "--email", help="contact e-mail (default: the one the CA holds for the certificate; a different one replaces it)"
    )
    renew_cmd.add_argument("--key-algorithm", choices=["rsa", "ec"])
    renew_cmd.add_argument("--rsa-bits", type=int)
    renew_cmd.add_argument("--ec-curve", choices=["P-256", "P-384", "P-521"])
    renew_cmd.add_argument("--san-dns", action="append")
    renew_cmd.add_argument("--san-email", action="append")
    renew_cmd.add_argument("--san-ip", action="append")
    renew_cmd.add_argument("--clear-san-dns", action="store_true", help="drop all DNS SANs")
    renew_cmd.add_argument("--clear-san-email", action="store_true", help="drop all e-mail SANs")
    renew_cmd.add_argument("--clear-san-ip", action="store_true", help="drop all IP SANs")
    renew_cmd.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    _add_pin_options(renew_cmd)
    _add_wait_options(renew_cmd)
    renew_cmd.set_defaults(func=cmd_renew)

    revoke_cmd = sub.add_parser("revoke", help="revoke a certificate")
    _add_common(revoke_cmd, suppress=True)
    revoke_cmd.add_argument("alias")
    revoke_cmd.add_argument("--reason", default="unspecified", help="revocation reason")
    revoke_cmd.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    revoke_cmd.set_defaults(func=cmd_revoke)

    import_cmd = sub.add_parser("import", help="import an existing PKCS#12 file")
    _add_common(import_cmd, suppress=True)
    import_cmd.add_argument("path")
    import_cmd.add_argument("--alias")
    import_cmd.add_argument("--allow-unverified-chain", action="store_true")
    add_ca_option(import_cmd, "CA profile the certificate belongs to (default: the primary CA)")
    _add_password_options(import_cmd)
    import_cmd.set_defaults(func=cmd_import)

    delete_cmd = sub.add_parser("delete", help="delete the local files for a request")
    _add_common(delete_cmd, suppress=True)
    delete_cmd.add_argument("alias")
    delete_cmd.add_argument(
        "--keep-p12", action="store_true", help="keep an exported .p12 outside the request directory"
    )
    delete_cmd.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    delete_cmd.set_defaults(func=cmd_delete)

    install = sub.add_parser("install", help="write usercert.pem / encrypted userkey.pem (GSI layout)")
    _add_common(install, suppress=True)
    install.add_argument("alias")
    install.add_argument("--dir", default="~/.globus")
    install.add_argument("--with-chain", action="store_true", help="append issuers to usercert.pem")
    install.add_argument(
        "--no-key-passphrase", action="store_true", help="write userkey.pem without a passphrase (asks you to confirm)"
    )
    _add_password_options(install)
    install.set_defaults(func=cmd_install)

    proxy = sub.add_parser("proxy", help="create a short-lived RFC 3820 proxy bundle")
    _add_common(proxy, suppress=True)
    proxy.add_argument("alias", help="stored certificate to delegate from")
    proxy.add_argument("--out", help="output PEM bundle (default: request directory/proxy.pem)")
    proxy.add_argument("--hours", type=int, default=12, help="proxy lifetime in hours (default 12)")
    proxy.add_argument("--path-length", type=int, help="RFC 3820 path length constraint")
    proxy.add_argument("--limited", action="store_true", help="use the limited-proxy policy")
    proxy.add_argument("--rsa-bits", type=int, default=2048, help="proxy key size (default 2048)")
    proxy.add_argument(
        "--remove",
        action="store_true",
        help="verify the bundle and immediately remove it",
    )
    _add_password_options(proxy)
    proxy.set_defaults(func=cmd_proxy)

    secret = sub.add_parser("secret", help="manage the saved PKCS#12 passphrase")
    _add_common(secret, suppress=True)
    secret.add_argument("action", choices=["set", "get", "rm", "list", "test"])
    secret.add_argument("--account", help="secret name (default: from the configuration)")
    secret.add_argument("--generate", action="store_true", help="generate a random secret")
    secret.add_argument("--length", type=int, default=32)
    secret.add_argument("--show", action="store_true", help="print the secret (get)")
    secret.set_defaults(func=cmd_secret)

    watch_cmd = sub.add_parser("watch", help="poll pending requests and export them as they are signed")
    _add_common(watch_cmd, suppress=True)
    watch_cmd.add_argument(
        "--interval", default=str(DEFAULT_WAIT_INTERVAL), help="poll interval (default 60s)"
    )
    watch_cmd.add_argument("--once", action="store_true", help="run a single cycle")
    watch_cmd.add_argument("--max-cycles", type=int, help="stop after N cycles")
    watch_cmd.add_argument(
        "--no-export", action="store_true", help="download certificates but do not write .p12 files"
    )
    watch_cmd.add_argument(
        "--allow-unverified-chain",
        action="store_true",
        help="accept certificates whose chain does not validate",
    )
    watch_cmd.set_defaults(func=cmd_watch)

    keystore_cmd = sub.add_parser("keystore", help="use Java PKCS#12 keystores (cakeystore.pkcs12) as a store")
    _add_common(keystore_cmd, suppress=True)
    keystore_cmd.add_argument("action", choices=["list", "link", "sync", "unlink", "import"])
    keystore_cmd.add_argument("target", nargs="?", help="keystore file (link, import) or linked name (sync, unlink)")
    keystore_cmd.add_argument("--name", help="name for the link (default: from the file name)")
    add_ca_option(keystore_cmd, "CA profile the keystore's certificates belong to (default: the primary CA)")
    keystore_cmd.add_argument("--no-import", action="store_true", help="link: do not import new entries automatically")
    keystore_cmd.add_argument("--no-write", action="store_true", help="link: never write to the keystore")
    keystore_cmd.add_argument("--create", action="store_true", help="link: the file is created on the first write")
    _add_password_options(keystore_cmd)
    keystore_cmd.set_defaults(func=cmd_keystore)

    deploy_cmd = sub.add_parser("deploy", help="deploy certificates to services (files + reload hook)")
    _add_common(deploy_cmd, suppress=True)
    deploy_cmd.add_argument("action", choices=["list", "add", "remove", "run", "presets"])
    deploy_cmd.add_argument("alias", nargs="?")
    deploy_cmd.add_argument("--name", help="target name")
    deploy_cmd.add_argument("--preset", choices=["grid-host", "globus-user", "nginx", "apache"])
    deploy_cmd.add_argument("--dir", help="directory for a preset")
    for kind, help_text in (
        ("cert", "write the leaf certificate here"),
        ("key", "write the private key here (encrypted with the saved secret; see --no-key-passphrase)"),
        ("chain", "write the issuer chain here"),
        ("fullchain", "write leaf + issuers here"),
        ("bundle", "write the encrypted key + leaf + issuers in one PEM here"),
        ("p12", "write a PKCS#12 copy here"),
    ):
        deploy_cmd.add_argument(f"--{kind}", metavar="PATH", help=help_text)
    deploy_cmd.add_argument("--cert-mode", help="mode for certificate files (default 0644)")
    deploy_cmd.add_argument("--key-mode", help="mode for key files (default 0600)")
    deploy_cmd.add_argument("--owner", help="chown files to this user")
    deploy_cmd.add_argument("--group", help="chgrp files to this group")
    deploy_cmd.add_argument("--hook", help="command run after the files are written")
    deploy_cmd.add_argument(
        "--no-key-passphrase",
        action="store_true",
        help="write the single --key file without a passphrase (asks you to confirm; never for bundles)",
    )
    deploy_cmd.add_argument("--now", action="store_true", help="deploy immediately after adding")
    deploy_cmd.add_argument("--no-hook", action="store_true", help="run: write files but skip hooks")
    deploy_cmd.set_defaults(func=cmd_deploy)

    check_cmd = sub.add_parser(
        "check", help="monitoring probe: exit 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (Nagios/Icinga)"
    )
    _add_common(check_cmd, suppress=True)
    check_cmd.add_argument("alias", nargs="*", help="only these certificates (default: all)")
    check_cmd.add_argument("--warn", type=int, default=30, metavar="DAYS", help="WARNING below this (default 30)")
    check_cmd.add_argument("--crit", type=int, default=7, metavar="DAYS", help="CRITICAL below this (default 7)")
    check_cmd.add_argument(
        "--stale-pending", type=int, default=14, metavar="DAYS", help="WARNING for requests pending this long"
    )
    add_ca_option(check_cmd, "only certificates from this CA profile")
    check_cmd.add_argument("--type", choices=["user", "host"])
    check_cmd.add_argument("--no-deploy-check", action="store_true", help="do not compare deployed files")
    check_cmd.set_defaults(func=cmd_check)

    report = sub.add_parser("report", help="inventory of all certificates (table, CSV or JSON)")
    _add_common(report, suppress=True)
    report.add_argument("--format", choices=["table", "csv", "json"], default="table")
    add_ca_option(report, "only certificates from this CA profile")
    report.add_argument("--type", choices=["user", "host"])
    report.set_defaults(func=cmd_report)

    edit = sub.add_parser("edit", help="rename a stored certificate, or change its description or auto-renew flag")
    _add_common(edit, suppress=True)
    edit.add_argument("alias")
    edit.add_argument("--name", help="give the certificate a new name")
    edit.add_argument(
        "--rename-keystore-entry",
        action="store_true",
        help="with --name: rename its entry in the linked Java keystore too (asks for the keystore passphrase)",
    )
    edit.add_argument("--password-file", metavar="PATH", help="keystore passphrase from a file (--rename-keystore-entry)")
    edit.add_argument("--password-stdin", action="store_true", help="keystore passphrase on stdin (--rename-keystore-entry)")
    edit.add_argument("--description")
    edit.add_argument("--auto-renew", dest="auto_renew", action="store_true", default=None)
    edit.add_argument("--no-auto-renew", dest="auto_renew", action="store_false")
    edit.set_defaults(func=cmd_edit)

    doctor = sub.add_parser("doctor", help="diagnose the installation and the connection")
    _add_common(doctor, suppress=True)
    doctor.add_argument("--offline", action="store_true", help="skip network checks")
    doctor.set_defaults(func=cmd_doctor)

    selftest = sub.add_parser("selftest", help="run offline cryptographic self-checks")
    _add_common(selftest, suppress=True)
    selftest.set_defaults(func=cmd_selftest)

    gui = sub.add_parser("gui", help="start the graphical interface")
    _add_common(gui, suppress=True)
    gui.add_argument("--check", action="store_true", help="open, render and close the main window, then exit (for tests)")
    gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: "list[str] | None" = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(
        json_mode=getattr(args, "json", False),
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
    )
    try:
        return int(args.func(args) or 0)
    except TimeoutWaiting as exc:
        console.error(str(exc))
        return 3
    except ChainError as exc:
        console.error(str(exc))
        return 4
    except PyCertError as exc:
        console.error(str(exc))
        if getattr(args, "debug", False):
            raise
        return 1
    except KeyboardInterrupt:
        console.error("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - last resort for a clean message
        if getattr(args, "debug", False):
            raise
        console.error(f"unexpected error: {exc} (use --debug for a traceback)")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
