"""pycert command line interface.

Design goals: scriptable (``--json``, meaningful exit codes), quiet by default,
never print a secret unless it is the point of the command, and make the
common case one line::

    pycert request "Jane Doe" --wait

Exit codes
----------
0   success
1   error (configuration, cryptographic, CA rejection, not found)
2   command line usage error (argparse)
3   timed out waiting for the CA to sign (the request is still stored)
4   certificate chain did not validate
"""

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from . import __version__, certs
from .compat import merge_dicts
from .config import ConfigError, init_config, load_config, write_config
from .errors import ChainError, PyCertError, TimeoutWaiting
from .secrets_store import SecretStore, generate_secret
from .store import PENDING_STATUSES, RequestState
from .util import parse_duration
from .workflow import (
    DEFAULT_WAIT_INTERVAL,
    DEFAULT_WAIT_TIMEOUT,
    AppContext,
    RequestSpec,
    create_request,
    download_and_export,
    expiry_warning,
    export_p12,
    import_p12,
    install_pem,
    poll_once,
    refresh_all,
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
    return AppContext.from_config(config)


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
    directory = Path(getattr(args, "directory", None) or (Path.home() / ".config" / "pycert")).expanduser()
    if directory.suffix.lower() == ".toml":
        directory = directory.parent
    config_path = directory / "pycert.toml"
    if config_path.exists() and not getattr(args, "force", False):
        raise PyCertError(f"{config_path} already exists (use --force to overwrite)")
    config = init_config(directory, profile=getattr(args, "profile", "default"))
    config.identity.email = getattr(args, "email", None) or config.identity.email
    config.identity.ra = getattr(args, "ra", None) or config.identity.ra
    base_url = getattr(args, "base_url", None)
    if base_url:
        config.ca.base_url = base_url
        from .config import validate_config

        validate_config(config)
    backend = getattr(args, "backend", None)
    if backend:
        config.secrets.backend = backend
    write_config(config.path, config)

    ctx = AppContext.from_config(config)
    ctx.secrets.ensure(config.secrets.account)
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
                    merge_dicts(
                        config.as_dict(),
                        {"secret_backend": str(SecretStore(config.secrets, config.data_dir, config.profile))},
                    ),
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
    client = ctx.client()
    started = time.monotonic()
    ok = client.ping()
    elapsed = time.monotonic() - started
    payload = {
        "ok": ok,
        "base_url": ctx.config.ca.base_url,
        "latency_ms": round(elapsed * 1000, 1),
        "tls": client.last_tls.as_dict() if client.last_tls else None,
        "error": client.last_error or None,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if ok:
            console.info(f"pong from {ctx.config.ca.base_url} in {payload['latency_ms']} ms")
            if client.last_tls:
                tls = client.last_tls
                console.info(f"TLS peer: {tls.subject}")
                console.info(f"  issued by {tls.issuer}")
                console.info(f"  SHA-256   {tls.fingerprint}")
                console.info(f"  expires   {tls.not_after.date()}")
        else:
            detail = f": {client.last_error}" if client.last_error else ""
            console.error(f"no response from {ctx.config.ca.base_url}{detail}")
    return 0 if ok else 1


def cmd_ras(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    info = ctx.client().info()
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
    console.info(f"{len(info.ras)} RAs on {ctx.config.ca.base_url}:")
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
    client = ctx.client()
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
                    "base_url": ctx.config.ca.base_url,
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


def cmd_request(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    pin = _read_pin(args)
    spec = RequestSpec.build(
        ctx.config,
        args.cn,
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
        san_dns=args.san_dns,
        san_email=args.san_email,
        san_ip=args.san_ip,
        csr_extensions=args.extensions,
        csr_hash=args.hash,
        auth_alias=args.auth,
    )
    pins: "list[str]" = [spec.pin] if spec.pin else []
    state = create_request(
        ctx,
        spec,
        progress=console.progress,
        on_pin=pins.append,
        wait=args.wait,
        timeout=parse_duration(args.timeout),
        interval=parse_duration(args.interval),
        export=not args.no_export,
        require_verified_chain=not args.allow_unverified_chain,
    )
    payload = {
        "alias": state.alias,
        "common_name": state.cn,
        "type": state.type,
        "status": state.status,
        "subject": state.subject,
        "p12": state.p12_path,
        "certificate": str(ctx.store.cert_path(state)) if state.cert.sha256 else None,
        "pin": pins[0] if pins else None,
        "days_remaining": state.days_remaining,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        console.info("")
        if pins:
            console.info(f"PIN for the RA: {pins[0]}")
        console.info(f"Request '{state.alias}' is {state.status}.")
        console.info(f"  certificate: {payload['certificate'] or '(not issued yet)'}")
        console.info(f"  PKCS#12:     {payload['p12'] or '(not exported yet)'}")
        if state.cert.not_after:
            console.info(f"  valid until: {state.cert.not_after} ({state.days_remaining} days)")
    return 0


def _print_states(console: Console, states: "list[RequestState]", *, verbose: bool = False) -> None:
    if not states:
        console.info("No certificate requests in the local store.")
        return
    console.info(f"{'ALIAS':<28} {'TYPE':<5} {'STATUS':<11} {'EXPIRES':<12} {'DAYS':>5}  P12")
    for state in states:
        expires = state.cert.not_after[:10] if state.cert.not_after else "-"
        days = "" if state.days_remaining is None else f"{state.days_remaining}"
        p12 = "yes" if state.p12_path else "no"
        console.info(
            f"{state.alias[:28]:<28} {state.type:<5} {state.status:<11} {expires:<12} {days:>5}  {p12}"
        )
        warning = expiry_warning(state)
        if warning:
            console.info(f"{'':28} ! {warning}")


def cmd_list(args) -> int:
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    states = ctx.store.list()
    if args.json:
        print(json.dumps([state.to_dict() for state in states], indent=2, default=str))
        return 0
    _print_states(console, states, verbose=args.verbose)
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
                console.info(f"{state.alias}: {state.status} (no need to poll)")
        else:
            for state, status in refresh_all(ctx, progress=console.progress):
                console.info(f"{state.alias}: {status}")
        if args.json:
            print(json.dumps([s.to_dict() for s in ctx.store.list()], indent=2, default=str))
            return 0
        return 0
    if args.alias:
        state = ctx.store.get(args.alias)
        payload = merge_dicts(state.to_dict(), {"days_remaining": state.days_remaining})
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
            return 0
        _print_state(console, ctx, state)
        return 0
    return cmd_list(args)


def _print_state(console: Console, ctx: AppContext, state: RequestState) -> None:
    console.info(f"Alias           {state.alias}")
    console.info(f"Common name     {state.cn} ({state.type} certificate)")
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
                merge_dicts(state.to_dict(), {"days_remaining": state.days_remaining}), indent=2, default=str
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
                    merge_dicts(state.to_dict(), {"days_remaining": state.days_remaining}),
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
    console = Console(json_mode=args.json, quiet=args.quiet)
    ctx = _context(args)
    state = ctx.store.get(args.alias)
    password = _read_secret_option(
        args, what="PKCS#12 passphrase", prompt_label="PKCS#12 passphrase", required=False
    )
    out = Path(args.out).expanduser() if args.out else None
    path = export_p12(ctx, state, password=password, out=out, progress=console.progress)
    if args.json:
        print(json.dumps({"alias": state.alias, "p12": str(path)}, indent=2))
    else:
        console.info(str(path))
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
            san_dns=args.san_dns,
            san_email=args.san_email,
            san_ip=args.san_ip,
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
        san_dns=args.san_dns,
        san_email=args.san_email,
        san_ip=args.san_ip,
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
    paths = install_pem(
        ctx,
        args.alias,
        Path(args.dir).expanduser(),
        encrypt_key=args.encrypt_key,
        include_chain=args.with_chain,
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


def cmd_gui(args) -> int:
    try:
        from .gui import run_gui
    except ImportError as exc:  # pragma: no cover - depends on system tkinter
        raise PyCertError(f"the GUI needs tkinter: {exc}") from exc
    return run_gui(config_path=args.config)


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pycert",
        description="Request, wait for, download and export UK e-Science CA certificates.",
        epilog="Run 'pycert <command> --help' for details. Documentation: docs/",
    )
    parser.add_argument("--version", action="version", version=f"pyCert {__version__}")
    _add_common(parser)
    sub = parser.add_subparsers(dest="command")
    sub.required = True  # add_subparsers(required=...) is 3.7+

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
    ping.set_defaults(func=cmd_ping)

    ras = sub.add_parser("ras", help="list the RAs published by the CA")
    _add_common(ras, suppress=True)
    ras.set_defaults(func=cmd_ras)

    info = sub.add_parser("info", help="show CA information and the message of the day")
    _add_common(info, suppress=True)
    info.set_defaults(func=cmd_info)

    request = sub.add_parser("request", help="create a key, build a CSR and submit it")
    _add_common(request, suppress=True)
    request.add_argument("cn", help="common name (host name for --type host)")
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

    export = sub.add_parser("export", help="write (or re-write) the PKCS#12 bundle")
    _add_common(export, suppress=True)
    export.add_argument("alias")
    export.add_argument("--out", help="output file (default: the request directory)")
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
    renew_cmd.add_argument("--email")
    renew_cmd.add_argument("--key-algorithm", choices=["rsa", "ec"])
    renew_cmd.add_argument("--rsa-bits", type=int)
    renew_cmd.add_argument("--ec-curve", choices=["P-256", "P-384", "P-521"])
    renew_cmd.add_argument("--san-dns", action="append")
    renew_cmd.add_argument("--san-email", action="append")
    renew_cmd.add_argument("--san-ip", action="append")
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

    install = sub.add_parser("install", help="write usercert.pem / userkey.pem (GSI layout)")
    _add_common(install, suppress=True)
    install.add_argument("alias")
    install.add_argument("--dir", default="~/.globus")
    install.add_argument("--encrypt-key", action="store_true", help="encrypt userkey.pem")
    install.add_argument("--with-chain", action="store_true", help="append issuers to usercert.pem")
    install.set_defaults(func=cmd_install)

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

    doctor = sub.add_parser("doctor", help="diagnose the installation and the connection")
    _add_common(doctor, suppress=True)
    doctor.add_argument("--offline", action="store_true", help="skip network checks")
    doctor.set_defaults(func=cmd_doctor)

    selftest = sub.add_parser("selftest", help="run offline cryptographic self-checks")
    _add_common(selftest, suppress=True)
    selftest.set_defaults(func=cmd_selftest)

    gui = sub.add_parser("gui", help="start the graphical interface")
    _add_common(gui, suppress=True)
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
