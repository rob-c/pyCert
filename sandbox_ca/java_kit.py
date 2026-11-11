"""Patch a Java CertWizard build to trust and talk to the sandbox CA.

Two modes are supported:

* ``--jar``: rewrite a built jar (no JDK required to patch).  The bundled CA
  PEM resources, the pinned SHA-256 fingerprints in ``BundledCaCertificates``
  and ``configure.properties`` are replaced, and JAR signatures are removed.
* ``--source-dir``: copy the source tree and apply the same replacements, then
  optionally build it with Maven.

The pin replacement works because the fingerprints are 64-character ASCII
constants in the class file: replacing one 64-character string with another
does not change the constant-pool layout.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# The resources and pins shipped by CertWizard (develop branch, 2.2.1).
_OLD_PINS = {
    "escience-root.pem": "76f3a5942e22012d7e10e11b416fb2eea21d8f4583f2d2fc799bd4ced0210323",
    "escience-2b.pem": "b6d140a765d165d8917bb9941f7ab21ff89c04155a4dce52cad345862c3e686e",
    "escience-root-2026.pem": "565c16e7d6ff0f602aefca2a585634c190d7d9da411c7750d79cac6b351ffffa",
    "escience-3b.pem": "16383860bc6e61488ffb945e961963967c4fe8d73d2b2e9641d0b535cca4b845",
}
_CLASS_PATH = "uk/ngs/ca/certificate/chain/BundledCaCertificates.class"
_CONFIG_PATH = "configure.properties"
_SIGNATURE_RE = re.compile(r"^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)$", re.IGNORECASE)


def _pin(path: Path) -> str:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _load_info(info: "dict | None", data_dir: "str | Path | None") -> dict:
    if info is not None:
        return info
    candidate = Path(data_dir or ".sandbox-ca").expanduser()
    path = candidate if candidate.is_file() else candidate / "sandbox.json"
    if not path.exists():
        raise SystemExit("java-kit: %s does not exist; start the sandbox first or pass --server-info" % path)
    import json

    return json.loads(path.read_text())


def _sandbox_files(info: dict) -> "tuple[Path, Path, str, str]":
    root = Path(info["root_pem"]).expanduser()
    issuing = Path(info["issuing_pem"]).expanduser()
    if not root.exists() or not issuing.exists():
        raise SystemExit("java-kit: root/issuing CA PEM files from sandbox.json are missing")
    root_cert = x509.load_pem_x509_certificate(root.read_bytes())
    issuing_cert = x509.load_pem_x509_certificate(issuing.read_bytes())
    if issuing_cert.issuer != root_cert.subject:
        raise SystemExit("java-kit: the issuing CA was not issued by the sandbox root")
    return root, issuing, _pin(root), _pin(issuing)


def _base_url(info: dict) -> str:
    url = str(info.get("url") or "").rstrip("/")
    if not url.startswith("https://"):
        raise SystemExit("java-kit: sandbox URL must be https")
    return url


def _patch_properties(text: str, info: dict) -> str:
    base = _base_url(info)
    issuer = str(info["issuer_dn"]).strip()
    seen_issuer = False
    seen_o = False
    seen_c = False
    seen_base = False
    lines = ["# Patched by pyCertWiz sandbox_ca: certificates are issued by a test CA.", "#"]
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw:
            lines.append(raw)
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value.startswith(("http://", "https://")):
            path = urlsplit(value).path or "/"
            query = ("?" + urlsplit(value).query) if urlsplit(value).query else ""
            raw = "%s=%s%s%s" % (key, base, path, query)
        elif key == "ngsca.issuer.dn":
            raw = "ngsca.issuer.dn=%s" % issuer
            seen_issuer = True
        elif key == "ngsca.cert.o":
            raw = "ngsca.cert.o=Sandbox"
            seen_o = True
        elif key == "ngsca.cert.c":
            raw = "ngsca.cert.c=UK"
            seen_c = True
        elif key == "ngsca.base.url":
            raw = "ngsca.base.url=%s" % base
            seen_base = True
        lines.append(raw)
    if not seen_issuer:
        lines.append("ngsca.issuer.dn=%s" % issuer)
    if not seen_o:
        lines.append("ngsca.cert.o=Sandbox")
    if not seen_c:
        lines.append("ngsca.cert.c=UK")
    if not seen_base:
        lines.append("ngsca.base.url=%s" % base)
    return "\n".join(lines) + "\n"


def _patch_class(data: bytes, root_pin: str, issuing_pin: str) -> bytes:
    new_pins = {
        "escience-root.pem": root_pin,
        "escience-2b.pem": issuing_pin,
        "escience-root-2026.pem": root_pin,
        "escience-3b.pem": issuing_pin,
    }
    result = data
    for resource, old in _OLD_PINS.items():
        new = new_pins[resource]
        old_bytes = old.encode("ascii")
        if old_bytes in result:
            result = result.replace(old_bytes, new.encode("ascii"))
        elif new.encode("ascii") not in result:
            raise SystemExit(
                "java-kit: cannot patch %s: neither the known pin %s nor the sandbox pin is in the class; "
                "this CertWizard build has different bundled CA pins" % (resource, old)
            )
    # Verify every sandbox pin is present and every old pin is gone.
    for new in set(new_pins.values()):
        if new.encode("ascii") not in result:
            raise SystemExit("java-kit: the patched class is missing a sandbox pin")
    for old in _OLD_PINS.values():
        if old.encode("ascii") in result:
            raise SystemExit("java-kit: an old CA pin survived patching")
    return result


def _write_jar(src: Path, dst: Path, info: dict) -> None:
    root, issuing, root_pin, issuing_pin = _sandbox_files(info)
    root_pem = root.read_bytes()
    issuing_pem = issuing.read_bytes()
    replacements = {
        "escience-root.pem": root_pem,
        "escience-2b.pem": issuing_pem,
        "escience-root-2026.pem": root_pem,
        "escience-3b.pem": issuing_pem,
    }
    with zipfile.ZipFile(src, "r") as zin:
        try:
            old_class = zin.read(_CLASS_PATH)
        except KeyError:
            raise SystemExit("java-kit: %s does not contain %s; is this a CertWizard jar?" % (src, _CLASS_PATH))
        patched_class = _patch_class(old_class, root_pin, issuing_pin)
        try:
            old_config = zin.read(_CONFIG_PATH).decode("utf-8")
        except KeyError:
            raise SystemExit("java-kit: %s does not contain %s" % (src, _CONFIG_PATH))
        patched_config = _patch_properties(old_config, info)
        dst.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=dst.name + ".", dir=str(dst.parent))
        os.close(fd)
        try:
            with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    name = item.filename
                    if name.startswith("META-INF/") and _SIGNATURE_RE.match(name):
                        continue
                    if name in replacements:
                        data = replacements[name]
                    elif name == _CLASS_PATH:
                        data = patched_class
                    elif name == _CONFIG_PATH:
                        data = patched_config.encode("utf-8")
                    else:
                        data = zin.read(name)
                    zout.writestr(item, data)
            os.replace(temporary, dst)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    # Validate the result rather than trusting the write.
    with zipfile.ZipFile(dst, "r") as zcheck:
        if zcheck.testzip() is not None:
            raise SystemExit("java-kit: %s failed its zip integrity check" % dst)
        if _patch_class(zcheck.read(_CLASS_PATH), root_pin, issuing_pin) != zcheck.read(_CLASS_PATH):
            raise SystemExit("java-kit: %s does not contain the expected patched pins" % dst)
        config = zcheck.read(_CONFIG_PATH).decode("utf-8")
        for line in config.splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                if value.strip().startswith(("http://", "https://")) and not value.strip().startswith(
                    _base_url(info)
                ):
                    raise SystemExit("java-kit: %s still points at %s" % (key, value.strip()))


def _write_readme(path: Path, info: dict, jar: "Path | None" = None, source: "Path | None" = None) -> None:
    base = _base_url(info)
    lines = [
        "CertWizard sandbox client",
        "========================",
        "",
        "Sandbox CA: %s" % base,
        "Issuer DN: %s" % info["issuer_dn"],
        "Root SHA-256: %s" % info["root_sha256"],
        "Issuing SHA-256: %s" % info["issuing_sha256"],
        "",
        "This build trusts only the sandbox CA. Do not use it against the real CA.",
        "",
        "Run the Java client (Java 25 or newer):",
    ]
    if jar is not None:
        lines.append("  java -jar %s /tmp/certwizard-sandbox-data" % jar)
        lines.append("  java -jar %s --self-test" % jar)
    else:
        lines.append(
            "  cd %s && mvn -q -DskipTests -Pjar-with-dependencies -P!package-mac package"
            % (source or "<source>")
        )
        lines.append("  java -jar target/CertWizard-jar-with-dependencies.jar /tmp/certwizard-sandbox-data")
        lines.append("  java -jar target/CertWizard-jar-with-dependencies.jar --self-test")
    lines.extend(
        [
            "",
            "The GUI asks for a data directory; use a fresh one so the sandbox truststore and",
            "keystore do not mix with a real CertWizard profile.",
            "",
            "With auto-sign enabled the sandbox issues a certificate after the configured number",
            "of status lookups. Use the admin CLI (see docs/CA_LISTENER.md) to approve or sign",
            "requests manually, inspect requests, or inject protocol failures.",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def build_jar_kit(jar: "str | Path", out: "str | Path", info: "dict | None" = None, *,
                  data_dir: "str | Path | None" = None) -> Path:
    info = _load_info(info, data_dir)
    source = Path(jar).expanduser()
    destination = Path(out).expanduser()
    if not source.exists():
        raise SystemExit("java-kit: %s does not exist" % source)
    if source.resolve() == destination.resolve():
        raise SystemExit("java-kit: refusing to overwrite the input jar; choose a different --out")
    _write_jar(source, destination, info)
    _write_readme(destination.with_name(destination.stem + "-README.txt"), info, jar=destination)
    return destination


def build_source_kit(source_dir: "str | Path", out_dir: "str | Path", info: "dict | None" = None, *,
                     data_dir: "str | Path | None" = None, build: bool = False) -> Path:
    info = _load_info(info, data_dir)
    source = Path(source_dir).expanduser().resolve()
    destination = Path(out_dir).expanduser().resolve()
    if not (source / "pom.xml").exists():
        raise SystemExit("java-kit: %s does not look like the CertWizard source tree (no pom.xml)" % source)
    if destination.exists():
        raise SystemExit("java-kit: %s already exists; remove it or choose another --out" % destination)
    root, issuing, root_pin, issuing_pin = _sandbox_files(info)
    shutil.copytree(
        str(source),
        str(destination),
        ignore=shutil.ignore_patterns(".git", "target", ".idea", "*.iml"),
    )
    resources = destination / "src" / "main" / "resources"
    replacements = {
        "escience-root.pem": root.read_bytes(),
        "escience-2b.pem": issuing.read_bytes(),
        "escience-root-2026.pem": root.read_bytes(),
        "escience-3b.pem": issuing.read_bytes(),
    }
    for name, data in replacements.items():
        (resources / name).write_bytes(data)
    java_file = destination / "src" / "main" / "java" / "uk" / "ngs" / "ca" / "certificate" / "chain" / "BundledCaCertificates.java"
    if not java_file.exists():
        raise SystemExit("java-kit: %s is missing" % java_file)
    text = java_file.read_text()
    new_pins = {
        "escience-root.pem": root_pin,
        "escience-2b.pem": issuing_pin,
        "escience-root-2026.pem": root_pin,
        "escience-3b.pem": issuing_pin,
    }
    for resource, old in _OLD_PINS.items():
        if old in text:
            text = text.replace(old, new_pins[resource])
    for new in set(new_pins.values()):
        if new not in text:
            raise SystemExit("java-kit: could not install the sandbox pin in BundledCaCertificates.java")
    java_file.write_text(text)
    config_file = resources / "configure.properties"
    config_file.write_text(_patch_properties(config_file.read_text(), info))
    _write_readme(destination / "SANDBOX-README.txt", info, source=destination)
    if build:
        subprocess.run(
            [
                "mvn",
                "-q",
                "-DskipTests",
                "-Pjar-with-dependencies",
                "-P!package-mac",
                "package",
            ],
            cwd=str(destination),
            check=True,
        )
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Patch CertWizard to trust/use a running pyCertWiz sandbox CA.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--data-dir", default=".sandbox-ca", help="directory containing sandbox.json")
    parser.add_argument("--server-info", help="explicit sandbox.json path")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--jar", help="built CertWizard jar to patch")
    group.add_argument("--source-dir", help="CertWizard source tree to copy and patch")
    parser.add_argument("--out", help="output jar or directory (default: <input>-sandbox)")
    parser.add_argument("--build", action="store_true", help="run Maven after patching source")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    info = _load_info(None, args.server_info or args.data_dir)
    if args.jar:
        source = Path(args.jar)
        out = Path(args.out) if args.out else source.with_name(source.stem + "-sandbox.jar")
        result = build_jar_kit(source, out, info)
        print("patched jar: %s" % result)
        print("sandbox URL: %s" % _base_url(info))
        print("run: java -jar %s /tmp/certwizard-sandbox-data" % result)
        print("self-test: java -jar %s --self-test" % result)
        return 0
    source = Path(args.source_dir)
    out = Path(args.out) if args.out else source.with_name(source.name + "-sandbox")
    result = build_source_kit(source, out, info, build=args.build)
    print("patched source: %s" % result)
    if args.build:
        print("built: %s" % (result / "target" / "CertWizard-jar-with-dependencies.jar"))
    else:
        print("build: cd %s && mvn -q -DskipTests -Pjar-with-dependencies -P!package-mac package" % result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
