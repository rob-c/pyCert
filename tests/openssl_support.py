"""Helpers for tests that drive the ``openssl`` command line tool.

Distributions ship different OpenSSL builds: 1.1 on RHEL 8, 3.x elsewhere,
LibreSSL on macOS, and RHEL 9's crypto policy refuses SHA-1 signatures.
"""

import os
import re
import shutil
import subprocess

OPENSSL = shutil.which("openssl")


def openssl_version() -> "tuple[str, int]":
    """('OpenSSL' or 'LibreSSL', major version)."""
    out = subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout.strip()
    match = re.match(r"(\w+)\s+(\d+)\.", out)
    return (match.group(1), int(match.group(2))) if match else ("", 0)


def legacy_pkcs12_args() -> "list[str]":
    """OpenSSL 3 writes RC2/3DES PKCS#12 only with -legacy; older builds do by default."""
    product, major = openssl_version()
    return ["-legacy"] if product == "OpenSSL" and major >= 3 else []


def sha1_env() -> dict:
    """Let RHEL 9's OpenSSL create SHA-1 signatures (its crypto policy refuses them)."""
    return {**os.environ, "OPENSSL_ENABLE_SHA1_SIGNATURES": "1"}
