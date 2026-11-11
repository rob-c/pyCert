"""CA providers: the protocols pyCertWiz can use to obtain certificates.

A *provider* implements one CA protocol behind the small interface in
:mod:`pycert.providers.base`.  The workflow (key generation, CSR building,
chain verification, storage, PKCS#12 export, deployment) is shared; only the
conversation with the CA differs.

Built-in kinds:

``ukca``
    The UK e-Science CA's CertWizard/OpenCA protocol (XML over HTTPS, RA PIN,
    PPPK-authenticated host requests, renewals and revocation).
``acme``
    RFC 8555 ACME, with External Account Binding and http-01 / dns-01
    validation, for host certificates from ACME CAs.

Third-party providers are discovered through the ``pycert.providers`` entry
point group, so another CA protocol can be added without changing pyCert::

    [project.entry-points."pycert.providers"]
    myca = "mypackage.myca:MyCAProvider"

and selected in the configuration with ``[cas.<name>] kind = "myca"``.
"""

import importlib
from functools import lru_cache
from importlib import metadata
from typing import Any

from ..errors import ConfigError

ENTRY_POINT_GROUP = "pycert.providers"

BUILTIN: "dict[str, str]" = {
    "ukca": "pycert.providers.ukca:UKCAProvider",
    "acme": "pycert.providers.acme:ACMEProvider",
}

_registered: "dict[str, Any]" = {}


def register(kind: str, factory: Any) -> None:
    """Register a provider class at runtime (tests, embedding applications)."""
    _registered[kind] = factory


def unregister(kind: str) -> None:
    _registered.pop(kind, None)


@lru_cache(maxsize=1)
def _entry_points() -> "dict[str, Any]":
    try:
        found = metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception:  # noqa: BLE001 - a broken plugin environment must not break pyCertWiz  # pragma: no cover
        return {}
    return {entry.name: entry for entry in found}


def known_kinds() -> "set[str]":
    return set(BUILTIN) | set(_registered) | set(_entry_points())


def provider_class(kind: str) -> Any:
    if kind in _registered:
        return _registered[kind]
    if kind in BUILTIN:
        module_name, attribute = BUILTIN[kind].split(":")
        return getattr(importlib.import_module(module_name), attribute)
    plugins = _entry_points()
    if kind in plugins:
        try:
            return plugins[kind].load()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover - plugin import failure
            raise ConfigError(f"the CA provider plugin {kind!r} failed to load: {exc}") from exc
    raise ConfigError(f"unknown CA kind {kind!r} (available: {', '.join(sorted(known_kinds()))})")


def create_provider(ctx: Any, profile: Any) -> Any:
    """Instantiate the provider for a :class:`~pycert.config.CAProfile`."""
    return provider_class(profile.kind)(ctx, profile)


def capabilities_for(kind: str) -> Any:
    return provider_class(kind).capabilities


__all__ = [
    "BUILTIN",
    "ENTRY_POINT_GROUP",
    "capabilities_for",
    "create_provider",
    "known_kinds",
    "provider_class",
    "register",
    "unregister",
]
