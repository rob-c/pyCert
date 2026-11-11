#!/usr/bin/env python3
"""Regenerate the screenshots in docs/images against a throw-away sandbox CA.

    make screenshots
    QT_QPA_PLATFORM=offscreen .venv/bin/python tools/screenshots.py docs/images [--keep DIR]

Everything runs inside a temporary directory with its own $HOME, a file secret
store and its own GUI preferences, against the in-process mock UK CA and the
sandbox ACME server. Your real configuration, certificates and keychain are
never read or written. With ``--keep DIR`` the demo store is left in DIR, so
the CLI can be run against it:

    HOME=DIR/home pycert --config DIR/home/.config/pycert/pycert.toml list
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = "1234567890AB"
KEYSTORE_PASSWORD = "cakeystore demo passphrase"
SIZE = (1600, 960)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def build_demo(home: Path):
    """A store with user, host, expiring, pending, ACME and keystore certificates."""
    from pycert import keystore as ks
    from pycert.config import (
        ChainEntry,
        init_config,
        load_config,
        new_acme_profile,
        validate_config,
        write_config,
    )
    from pycert.deploy import add_target, deploy_state, target_from_preset
    from pycert.workflow import AppContext, RequestSpec, create_request, refresh_records
    from sandbox_ca.acme import ACMEServer
    from sandbox_ca.mock_ca import MockCA

    ca = MockCA()
    ca.auto_approve, ca.sign_after_polls = True, 0
    acme = ACMEServer(ca, port=0, challenge_mode="auto").start()

    confdir = home / ".config" / "pycert"
    confdir.mkdir(parents=True)
    config = init_config(confdir, copy_chain=False)
    pins = ca.chain_files(confdir / "chain")
    config.chain = [ChainEntry(label=name, file=f"chain/{name}", sha256=pin) for name, pin in pins.items()]
    config.ca.base_url = ca.url
    config.ca.retries = 0
    config.identity.email = "grid-admin@example.ac.uk"
    config.identity.ra = "CLRC DL"
    config.paths.data_dir = str(home / ".local" / "share" / "pycert")
    config.secrets.backend = "file"
    config.keys.rsa_bits = 2048
    profile = new_acme_profile(
        "sandbox-acme",
        acme.directory_url(),
        display_name="Sandbox ACME",
        contact=["web-admin@example.ac.uk"],
        terms_agreed=True,
        tls_trust="chain",
    )
    profile.chain = list(config.chain)
    profile.ca.retries = 0
    profile.acme.poll_interval = 0.1
    profile.acme.http_bind = "127.0.0.1"
    profile.acme.http_port = _free_port()
    config.add_ca(profile)
    validate_config(config)
    write_config(config.path, config)
    config = load_config(config.path)
    ctx = AppContext.from_config(config)

    def make(cn, **kwargs):
        if kwargs.get("ca") != "sandbox-acme":
            kwargs.setdefault("pin", PIN)
        spec = RequestSpec.build(config, cn, **kwargs)
        return create_request(ctx, spec, wait=True, timeout=60, interval=0.1)

    jane = make("jane doe", description="Grid user certificate")
    ca.host_valid_days = 22
    make("argus.example.ac.uk", type="host", auth_alias=jane.alias, description="Authorisation service")
    ca.host_valid_days = 395
    se01 = make("se01.grid.example.ac.uk", type="host", auth_alias=jane.alias, description="Storage element")
    target = target_from_preset("grid-host", directory=str(home / "grid-security" / "se01"), hook="systemctl reload xrootd")
    target["hook"] = ""  # shown in the GUI, but not run for the screenshots
    add_target(ctx, se01, target)
    deploy_state(ctx, ctx.store.get(se01.alias))
    make("ce01.grid.example.ac.uk", type="host", auth_alias=jane.alias, description="Compute element")
    make("www.example.ac.uk", type="host", ca="sandbox-acme", description="Public web site")

    # Certificates CertWizard keeps in its Java keystore, linked as a live store.
    entries = []
    for cn, alias in (
        ("dcache.example.ac.uk", "dcache.example.ac.uk (uk e-science ca 2b)_nov2025"),
        ("gridftp.example.ac.uk", "gridftp.example.ac.uk (uk e-science ca 2b)_oct2025"),
    ):
        state = make(cn, type="host", auth_alias=jane.alias)
        entries.append((alias, ctx.store.load_key(state, ctx.key_passphrase()), ctx.store.load_certificate(state), ctx.store.load_chain(state)))
        ctx.store.delete(state)
    keystore_path = home / ".ca" / "cakeystore.pkcs12"
    keystore_path.parent.mkdir(mode=0o700)
    keystore = ks.Keystore.load(keystore_path, KEYSTORE_PASSWORD)
    for entry in entries:
        keystore.put(*entry)
    keystore.save(backup=False)
    link, _keystore = ks.link_keystore(ctx, keystore_path, KEYSTORE_PASSWORD, name="cakeystore")
    ks.sync(ctx, link)

    # One request still waiting for the RA.
    ca.auto_approve, ca.sign_after_polls = False, 10**6
    pending = RequestSpec.build(
        config, "wn042.grid.example.ac.uk", type="host", auth_alias=jane.alias, pin=PIN, description="Worker node"
    )
    create_request(ctx, pending)
    refresh_records(ctx)  # the CA's record (status, contact) of every issued certificate
    return ca, acme, config, keystore_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", nargs="?", default=str(ROOT / "docs" / "images"))
    parser.add_argument("--keep", help="build the demo store in this directory and keep it")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="no screenshots: open pyCertWiz on the demo store (with the sandbox CA running) until it is closed",
    )
    args = parser.parse_args()
    out = Path(args.out).resolve()
    if not args.interactive:
        out.mkdir(parents=True, exist_ok=True)
    root = Path(args.keep).resolve() if args.keep else Path(tempfile.mkdtemp(prefix="pycert-shots-"))
    home = root / "home"
    home.mkdir(parents=True, exist_ok=True)
    # Isolate everything before Qt or pyCertWiz look at the environment.
    os.environ["HOME"] = str(home)
    os.environ["XDG_CONFIG_HOME"] = str(home / ".config")
    os.environ["XDG_DATA_HOME"] = str(home / ".local" / "share")
    os.environ["PYCERT_GUI_SETTINGS"] = str(root / "gui.ini")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

    ca, acme, config, keystore_path = build_demo(home)
    try:
        if args.interactive:
            interactive(config)
        else:
            shoot(config, keystore_path, out)
    finally:
        acme.stop()
        ca.stop()
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    return 0


def interactive(config) -> None:
    """The real application on the demo store; requests are signed by the sandbox CA."""
    from pycert import keystore as ks
    from pycert.gui.app import MainWindow, create_application
    from pycert.gui.settings import preferences
    from pycert.gui.workers import MainThreadCollector

    preferences().setValue("tray", False)
    app = create_application(["pycert"])
    collector = MainThreadCollector(app)  # garbage is freed on the UI thread only, as in pycert gui
    window = MainWindow(str(config.path), start_background=True)
    ks.unlock(window.ctx, window.cfg.keystore("cakeystore"), KEYSTORE_PASSWORD)
    window.resize(*SIZE)
    window.show()
    print(f"pyCertWiz is open (demo store; the keystore passphrase is {KEYSTORE_PASSWORD!r}). Close the window to stop.")
    app.exec()
    collector.stop()


def shoot(config, keystore_path: Path, out: Path) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication

    from pycert import keystore as ks
    from pycert.gui.app import MainWindow, create_application
    from pycert.gui.bundle import BundleInspector
    from pycert.gui.dialogs import ExportDialog, RenameDialog, RenewDialog
    from pycert.gui.settings import SettingsDialog, preferences
    from pycert.gui.viewer import CertificateViewer
    from pycert.gui.wizard import NewRequestWizard
    from pycert.gui.workers import MainThreadCollector

    preferences().setValue("appearance", "light")
    preferences().setValue("tray", False)
    app = create_application(["pycert"])
    collector = MainThreadCollector(app)  # garbage is freed on the UI thread only, as in pycert gui
    window = MainWindow(str(config.path), start_background=False)
    window.resize(*SIZE)
    window.show()
    ks.unlock(window.ctx, window.cfg.keystore("cakeystore"), KEYSTORE_PASSWORD)

    def settle(seconds: float = 0.3) -> None:
        deadline = time.monotonic() + 30
        while window.runner.busy and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(0.02)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            QApplication.processEvents()
            time.sleep(0.02)

    def save(widget, name: str) -> None:
        settle()
        widget.grab().save(str(out / name))
        print(f"wrote {out / name}")

    def dispose(widget) -> None:
        widget.close()
        widget.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def select(alias: str, tab: int = 0) -> None:
        window.nav.setCurrentItem(window._nav_items["all"])
        window.refresh(select=alias)
        window.detail.tabs.setCurrentIndex(tab)

    window.ping_cas()
    settle(0.5)

    select("argus.example.ac.uk")
    save(window, "main-light.png")
    select("se01.grid.example.ac.uk", tab=2)
    save(window, "deployment.png")
    window.nav.setCurrentItem(window._nav_items["keystore:cakeystore"])
    window.refresh(select="dcache.example.ac.uk (uk e-science ca 2b)_nov2025")
    window.detail.tabs.setCurrentIndex(0)
    save(window, "keystores.png")

    state = window.ctx.store.get("se01.grid.example.ac.uk")
    viewer = CertificateViewer(window, window.ctx, state)
    viewer.resize(1120, 660)
    splitter = viewer.chain_list.parentWidget()
    splitter.setSizes([280, 840])
    viewer.show()
    for index, name in enumerate(("viewer-chain.png", "viewer-public-key.png", "viewer-private-key.png")):
        viewer.tabs.setCurrentIndex(index)
        save(viewer, name)
    dispose(viewer)

    export = ExportDialog(window, window.ctx, state, directory=str(Path.home() / "Certificates"))
    export.destination.setText("~/Certificates/se01.grid.example.ac.uk.p12")
    export.password.setText("a new export passphrase")
    export.confirm.setText("a new export passphrase")
    export.show()
    save(export, "export-dialog.png")
    dispose(export)

    linked = window.ctx.store.get("dcache.example.ac.uk (uk e-science ca 2b)_nov2025")
    rename = RenameDialog(window, window.ctx, linked)
    rename.name.setText("dcache.example.ac.uk 2025-26")
    rename.show()
    save(rename, "rename-dialog.png")
    dispose(rename)

    argus = window.ctx.store.get("argus.example.ac.uk")
    provider = window.ctx.provider_for(argus)
    renew = RenewDialog(window, argus, provider.capabilities, window.cfg, argus.server.email)
    renew.show()
    save(renew, "renew-dialog.png")
    dispose(renew)

    wizard = NewRequestWizard(window, window.ctx, window.runner, cert_type="host")
    wizard.resize(760, 600)
    wizard.show()
    settle()
    if wizard.currentPage() is wizard.type_page:
        wizard.type_page.host.setChecked(True)
        wizard.next()
    wizard.details_page.hosts.setPlainText("wn043.grid.example.ac.uk\nwn044.grid.example.ac.uk\nwn045.grid.example.ac.uk")
    save(wizard, "wizard-hosts.png")
    dispose(wizard)

    inspector = BundleInspector(window, str(keystore_path))
    inspector.password.setText(KEYSTORE_PASSWORD)
    inspector.load()
    inspector.path.setText("~/.ca/cakeystore.pkcs12")
    inspector.resize(1000, 640)
    inspector.show()
    save(inspector, "bundle-inspector.png")
    dispose(inspector)

    settings = SettingsDialog(window, str(config.path))
    settings.resize(900, 620)
    settings.tabs.setCurrentIndex(next(i for i in range(settings.tabs.count()) if settings.tabs.tabText(i) == "Certificate authorities"))
    settings.show()
    save(settings, "settings.png")
    dispose(settings)

    window.set_appearance("dark")
    select("se01.grid.example.ac.uk")
    save(window, "main-dark.png")
    window.set_appearance("light")

    window.runner.shutdown()
    window.runner.wait(5000)
    dispose(window)
    collector.stop()


if __name__ == "__main__":
    raise SystemExit(main())
