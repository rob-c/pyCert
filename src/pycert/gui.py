"""Tkinter GUI for pyCert.

The GUI is deliberately thin: every action calls the same :mod:`pycert.workflow`
functions as the CLI, in a worker thread, so the two front-ends cannot drift
apart.  Nothing here talks to the network directly.

Why Tkinter?  It is in the Python standard library, starts in well under a
second, needs no browser engine or JVM, and works over SSH with X forwarding.
The Java client needed a bundled JRE, Restlet and BouncyCastle; this file and
the modules it imports are the whole program.

Security notes:

* the PIN is shown once in a modal dialog with a copy button and is never
  written to the log or to disk;
* the PKCS#12 passphrase is only ever handled by the secret store;
* private keys are never displayed, only their algorithm, size and fingerprint;
* files are opened read-only and paths are shown in full.
"""

import os
import queue
import shlex
import subprocess
import sys
import threading
import tkinter as tk
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from . import __version__, certs
from .config import ChainEntry, Config, load_config, write_config
from .errors import NotFound, PyCertError
from .secrets_store import SecretStore
from .store import PENDING_STATUSES, RequestState
from .workflow import (
    AppContext,
    RequestSpec,
    create_request,
    download_and_export,
    export_p12,
    list_ras,
    refresh_all,
    renew,
    revoke,
    verify,
    wait_for_certificate,
)

APP_TITLE = "pyCert - UK e-Science CA"
ACCENT = "#0b5cad"
MUTED = "#666666"


# ---------------------------------------------------------------------------
# Small widgets
# ---------------------------------------------------------------------------


class Tooltip:
    """Hover help for a widget (Tkinter has no built-in tooltips)."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 450):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after: "str | None" = None
        self._window: "tk.Toplevel | None" = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._after = self.widget.after(self.delay, self._show)

    def _show(self) -> None:
        if self._window is not None:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self._window = tk.Toplevel(self.widget)
        self._window.wm_overrideredirect(True)
        self._window.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self._window, text=self.text, padx=6, pady=4, background="#ffffe0", relief="solid", borderwidth=1
        ).pack()

    def _hide(self, _event=None) -> None:
        if self._after is not None:
            self.widget.after_cancel(self._after)
            self._after = None
        if self._window is not None:
            self._window.destroy()
            self._window = None


def _readonly_text(parent: tk.Widget, height: int = 12) -> "tuple[tk.Text, ttk.Scrollbar, tk.Frame]":
    frame = ttk.Frame(parent)
    text = tk.Text(
        frame,
        height=height,
        wrap="word",
        relief="flat",
        borderwidth=0,
        padx=10,
        pady=8,
        font=("TkFixedFont", 11),
        background="#fbfbfb",
    )
    scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scroll.set, state="disabled")
    text.grid(row=0, column=0, sticky="nsew")
    scroll.grid(row=0, column=1, sticky="ns")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return text, scroll, frame


def _set_text(widget: tk.Text, value: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    widget.configure(state="disabled")


def _open_path(path: Path) -> None:
    if sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    elif os.name == "nt":  # pragma: no cover - Windows
        os.startfile(str(path))  # type: ignore[attr-defined]
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


def _clipboard(widget: tk.Widget, text: str) -> None:
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update_idletasks()


# ---------------------------------------------------------------------------
# PIN dialog
# ---------------------------------------------------------------------------


class PinDialog(tk.Toplevel):
    """Show the PIN once. It is never stored by pyCert."""

    def __init__(self, parent: tk.Widget, pin: str, common_name: str):
        super().__init__(parent)
        self.title("PIN for the RA")
        self.transient(parent)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"PIN for {common_name}", font=("TkDefaultFont", 13, "bold")).pack(anchor="w")
        ttk.Label(
            body,
            text=(
                "Read this PIN to the RA when they contact you, or enter it in the RA portal.\n"
                "pyCert does not store it; it is only used to compute the hash sent with the CSR."
            ),
            wraplength=520,
            justify="left",
            foreground=MUTED,
        ).pack(anchor="w", pady=(4, 12))
        entry = tk.Entry(body, font=("TkFixedFont", 20), justify="center", relief="solid", borderwidth=1)
        entry.insert(0, pin)
        entry.configure(state="readonly", readonlybackground="#ffffff")
        entry.pack(fill="x", ipady=8)
        entry.focus_set()
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(14, 0))

        def copy():
            _clipboard(self, pin)
            copy_button.configure(text="Copied")

        copy_button = ttk.Button(buttons, text="Copy PIN", command=copy)
        copy_button.pack(side="left")
        ttk.Button(buttons, text="Done", command=self.destroy).pack(side="right")
        self.bind("<Return>", lambda _e: self.destroy())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()
        self.wait_window(self)


# ---------------------------------------------------------------------------
# Wait dialog
# ---------------------------------------------------------------------------


class WaitDialog(tk.Toplevel):
    """Shows progress while polling the CA; cancel is cooperative."""

    def __init__(
        self,
        parent: "PyCertApp",  # noqa: F821
        title: str,
        work: Callable[[Callable[[str], None]], object],
        on_done: Callable[[object], None],
    ):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(True, True)
        self.geometry("720x360")
        self._work = work
        self._on_done = on_done
        self._queue: queue.Queue = queue.Queue()
        self._cancel = parent._stop_event  # shared flag, cleared by the app
        self._cancel.clear()
        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        self.status = ttk.Label(body, text="Starting...", font=("TkDefaultFont", 11, "bold"))
        self.status.pack(anchor="w")
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill="x", pady=8)
        self.progress.start(12)
        self.log, _scroll, frame = _readonly_text(body, height=10)
        frame.pack(fill="both", expand=True)
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(10, 0))
        self.cancel_button = ttk.Button(buttons, text="Cancel", command=self._on_cancel)
        self.cancel_button.pack(side="right")
        ttk.Button(buttons, text="Open folder", command=lambda: parent._open_selected_folder()).pack(
            side="left"
        )
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.after(120, self._drain)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _run(self) -> None:
        try:
            result = self._work(lambda message: self._queue.put(("log", message)))
        except BaseException as exc:  # noqa: BLE001 - reported in the dialog
            self._queue.put(("error", exc))
        else:
            self._queue.put(("done", result))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self.status.configure(text=payload)
                    self.log.configure(state="normal")
                    self.log.insert("end", f"{datetime.now().strftime('%H:%M:%S')}  {payload}\n")
                    self.log.see("end")
                    self.log.configure(state="disabled")
                elif kind == "done":
                    self.progress.stop()
                    self.grab_release()
                    self.destroy()
                    self._on_done(payload)
                    return
                elif kind == "error":
                    self.progress.stop()
                    self.grab_release()
                    try:
                        self.destroy()
                    finally:
                        self._on_done(payload)
                    return
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _on_cancel(self) -> None:
        self._cancel.set()
        self.status.configure(text="Cancelling...")
        self.cancel_button.configure(state="disabled")


# ---------------------------------------------------------------------------
# New request dialog
# ---------------------------------------------------------------------------


class NewRequestDialog(tk.Toplevel):
    def __init__(self, app: "PyCertApp"):  # noqa: F821
        super().__init__(app)
        self.app = app
        self.ctx = app.ctx
        self.cfg = app.cfg
        self.result_holder: "list[RequestState]" = []
        self.title("New certificate request")
        self.transient(app)
        self.minsize(720, 620)
        self._ras: "list[str]" = [self.cfg.identity.ra] if self.cfg.identity.ra else []
        self._build()
        self.grab_set()
        self.cn_var.set("")
        self.pin_var.set("")
        self._on_type_change()
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(200, lambda: self.cn_entry.focus_set())

    # -- construction ------------------------------------------------------
    def _build(self) -> None:
        pad = {"padx": 10, "pady": 6}
        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(1, weight=1)

        ttk.Label(outer, text="Certificate request", font=("TkDefaultFont", 15, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )

        self.type_var = tk.StringVar(value="user")
        type_frame = ttk.Frame(outer)
        type_frame.grid(row=1, column=1, sticky="w", **pad)
        ttk.Radiobutton(
            type_frame,
            text="Personal certificate",
            value="user",
            variable=self.type_var,
            command=self._on_type_change,
        ).pack(side="left")
        ttk.Radiobutton(
            type_frame,
            text="Host certificate",
            value="host",
            variable=self.type_var,
            command=self._on_type_change,
        ).pack(side="left", padx=(18, 0))
        ttk.Label(outer, text="Type").grid(row=1, column=0, sticky="e", **pad)

        self.cn_label = ttk.Label(outer, text="Full name")
        self.cn_label.grid(row=2, column=0, sticky="e", **pad)
        self.cn_var = tk.StringVar()
        self.cn_entry = ttk.Entry(outer, textvariable=self.cn_var, width=42)
        self.cn_entry.grid(row=2, column=1, sticky="we", **pad)

        ttk.Label(outer, text="Contact e-mail").grid(row=3, column=0, sticky="e", **pad)
        self.email_var = tk.StringVar(value=self.cfg.identity.email)
        ttk.Entry(outer, textvariable=self.email_var).grid(row=3, column=1, sticky="we", **pad)
        self.email_hint = ttk.Label(outer, text="", foreground=MUTED)
        self.email_hint.grid(row=3, column=2, sticky="w")

        ttk.Label(outer, text="RA").grid(row=4, column=0, sticky="e", **pad)
        ra_frame = ttk.Frame(outer)
        ra_frame.grid(row=4, column=1, sticky="we", **pad)
        ra_frame.columnconfigure(0, weight=1)
        self.ra_var = tk.StringVar(value=self.cfg.identity.ra)
        self.ra_combo = ttk.Combobox(ra_frame, textvariable=self.ra_var, values=self._ras)
        self.ra_combo.grid(row=0, column=0, sticky="we")
        self.fetch_button = ttk.Button(ra_frame, text="Fetch from CA", command=self._fetch_ras)
        self.fetch_button.grid(row=0, column=1, padx=(8, 0))

        ttk.Label(outer, text="Organisation").grid(row=5, column=0, sticky="e", **pad)
        org = ttk.Frame(outer)
        org.grid(row=5, column=1, sticky="we", **pad)
        self.ou_var = tk.StringVar(value=self.cfg.identity.ou)
        self.l_var = tk.StringVar(value=self.cfg.identity.l)
        self.o_var = tk.StringVar(value=self.cfg.identity.o)
        self.c_var = tk.StringVar(value=self.cfg.identity.c)
        ttk.Label(org, text="OU").pack(side="left")
        ttk.Entry(org, textvariable=self.ou_var, width=14).pack(side="left", padx=(4, 10))
        ttk.Label(org, text="L").pack(side="left")
        ttk.Entry(org, textvariable=self.l_var, width=10).pack(side="left", padx=(4, 10))
        ttk.Label(org, text="O").pack(side="left")
        ttk.Entry(org, textvariable=self.o_var, width=14).pack(side="left", padx=(4, 10))
        ttk.Label(org, text="C").pack(side="left")
        ttk.Entry(org, textvariable=self.c_var, width=4).pack(side="left", padx=(4, 0))

        ttk.Label(outer, text="Key").grid(row=6, column=0, sticky="e", **pad)
        key_frame = ttk.Frame(outer)
        key_frame.grid(row=6, column=1, sticky="w", **pad)
        self.algorithm_var = tk.StringVar(value=self.cfg.keys.algorithm)
        self.size_var = tk.StringVar(
            value=str(self.cfg.keys.rsa_bits) if self.cfg.keys.algorithm == "rsa" else self.cfg.keys.ec_curve
        )
        ttk.Combobox(
            key_frame, textvariable=self.algorithm_var, values=["rsa", "ec"], width=6, state="readonly"
        ).pack(side="left")
        self.size_combo = ttk.Combobox(key_frame, textvariable=self.size_var, width=10, state="readonly")
        self.size_combo.pack(side="left", padx=(8, 0))
        self.algorithm_var.trace_add("write", lambda *_: self._update_sizes())
        self._update_sizes()

        ttk.Label(outer, text="Extra SANs").grid(row=7, column=0, sticky="e", **pad)
        san_frame = ttk.Frame(outer)
        san_frame.grid(row=7, column=1, sticky="we", **pad)
        self.san_var = tk.StringVar()
        ttk.Entry(san_frame, textvariable=self.san_var).pack(fill="x")
        ttk.Label(outer, text="Comma-separated DNS names, IPs or e-mails", foreground=MUTED).grid(
            row=7, column=2, sticky="w"
        )

        ttk.Label(outer, text="Authenticate with").grid(row=8, column=0, sticky="e", **pad)
        self.auth_var = tk.StringVar()
        self.auth_combo = ttk.Combobox(outer, textvariable=self.auth_var, state="readonly")
        self.auth_combo.grid(row=8, column=1, sticky="we", **pad)
        self.auth_hint = ttk.Label(outer, text="", foreground=MUTED)
        self.auth_hint.grid(row=8, column=2, sticky="w")

        pin_frame = ttk.LabelFrame(outer, text="PIN", padding=10)
        pin_frame.grid(row=9, column=0, columnspan=3, sticky="we", pady=(10, 0))
        pin_frame.columnconfigure(1, weight=1)
        ttk.Label(pin_frame, text="PIN").grid(row=0, column=0, sticky="e", padx=(0, 8))
        self.pin_var = tk.StringVar()
        self.pin_entry = ttk.Entry(pin_frame, textvariable=self.pin_var, show="*", width=28)
        self.pin_entry.grid(row=0, column=1, sticky="w")
        self.show_pin = tk.BooleanVar(value=False)
        ttk.Checkbutton(pin_frame, text="Show", variable=self.show_pin, command=self._toggle_pin).grid(
            row=0, column=2, padx=(8, 0)
        )
        self.generate_pin_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            pin_frame,
            text="Generate a strong PIN for me",
            variable=self.generate_pin_var,
            command=self._toggle_generate,
        ).grid(row=0, column=3, padx=(18, 0))
        ttk.Label(
            pin_frame,
            text=(
                "At least 10 characters. The RA checks it by hashing what you tell them, so keep it\n"
                "short enough to read out, but not guessable. pyCert never stores it."
            ),
            foreground=MUTED,
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))

        options = ttk.Frame(outer)
        options.grid(row=10, column=0, columnspan=3, sticky="we", pady=(10, 0))
        self.wait_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options, text="Wait for signing, then download and export the .p12", variable=self.wait_var
        ).pack(anchor="w")
        self.export_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Write a PKCS#12 file", variable=self.export_var).pack(anchor="w")

        self.status_label = ttk.Label(outer, text="", foreground=MUTED, wraplength=680)
        self.status_label.grid(row=11, column=0, columnspan=3, sticky="w", pady=(8, 0))

        buttons = ttk.Frame(outer)
        buttons.grid(row=12, column=0, columnspan=3, sticky="e", pady=(12, 0))
        self.submit_button = ttk.Button(buttons, text="Submit request", command=self._submit)
        self.submit_button.pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(0, 8))

        self._toggle_generate()

    # -- behaviour ---------------------------------------------------------
    def _update_sizes(self) -> None:
        if self.algorithm_var.get() == "rsa":
            self.size_combo.configure(values=["2048", "3072", "4096"])
            if self.size_var.get() not in ("2048", "3072", "4096"):
                self.size_var.set(str(self.cfg.keys.rsa_bits))
        else:
            self.size_combo.configure(values=["P-256", "P-384", "P-521"])
            if self.size_var.get() not in ("P-256", "P-384", "P-521"):
                self.size_var.set(self.cfg.keys.ec_curve)

    def _toggle_pin(self) -> None:
        self.pin_entry.configure(show="" if self.show_pin.get() else "*")

    def _toggle_generate(self) -> None:
        state = "disabled" if self.generate_pin_var.get() else "normal"
        self.pin_entry.configure(state=state)

    def _on_type_change(self) -> None:
        host = self.type_var.get() == "host"
        self.cn_label.configure(text="Host name" if host else "Full name")
        self.email_hint.configure(text="administrator contact" if host else "")
        self.auth_combo.configure(state="readonly" if host else "disabled")
        self.auth_hint.configure(text="an existing valid certificate signs the host request" if host else "")
        if host and not self.auth_combo.cget("values"):
            self._load_auth_aliases()

    def _load_auth_aliases(self) -> None:
        aliases = []
        for state in self.ctx.store.list():
            remaining = state.days_remaining
            if state.cert.not_after and state.status != "REVOKED" and (remaining is None or remaining > 0):
                aliases.append(state.alias)
        self.auth_combo.configure(values=aliases)
        if aliases and not self.auth_var.get():
            self.auth_var.set(aliases[0])

    def _fetch_ras(self) -> None:
        self.fetch_button.configure(state="disabled")
        self.status_label.configure(text="Fetching the RA list from the CA...")

        def work(_progress):
            return list_ras(self.ctx)

        def done(result):
            self.fetch_button.configure(state="normal")
            if isinstance(result, Exception):
                self.status_label.configure(text=f"Could not fetch RAs: {result}")
                return
            self._ras = [ra.label for ra in result]
            self.ra_combo.configure(values=self._ras)
            self.status_label.configure(text=f"{len(self._ras)} RAs available")

        self.app.run_background(work, done)

    def _submit(self) -> None:
        san_dns, san_email, san_ip = [], [], []
        for value in (self.san_var.get() or "").split(","):
            value = value.strip()
            if not value:
                continue
            if "@" in value:
                san_email.append(value)
            elif value.replace(".", "").isdigit() or ":" in value:
                san_ip.append(value)
            else:
                san_dns.append(value)
        try:
            spec = RequestSpec.build(
                self.cfg,
                self.cn_entry.get(),
                type=self.type_var.get(),
                email=self.email_var.get(),
                ra=" ".join([self.ou_var.get().strip(), self.l_var.get().strip()]).strip(),
                o=self.o_var.get(),
                c=self.c_var.get(),
                key_algorithm=self.algorithm_var.get(),
                rsa_bits=int(self.size_var.get()) if self.algorithm_var.get() == "rsa" else 0,
                ec_curve=self.size_var.get() if self.algorithm_var.get() == "ec" else "",
                pin="" if self.generate_pin_var.get() else self.pin_var.get(),
                san_dns=san_dns,
                san_email=san_email,
                san_ip=san_ip,
                auth_alias=self.auth_var.get() if self.type_var.get() == "host" else "",
            )
        except PyCertError as exc:
            messagebox.showerror("Check the form", str(exc), parent=self)
            return
        self.submit_button.configure(state="disabled")
        self.status_label.configure(text="Generating the key and submitting...")
        wait = self.wait_var.get()

        def work(progress):
            pins: "list[str]" = []
            state = create_request(
                self.ctx,
                spec,
                progress=progress,
                on_pin=pins.append,
                wait=False,
            )
            return state, (pins[0] if pins else "")

        def done(result):
            if isinstance(result, Exception):
                self.submit_button.configure(state="normal")
                self.status_label.configure(text="")
                self.app.show_error("The request could not be submitted", result)
                return
            state, pin = result
            self.destroy()
            if pin:
                PinDialog(self.app, pin, state.cn)
            self.app.after_change(f"Request '{state.alias}' submitted")
            if wait:
                self.app.wait_for_state(state, export=self.export_var.get())

        self.app.run_background(work, done)


# ---------------------------------------------------------------------------
# Revoke dialog
# ---------------------------------------------------------------------------


class RevokeDialog(tk.Toplevel):
    def __init__(self, app: "PyCertApp", state: RequestState):  # noqa: F821
        super().__init__(app)
        self.app = app
        self.state = state
        self.title("Revoke certificate")
        self.transient(app)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"Revoke '{state.cn}'?", font=("TkDefaultFont", 13, "bold")).pack(anchor="w")
        ttk.Label(
            body,
            text=(
                "Revocation is permanent and immediately visible to relying services.\n"
                "The local files are kept, but the status is marked REVOKED."
            ),
            foreground=MUTED,
            justify="left",
        ).pack(anchor="w", pady=(4, 12))
        ttk.Label(body, text="Reason").pack(anchor="w")
        self.reason = ttk.Combobox(
            body,
            values=[
                "unspecified",
                "keyCompromise",
                "affiliationChanged",
                "superseded",
                "cessationOfOperation",
                "certificateHold",
            ],
            state="readonly",
            width=28,
        )
        self.reason.set("unspecified")
        self.reason.pack(anchor="w", pady=(4, 14))
        self.confirm = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            body,
            text=f"I understand this revokes {state.cn}",
            variable=self.confirm,
        ).pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(16, 0))
        self.revoke_button = ttk.Button(buttons, text="Revoke", command=self._revoke, state="disabled")
        self.revoke_button.pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(0, 8))
        self.confirm.trace_add(
            "write",
            lambda *_: self.revoke_button.configure(state="normal" if self.confirm.get() else "disabled"),
        )
        self.grab_set()

    def _revoke(self) -> None:
        self.revoke_button.configure(state="disabled")
        reason = self.reason.get()

        def work(progress):
            return revoke(self.app.ctx, self.state.alias, reason=reason, progress=progress)

        def done(result):
            if isinstance(result, Exception):
                self.revoke_button.configure(state="normal")
                self.app.show_error("Revocation failed", result)
                return
            self.destroy()
            self.app.after_change(f"'{self.state.alias}' revoked")

        self.app.run_background(work, done)


# ---------------------------------------------------------------------------
# Settings dialog
# ---------------------------------------------------------------------------


class SettingsDialog(tk.Toplevel):
    def __init__(self, app: "PyCertApp"):  # noqa: F821
        super().__init__(app)
        self.app = app
        self.cfg = app.cfg
        self.ctx = app.ctx
        self.title("Settings")
        self.transient(app)
        self.minsize(780, 660)
        self._build()
        self.grab_set()

    def _build(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        self._server_tab(notebook)
        self._identity_tab(notebook)
        self._keys_tab(notebook)
        self._secrets_tab(notebook)
        self._chain_tab(notebook)
        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Save", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(0, 8))
        ttk.Button(buttons, text="Reload", command=self._reload).pack(side="left")

    def _tab(self, notebook: ttk.Notebook, title: str) -> ttk.Frame:
        frame = ttk.Frame(notebook, padding=14)
        notebook.add(frame, text=title)
        frame.columnconfigure(1, weight=1)
        return frame

    def _row(self, frame: ttk.Frame, row: int, label: str, widget: tk.Widget, hint: str = "") -> None:
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="e", padx=(0, 10), pady=6)
        widget.grid(row=row, column=1, sticky="we", pady=6)
        if hint:
            frame.columnconfigure(2, weight=1)
            ttk.Label(frame, text=hint, foreground=MUTED, wraplength=300, justify="left").grid(
                row=row, column=2, sticky="w", padx=(12, 0), pady=6
            )

    def _server_tab(self, notebook: ttk.Notebook) -> None:
        frame = self._tab(notebook, "Server")
        self.base_url = tk.StringVar(value=self.cfg.ca.base_url)
        self._row(
            frame,
            0,
            "Base URL",
            ttk.Entry(frame, textvariable=self.base_url),
            "e.g. https://cwiz-live.ca.ngs.ac.uk:443",
        )
        self.timeout = tk.StringVar(value=str(self.cfg.ca.timeout))
        self._row(frame, 2, "Timeout (s)", ttk.Entry(frame, textvariable=self.timeout))
        self.retries = tk.StringVar(value=str(self.cfg.ca.retries))
        self._row(frame, 3, "Retries", ttk.Entry(frame, textvariable=self.retries))
        self.tls_verify = tk.BooleanVar(value=self.cfg.ca.tls_verify)
        ttk.Checkbutton(frame, text="Verify the server's TLS certificate", variable=self.tls_verify).grid(
            row=4, column=1, sticky="w", pady=6
        )
        self.tls_trust = tk.StringVar(value=self.cfg.ca.tls_trust)
        trust = ttk.Combobox(
            frame, textvariable=self.tls_trust, values=["chain", "system", "both"], state="readonly"
        )
        self._row(frame, 5, "TLS trust", trust, "'chain' uses the CA chain below as trust anchors")
        self.allow_plaintext = tk.BooleanVar(value=self.cfg.ca.allow_plaintext)
        ttk.Checkbutton(
            frame, text="Allow plaintext HTTP (not recommended)", variable=self.allow_plaintext
        ).grid(row=6, column=1, sticky="w", pady=6)
        self.allow_sha1 = tk.BooleanVar(value=self.cfg.ca.allow_sha1)
        ttk.Checkbutton(
            frame, text="Accept SHA-1 certificates in chains (historic roots)", variable=self.allow_sha1
        ).grid(row=7, column=1, sticky="w", pady=6)

    def _identity_tab(self, notebook: ttk.Notebook) -> None:
        frame = self._tab(notebook, "Identity")
        self.attr_vars = {}
        for index, (key, label) in enumerate(
            [("o", "Organisation"), ("ou", "Organisational unit"), ("l", "Locality"), ("c", "Country")]
        ):
            variable = tk.StringVar(value=getattr(self.cfg.identity, key))
            self.attr_vars[key] = variable
            self._row(frame, index, label, ttk.Entry(frame, textvariable=variable))
        self.email = tk.StringVar(value=self.cfg.identity.email)
        self._row(frame, 4, "E-mail", ttk.Entry(frame, textvariable=self.email))
        self.ra = tk.StringVar(value=self.cfg.identity.ra)
        self._row(frame, 5, "RA", ttk.Entry(frame, textvariable=self.ra), "Format: 'OU L', e.g. 'CLRC DL'")

    def _keys_tab(self, notebook: ttk.Notebook) -> None:
        frame = self._tab(notebook, "Keys & CSR")
        self.algorithm = tk.StringVar(value=self.cfg.keys.algorithm)
        self._row(
            frame,
            0,
            "Algorithm",
            ttk.Combobox(frame, textvariable=self.algorithm, values=["rsa", "ec"], state="readonly"),
        )
        self.bits = tk.StringVar(value=str(self.cfg.keys.rsa_bits))
        self._row(
            frame,
            1,
            "RSA bits",
            ttk.Combobox(frame, textvariable=self.bits, values=["2048", "3072", "4096"], state="readonly"),
        )
        self.curve = tk.StringVar(value=self.cfg.keys.ec_curve)
        self._row(
            frame,
            2,
            "EC curve",
            ttk.Combobox(
                frame, textvariable=self.curve, values=["P-256", "P-384", "P-521"], state="readonly"
            ),
        )
        self.csr_hash = tk.StringVar(value=self.cfg.csr.hash)
        self._row(
            frame,
            3,
            "CSR hash",
            ttk.Combobox(
                frame, textvariable=self.csr_hash, values=["sha256", "sha384", "sha512"], state="readonly"
            ),
        )
        self.pin_hash = tk.StringVar(value=self.cfg.csr.pin_hash)
        self._row(
            frame,
            4,
            "PIN hash",
            ttk.Combobox(frame, textvariable=self.pin_hash, values=["sha1", "sha256"], state="readonly"),
            "SHA-1 is required by the current CA",
        )
        self.extensions = tk.StringVar(value=", ".join(self.cfg.csr.extensions))
        self._row(
            frame,
            5,
            "CSR extensions",
            ttk.Entry(frame, textvariable=self.extensions),
            "san, key_usage, extended_key_usage, basic_constraints",
        )
        self.p12_name = tk.StringVar(value=self.cfg.p12.filename_template)
        self._row(
            frame,
            6,
            "P12 filename",
            ttk.Entry(frame, textvariable=self.p12_name),
            "{cn} is replaced with the common name",
        )
        self.export_dir = tk.StringVar(value=self.cfg.p12.export_dir)
        self._row(
            frame,
            7,
            "P12 directory",
            ttk.Entry(frame, textvariable=self.export_dir),
            "empty = the request directory",
        )
        self.include_chain = tk.BooleanVar(value=self.cfg.p12.include_chain)
        ttk.Checkbutton(
            frame, text="Include the CA chain in the PKCS#12 file", variable=self.include_chain
        ).grid(row=8, column=1, sticky="w", pady=6)

    def _secrets_tab(self, notebook: ttk.Notebook) -> None:
        frame = self._tab(notebook, "Secrets")
        self.backend = tk.StringVar(value=self.cfg.secrets.backend)
        self._row(
            frame,
            0,
            "Backend",
            ttk.Combobox(
                frame,
                textvariable=self.backend,
                values=["auto", "keychain", "secret-service", "file", "command", "env", "prompt"],
                state="readonly",
            ),
            "Where the saved PKCS#12/key passphrase lives",
        )
        self.service = tk.StringVar(value=self.cfg.secrets.service)
        self._row(frame, 1, "Service", ttk.Entry(frame, textvariable=self.service))
        self.account = tk.StringVar(value=self.cfg.secrets.account)
        self._row(frame, 2, "Account", ttk.Entry(frame, textvariable=self.account))
        self.command = tk.StringVar(value=self.cfg.secrets.command)
        self._row(
            frame,
            3,
            "Command",
            ttk.Entry(frame, textvariable=self.command),
            "for backend=command; reads stdout / writes stdin",
        )
        ttk.Label(frame, text=f"Active backend: {self.ctx.secrets}", foreground=MUTED).grid(
            row=4, column=1, sticky="w", pady=(10, 4)
        )
        ttk.Button(frame, text="Test the secret store", command=self._test_secret).grid(
            row=5, column=1, sticky="w"
        )
        ttk.Label(
            frame,
            text=(
                "Changing the backend does not move an existing secret. Use 'pycert secret set'\n"
                "after saving if you switch backends."
            ),
            foreground=MUTED,
            justify="left",
        ).grid(row=6, column=1, sticky="w", pady=(12, 0))

    def _chain_tab(self, notebook: ttk.Notebook) -> None:
        frame = self._tab(notebook, "CA chain")
        frame.columnconfigure(0, weight=1)
        columns = ("subject", "expires", "fingerprint")
        self.chain_tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
        for column, width in (("subject", 330), ("expires", 110), ("fingerprint", 330)):
            self.chain_tree.heading(column, text=column.title())
            self.chain_tree.column(column, width=width, anchor="w")
        self.chain_tree.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self._load_chain_rows()
        ttk.Button(frame, text="Add PEM file...", command=self._add_chain_file).grid(
            row=1, column=0, sticky="w", pady=(10, 0)
        )
        ttk.Button(frame, text="Remove selected", command=self._remove_chain_entry).grid(
            row=1, column=1, sticky="w", pady=(10, 0)
        )
        ttk.Label(
            frame,
            text=(
                "Entries are pinned by SHA-256. Adding the issuing CA and the root gives the\n"
                "shortest, most reliable chain for exported PKCS#12 files."
            ),
            foreground=MUTED,
            justify="left",
        ).grid(row=2, column=0, sticky="w", pady=(10, 0))

    def _load_chain_rows(self) -> None:
        for item in self.chain_tree.get_children():
            self.chain_tree.delete(item)
        try:
            bundle = self.cfg.load_chain()
        except PyCertError:
            return
        for cert in bundle.certificates:
            description = certs.describe_certificate(cert)
            self.chain_tree.insert(
                "",
                "end",
                values=(
                    description.subject,
                    str(description.not_after.date()),
                    description.fingerprint_sha256,
                ),
            )

    def _add_chain_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Add CA certificate",
            filetypes=[("PEM certificates", "*.pem"), ("All files", "*")],
        )
        if not path:
            return
        try:
            data = Path(path).read_bytes()
            parsed = certs.load_certificates(data)
        except PyCertError as exc:
            messagebox.showerror("Could not read certificate", str(exc), parent=self)
            return
        target_dir = self.cfg.directory / "chain"
        target_dir.mkdir(parents=True, exist_ok=True)
        for cert in parsed:
            target = target_dir / f"{certs.fingerprint(cert)[:16]}.pem"
            target.write_text(certs.cert_pem(cert))
            self.cfg.chain.append(
                ChainEntry(
                    label=certs.name_to_string(cert.subject),
                    file=str(target.relative_to(self.cfg.directory)),
                    sha256=certs.fingerprint(cert),
                )
            )
        self._load_chain_rows()

    def _remove_chain_entry(self) -> None:
        selected = self.chain_tree.selection()
        if not selected:
            return
        values = self.chain_tree.item(selected[0], "values")
        fingerprint = values[2].replace(":", "").lower()
        for entry in self.cfg.chain:
            if entry.file:
                path = entry.resolved_path(self.cfg.directory)
                if path and path.is_file():
                    try:
                        cert = certs.load_certificate(path.read_bytes())
                    except PyCertError:
                        continue
                    if certs.fingerprint(cert) == fingerprint:
                        self.cfg.chain.remove(entry)
                        break
        self._load_chain_rows()

    def _test_secret(self) -> None:
        store = SecretStore(self.cfg.secrets, self.cfg.data_dir, self.cfg.profile)
        if store.exists(self.cfg.secrets.account):
            messagebox.showinfo("Secret store", f"OK: a secret is stored in {store}", parent=self)
        else:
            messagebox.showwarning(
                "Secret store",
                f"No secret stored in {store}. Save the settings, then run:\n"
                f"pycert secret set --account {self.cfg.secrets.account}",
                parent=self,
            )

    def _reload(self) -> None:
        self.destroy()
        SettingsDialog(self.app)

    def _save(self) -> None:
        self.cfg.ca.base_url = self.base_url.get().strip()
        try:
            self.cfg.ca.timeout = float(self.timeout.get())
            self.cfg.ca.retries = int(self.retries.get())
            self.cfg.keys.rsa_bits = int(self.bits.get())
        except ValueError:
            messagebox.showerror("Settings", "Timeout, retries and RSA bits must be numbers", parent=self)
            return
        self.cfg.ca.tls_verify = self.tls_verify.get()
        self.cfg.ca.tls_trust = self.tls_trust.get()
        self.cfg.ca.allow_plaintext = self.allow_plaintext.get()
        self.cfg.ca.allow_sha1 = self.allow_sha1.get()
        for key, variable in self.attr_vars.items():
            setattr(self.cfg.identity, key, variable.get().strip())
        self.cfg.identity.email = self.email.get().strip()
        self.cfg.identity.ra = self.ra.get().strip()
        self.cfg.keys.algorithm = self.algorithm.get()
        self.cfg.keys.ec_curve = self.curve.get()
        self.cfg.csr.hash = self.csr_hash.get()
        self.cfg.csr.pin_hash = self.pin_hash.get()
        self.cfg.csr.extensions = [item.strip() for item in self.extensions.get().split(",") if item.strip()]
        self.cfg.p12.filename_template = self.p12_name.get().strip()
        self.cfg.p12.export_dir = self.export_dir.get().strip()
        self.cfg.p12.include_chain = self.include_chain.get()
        self.cfg.secrets.backend = self.backend.get()
        self.cfg.secrets.service = self.service.get().strip()
        self.cfg.secrets.account = self.account.get().strip()
        self.cfg.secrets.command = self.command.get().strip()
        try:
            from .config import validate_config

            self.cfg.invalidate_chain_cache()
            validate_config(self.cfg)
            self.cfg.load_chain()
            write_config(self.cfg.path, self.cfg)
        except PyCertError as exc:
            messagebox.showerror("Settings not saved", str(exc), parent=self)
            return
        self.app.reload_config()
        self.destroy()
        self.app.after_change("Settings saved")


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------


class PyCertApp(tk.Tk):
    def __init__(self, config_path: "str | None" = None):
        super().__init__()
        self.config_path = config_path
        self.cfg: Config = load_config(config_path)
        self.ctx: AppContext = AppContext.from_config(self.cfg)
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._busy_count = 0
        self._selected_alias: "str | None" = None
        self._sort_column = "alias"
        self._sort_reverse = False

        self.title(f"{APP_TITLE} - {self.cfg.profile}")
        self.geometry("1220x800")
        self.minsize(980, 640)
        self._build_style()
        self._build_menu()
        self._build_header()
        self._build_toolbar()
        self._build_body()
        self._build_log()
        self._build_statusbar()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.refresh_list()
        self.after(120, self._drain_queue)
        self.after(400, self._startup_ping)

    # -- styling -----------------------------------------------------------
    def _build_style(self) -> None:
        style = ttk.Style(self)
        if sys.platform == "darwin":
            try:
                style.theme_use("aqua")
            except tk.TclError:
                pass
        else:
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
        style.configure("Heading.TLabel", font=("TkDefaultFont", 18, "bold"))
        style.configure("Subtle.TLabel", foreground=MUTED)
        style.configure("Status.TLabel", padding=(8, 4))
        style.configure("Treeview", rowheight=24)
        style.configure("Treeview.Heading", font=("TkDefaultFont", 10, "bold"))
        style.configure("Accent.TButton", font=("TkDefaultFont", 11, "bold"))

    # -- menus -------------------------------------------------------------
    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(
            label="New request...",
            accelerator="Cmd+N" if sys.platform == "darwin" else "Ctrl+N",
            command=self.new_request,
        )
        file_menu.add_command(label="Import PKCS#12...", command=self.import_p12_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Open configuration", command=lambda: _open_text_file(self.cfg.path))
        file_menu.add_command(label="Open data folder", command=lambda: _open_path(self.cfg.data_dir))
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self._on_close)
        menu.add_cascade(label="File", menu=file_menu)

        cert_menu = tk.Menu(menu, tearoff=False)
        cert_menu.add_command(label="Refresh list", command=self.refresh_list)
        cert_menu.add_command(label="Refresh status of all pending", command=self.refresh_pending)
        cert_menu.add_command(label="Wait for signing...", command=self.wait_selected)
        cert_menu.add_command(label="Download && export", command=self.download_selected)
        cert_menu.add_command(label="Re-export .p12", command=self.export_selected)
        cert_menu.add_command(label="Verify", command=self.verify_selected)
        cert_menu.add_separator()
        cert_menu.add_command(label="Renew...", command=self.renew_selected)
        cert_menu.add_command(label="Revoke...", command=self.revoke_selected)
        menu.add_cascade(label="Certificate", menu=cert_menu)

        tools_menu = tk.Menu(menu, tearoff=False)
        tools_menu.add_command(label="Ping the CA", command=self.ping_server)
        tools_menu.add_command(label="Show CA info", command=self.show_ca_info)
        tools_menu.add_command(label="Secret store...", command=self.show_secret_info)
        tools_menu.add_command(label="Run diagnostics (doctor)", command=self.run_diagnostics)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings...", command=lambda: SettingsDialog(self))
        menu.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Documentation", command=lambda: _open_doc("README.md"))
        help_menu.add_command(
            label="Configuration reference", command=lambda: _open_doc("docs/CONFIGURATION.md")
        )
        help_menu.add_command(label="Security notes", command=lambda: _open_doc("SECURITY.md"))
        help_menu.add_separator()
        help_menu.add_command(label="About pyCert", command=self.show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu)

        modifier = "Command" if sys.platform == "darwin" else "Control"
        self.bind_all(f"<{modifier}-n>", lambda _e: self.new_request())
        self.bind_all(f"<{modifier}-r>", lambda _e: self.refresh_list())
        self.bind_all(f"<{modifier}-e>", lambda _e: self.export_selected())
        self.bind_all(f"<{modifier}-q>", lambda _e: self._on_close())

    # -- header ------------------------------------------------------------
    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(16, 12, 16, 6))
        header.pack(fill="x")
        left = ttk.Frame(header)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="pyCert", style="Heading.TLabel").pack(side="left")
        ttk.Label(
            left,
            text=f"  profile {self.cfg.profile}  ·  {self.cfg.ca.base_url}",
            style="Subtle.TLabel",
        ).pack(side="left", pady=(6, 0))
        self.online_label = ttk.Label(header, text="checking CA...", style="Status.TLabel")
        self.online_label.pack(side="right")

    # -- toolbar -----------------------------------------------------------
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(16, 4))
        bar.pack(fill="x")
        self.buttons: "dict[str, ttk.Button]" = {}
        definitions = [
            ("new", "New request", self.new_request, "Create a key and submit a CSR"),
            ("refresh", "Refresh", self.refresh_list, "Re-read the local store"),
            ("wait", "Wait for signing", self.wait_selected, "Poll the CA until the certificate is issued"),
            (
                "download",
                "Download && export",
                self.download_selected,
                "Store the certificate and write the .p12",
            ),
            (
                "export",
                "Re-export .p12",
                self.export_selected,
                "Write the PKCS#12 again with the saved secret",
            ),
            ("verify", "Verify", self.verify_selected, "Check key, certificate, chain and PKCS#12"),
        ]
        for name, label, command, tip in definitions:
            button = ttk.Button(bar, text=label, command=command)
            button.pack(side="left", padx=(0, 6))
            Tooltip(button, tip)
            self.buttons[name] = button
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        for name, label, command, tip in [
            ("renew", "Renew...", self.renew_selected, "Request a renewal signed with the current key"),
            ("revoke", "Revoke...", self.revoke_selected, "Revoke the certificate at the CA"),
            ("folder", "Open folder", self._open_selected_folder, "Show the files for this request"),
        ]:
            button = ttk.Button(bar, text=label, command=command)
            button.pack(side="left", padx=(0, 6))
            Tooltip(button, tip)
            self.buttons[name] = button
        ttk.Button(bar, text="Settings", command=lambda: SettingsDialog(self)).pack(side="right")
        self._update_buttons()

    # -- body --------------------------------------------------------------
    def _build_body(self) -> None:
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=16, pady=(6, 6))

        left = ttk.Frame(paned)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        columns = ("alias", "type", "status", "expires", "days", "p12")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        headings = {
            "alias": ("Alias / common name", 220),
            "type": ("Type", 60),
            "status": ("Status", 110),
            "expires": ("Expires", 100),
            "days": ("Days", 55),
            "p12": ("P12", 45),
        }
        for column, (title, width) in headings.items():
            self.tree.heading(column, text=title, command=lambda c=column: self._sort_by(c))
            self.tree.column(column, width=width, anchor="w", stretch=(column == "alias"))
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _e: self.show_details())
        self.tree.tag_configure("pending", foreground="#8a5a00")
        self.tree.tag_configure("valid", foreground="#155724")
        self.tree.tag_configure("expiring", foreground="#a94400")
        self.tree.tag_configure("expired", foreground="#9b1c1c")
        self.tree.tag_configure("revoked", foreground="#6b1d6b")
        self.tree.tag_configure("failed", foreground="#9b1c1c")
        paned.add(left, weight=3)

        right = ttk.Frame(paned)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        overview = ttk.Frame(self.notebook, padding=12)
        overview.columnconfigure(1, weight=1)
        self.overview_labels: "dict[str, ttk.Label]" = {}
        rows = [
            ("status", "Status"),
            ("type", "Type"),
            ("cn", "Common name"),
            ("subject", "Subject"),
            ("issuer", "Issuer"),
            ("validity", "Validity"),
            ("days", "Days remaining"),
            ("key", "Key"),
            ("serial", "Serial"),
            ("fingerprint", "SHA-256"),
            ("sans", "Subject alt names"),
            ("verified", "Chain verified"),
            ("p12", "PKCS#12"),
            ("directory", "Directory"),
            ("server", "CA state"),
            ("notes", "Notes"),
        ]
        for index, (key, label) in enumerate(rows):
            ttk.Label(overview, text=label, style="Subtle.TLabel").grid(
                row=index, column=0, sticky="ne", padx=(0, 12), pady=2
            )
            value = ttk.Label(overview, text="", wraplength=560, justify="left")
            value.grid(row=index, column=1, sticky="w", pady=2)
            self.overview_labels[key] = value
        overview_buttons = ttk.Frame(overview)
        overview_buttons.grid(row=len(rows), column=0, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Button(overview_buttons, text="Verify", command=self.verify_selected).pack(side="left")
        ttk.Button(overview_buttons, text="Copy fingerprint", command=self._copy_fingerprint).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(overview_buttons, text="Open folder", command=self._open_selected_folder).pack(
            side="left", padx=(8, 0)
        )
        self.notebook.add(overview, text="Overview")

        cert_tab = ttk.Frame(self.notebook, padding=6)
        self.cert_text, _scroll, frame = _readonly_text(cert_tab, height=20)
        frame.pack(fill="both", expand=True)
        self.notebook.add(cert_tab, text="Certificate")

        history_tab = ttk.Frame(self.notebook, padding=6)
        self.history_text, _scroll2, frame2 = _readonly_text(history_tab, height=20)
        frame2.pack(fill="both", expand=True)
        self.notebook.add(history_tab, text="History")
        paned.add(right, weight=5)

    def _build_log(self) -> None:
        frame = ttk.Frame(self, padding=(16, 0, 16, 6))
        frame.pack(fill="both")
        top = ttk.Frame(frame)
        top.pack(fill="x")
        self.show_log = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Activity log", variable=self.show_log, command=self._toggle_log).pack(
            side="left"
        )
        ttk.Button(top, text="Clear", command=lambda: _set_text(self.log_text, "")).pack(side="right")
        ttk.Button(top, text="Copy", command=self._copy_log).pack(side="right", padx=(0, 6))
        self.log_frame = ttk.Frame(frame)
        self.log_frame.pack(fill="both", expand=False)
        self.log_text, _scroll, inner = _readonly_text(self.log_frame, height=5)
        inner.pack(fill="both", expand=True)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(16, 2, 16, 8))
        bar.pack(fill="x", side="bottom")
        self.status_label = ttk.Label(bar, text="Ready", style="Subtle.TLabel")
        self.status_label.pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self.progress.pack(side="right")
        self.server_label = ttk.Label(bar, text=self.cfg.ca.base_url, style="Subtle.TLabel")
        self.server_label.pack(side="right", padx=(0, 16))

    # -- background work ---------------------------------------------------
    def run_background(
        self, work: Callable[[Callable[[str], None]], object], done: Callable[[object], None]
    ) -> None:
        """Run *work* in a thread; *done* is called on the Tk main thread."""
        self._busy_count += 1
        self.progress.start(12)
        self.status_label.configure(text="Working...")

        def runner():
            try:
                result = work(self._progress)
            except BaseException as exc:  # noqa: BLE001 - delivered to the GUI
                self._queue.put(("result", exc, done))
            else:
                self._queue.put(("result", result, done))

        threading.Thread(target=runner, daemon=True).start()

    def _progress(self, message: str) -> None:
        self._queue.put(("log", message, None))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload, callback = self._queue.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "result":
                    self._busy_count = max(0, self._busy_count - 1)
                    if self._busy_count == 0:
                        self.progress.stop()
                        self.status_label.configure(text="Ready")
                    try:
                        callback(payload)
                    except Exception:  # noqa: BLE001 - never crash the event loop
                        traceback.print_exc()
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{stamp}  {message}\n")
        # keep the log bounded
        if int(self.log_text.index("end-1c").split(".")[0]) > 400:
            self.log_text.delete("1.0", "50.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.status_label.configure(text=message)

    def _copy_log(self) -> None:
        _clipboard(self, self.log_text.get("1.0", "end-1c"))

    def _toggle_log(self) -> None:
        if self.show_log.get():
            self.log_frame.pack(fill="both", expand=False)
        else:
            self.log_frame.pack_forget()

    # -- list / details ----------------------------------------------------
    def refresh_list(self) -> None:
        selected = self._selected_alias
        for item in self.tree.get_children():
            self.tree.delete(item)
        states = self.ctx.store.list()
        states.sort(key=lambda s: self._sort_key(s), reverse=self._sort_reverse)
        by_slug = {state.slug: state.alias for state in states}
        for state in states:
            expires = state.cert.not_after[:10] if state.cert.not_after else "-"
            days = "" if state.days_remaining is None else str(state.days_remaining)
            self.tree.insert(
                "",
                "end",
                iid=state.slug,
                values=(
                    state.alias,
                    state.type,
                    state.status,
                    expires,
                    days,
                    "yes" if state.p12_path else "no",
                ),
                tags=(self._tag(state),),
            )
        if selected:
            for slug, alias in by_slug.items():
                if alias == selected and self.tree.exists(slug):
                    self.tree.selection_set(slug)
                    self.tree.focus(slug)
                    self._on_select()
                    break
            else:
                if states:
                    first = self.tree.get_children()[0]
                    self.tree.selection_set(first)
                    self.tree.focus(first)
                    self._on_select()
        elif states:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
            self._on_select()
        else:
            self._show_placeholder()
        self._update_buttons()

    @staticmethod
    def _tag(state: RequestState) -> str:
        if state.status == "REVOKED":
            return "revoked"
        if state.status in ("FAILED",):
            return "failed"
        days = state.days_remaining
        if state.cert.not_after:
            if days is not None and days < 0:
                return "expired"
            if days is not None and days <= 30:
                return "expiring"
            return "valid"
        return "pending"

    def _sort_key(self, state: RequestState):
        if self._sort_column == "days":
            return state.days_remaining if state.days_remaining is not None else 10**6
        if self._sort_column == "expires":
            return state.cert.not_after or "9999"
        return getattr(state, self._sort_column, "")

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self.refresh_list()

    def _show_placeholder(self) -> None:
        for label in self.overview_labels.values():
            label.configure(text="")
        self.overview_labels["status"].configure(text="No certificate requests yet")
        _set_text(self.cert_text, "Use File -> New request to create your first certificate.")
        _set_text(self.history_text, "")

    def _on_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            self._selected_alias = None
            self._show_placeholder()
            self._update_buttons()
            return
        try:
            state = self.ctx.store.get_by_slug(selection[0])
        except NotFound:
            return
        self._selected_alias = state.alias
        self._render_state(state)
        self._update_buttons()

    def _render_state(self, state: RequestState) -> None:
        server = " · ".join(
            part
            for part in (
                f"CSR {state.server.csr_id}" if state.server.csr_id else "",
                f"cert {state.server.cert_id}" if state.server.cert_id else "",
                state.server.status,
                f"checked {state.server.last_checked[:19].replace('T', ' ')}"
                if state.server.last_checked
                else "",
            )
            if part
        )
        notes = "\n".join(state.notes[-4:])
        values = {
            "status": state.status + (" (renewal pending)" if state.renewal else ""),
            "type": state.type,
            "cn": state.cn,
            "subject": state.subject,
            "issuer": state.cert.issuer,
            "validity": (
                f"{state.cert.not_before[:10]} .. {state.cert.not_after[:10]}"
                if state.cert.not_after
                else "not issued"
            ),
            "days": f"{state.days_remaining}" if state.days_remaining is not None else "",
            "key": state.key_algorithm,
            "serial": state.cert.serial,
            "fingerprint": state.cert.sha256,
            "sans": ", ".join(state.cert.sans),
            "verified": ("yes" if state.cert.verified else "no") if state.cert.sha256 else "",
            "p12": state.p12_path,
            "directory": str(self.ctx.store.path(state)),
            "server": server,
            "notes": notes,
        }
        for key, value in values.items():
            self.overview_labels[key].configure(text=value or "")
        self._render_certificate(state)
        self._render_history(state)

    def _render_certificate(self, state: RequestState) -> None:
        lines = []
        try:
            certificate = self.ctx.store.load_certificate(state)
        except NotFound:
            _set_text(
                self.cert_text,
                "No certificate has been issued yet.\n\n"
                f"Requested subject: {state.subject}\n"
                f"Key: {state.key_algorithm}\n"
                f"CSR SHA-256: {state.csr_sha256}\n"
                f"Fetching from: {self.cfg.ca.base_url}\n",
            )
            return
        description = certs.describe_certificate(certificate)
        lines.append(f"Subject      {description.subject}")
        lines.append(f"Issuer       {description.issuer}")
        lines.append(f"Serial       {description.serial}")
        lines.append(f"Validity     {description.not_before:%Y-%m-%d} .. {description.not_after:%Y-%m-%d}")
        lines.append(f"Days left    {description.days_remaining}")
        lines.append(f"Key          {description.key}")
        lines.append(f"Signature    {description.signature}")
        lines.append(f"SHA-256      {description.fingerprint_sha256}")
        lines.append(f"Basic        {description.basic_constraints}")
        lines.append(f"Key usage    {', '.join(description.key_usage) or '(none)'}")
        lines.append(f"EKU          {', '.join(description.extended_key_usage) or '(none)'}")
        lines.append(f"SANs         {', '.join(description.subject_alt_names) or '(none)'}")
        if description.aia_urls:
            lines.append(f"AIA          {', '.join(description.aia_urls)}")
        if description.crl_urls:
            lines.append(f"CRL          {', '.join(description.crl_urls)}")
        lines.append(f"SKI          {description.subject_key_id}")
        lines.append(f"AKI          {description.authority_key_id}")
        lines.append("")
        lines.append("Chain (leaf first):")
        try:
            chain_certs = [certificate, *self.ctx.store.load_chain(state)]
        except PyCertError:
            chain_certs = [certificate]
        for index, cert in enumerate(chain_certs):
            info = certs.describe_certificate(cert)
            role = "leaf" if index == 0 else ("root" if cert.subject == cert.issuer else "issuer")
            lines.append(f"  [{index}] {role}: {info.subject}")
            lines.append(f"      expires {info.not_after:%Y-%m-%d}  {info.key}  {info.fingerprint_sha256}")
        lines.append("")
        lines.append("Files:")
        lines.append(f"  key.pem      {self.ctx.store.file(state, 'key.pem')}")
        lines.append(f"  request.csr  {self.ctx.store.file(state, 'request.csr')}")
        lines.append(f"  cert.pem     {self.ctx.store.file(state, 'cert.pem')}")
        lines.append(f"  chain.pem    {self.ctx.store.file(state, 'chain.pem')}")
        lines.append(f"  .p12         {state.p12_path or '(not exported)'}")
        _set_text(self.cert_text, "\n".join(lines))

    def _render_history(self, state: RequestState) -> None:
        lines = [
            f"{entry.get('at', '')}  {entry.get('status', '')}"
            + (f"  —  {entry.get('detail')}" if entry.get("detail") else "")
            for entry in state.history
        ]
        if state.notes:
            lines.append("")
            lines.extend(f"note: {note}" for note in state.notes)
        _set_text(self.history_text, "\n".join(lines) or "No history yet.")

    # -- actions -----------------------------------------------------------
    def _selected_state(self, *, require_cert: bool = False) -> "RequestState | None":
        if not self._selected_alias:
            messagebox.showinfo("pyCert", "Select a certificate first.", parent=self)
            return None
        try:
            state = self.ctx.store.get(self._selected_alias)
        except NotFound:
            self.refresh_list()
            return None
        if require_cert and not state.cert.sha256:
            messagebox.showinfo(
                "pyCert", "This request has no certificate yet. Use 'Wait for signing'.", parent=self
            )
            return None
        return state

    def _update_buttons(self) -> None:
        state = None
        if self._selected_alias:
            try:
                state = self.ctx.store.get(self._selected_alias)
            except NotFound:
                state = None
        has_cert = bool(state and state.cert.sha256)
        pending = bool(state and (state.status in PENDING_STATUSES or state.renewal))
        self.buttons["wait"].configure(state="normal" if pending else "disabled")
        self.buttons["download"].configure(state="normal" if state else "disabled")
        self.buttons["folder"].configure(state="normal" if state else "disabled")
        for name in ("export", "verify", "renew", "revoke"):
            self.buttons[name].configure(state="normal" if has_cert else "disabled")

    def new_request(self) -> None:
        NewRequestDialog(self)

    def refresh_pending(self) -> None:
        self.log("Refreshing the status of pending requests...")
        self.run_background(
            lambda progress: refresh_all(self.ctx, progress=progress),
            lambda result: self._after_refresh_result(result, "status refreshed"),
        )

    def _after_refresh_result(self, result, message: str) -> None:
        if isinstance(result, Exception):
            self.show_error("Could not refresh", result)
            return
        self.after_change(message)

    def wait_selected(self) -> None:
        state = self._selected_state()
        if state is None:
            return
        if state.cert.sha256 and not state.renewal:
            messagebox.showinfo("pyCert", "This certificate is already signed.", parent=self)
            return
        interval = 20.0

        def work(progress):
            return wait_for_certificate(
                self.ctx,
                state,
                progress=progress,
                interval=interval,
                timeout=24 * 3600,
                export=True,
                require_verified_chain=True,
                stop_event=self._stop_event,
            )

        def done(result):
            if isinstance(result, Exception):
                if "cancelled" in str(result).lower():
                    self.log("Waiting cancelled")
                    self.after_change("Waiting cancelled")
                else:
                    self.show_error("Waiting for the certificate failed", result)
                return
            self.after_change(f"Certificate for '{state.alias}' ready")
            if result.p12_path:
                messagebox.showinfo(
                    "Certificate ready",
                    f"Certificate and PKCS#12 are ready for '{state.alias}'.\n\n{result.p12_path}",
                    parent=self,
                )

        WaitDialog(self, "Waiting for signing", work, done)

    def wait_for_state(self, state: RequestState, *, export: bool = True) -> None:
        self._selected_alias = state.alias
        self.refresh_list()
        self.wait_selected()

    def download_selected(self) -> None:
        state = self._selected_state()
        if state is None:
            return

        def work(progress):
            return download_and_export(self.ctx, state, progress=progress, export=True)

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Download failed", result)
                return
            self.after_change(f"Certificate for '{state.alias}' downloaded")
            if result.p12_path:
                messagebox.showinfo(
                    "PKCS#12 written",
                    f"{result.p12_path}\n\nPassphrase: stored in {self.ctx.secrets}",
                    parent=self,
                )

        self.run_background(work, done)

    def export_selected(self) -> None:
        state = self._selected_state(require_cert=True)
        if state is None:
            return

        def work(progress):
            return export_p12(self.ctx, state, progress=progress)

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Export failed", result)
                return
            self.after_change(f"PKCS#12 written to {result}")
            messagebox.showinfo(
                "PKCS#12 written",
                f"{result}\n\nPassphrase: stored in {self.ctx.secrets}",
                parent=self,
            )

        self.run_background(work, done)

    def verify_selected(self) -> None:
        state = self._selected_state()
        if state is None:
            return

        def work(_progress):
            return verify(self.ctx, state.alias)

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Verification failed", result)
                return
            lines = [
                f"[{'OK  ' if passed else 'FAIL'}] {name}" + (f": {detail}" if detail else "")
                for name, passed, detail in result.checks
            ]
            lines += [f"[WARN] {warning}" for warning in result.warnings]
            text = "\n".join(lines)
            if result.ok:
                messagebox.showinfo("Verification", "All checks passed.\n\n" + text, parent=self)
            else:
                messagebox.showwarning("Verification", "Some checks failed.\n\n" + text, parent=self)

        self.run_background(work, done)

    def renew_selected(self) -> None:
        state = self._selected_state(require_cert=True)
        if state is None:
            return
        if state.renewal:
            messagebox.showinfo("pyCert", "A renewal is already in flight.", parent=self)
            return
        if not messagebox.askyesno(
            "Renew",
            f"Request a renewal for '{state.cn}'?\n\n"
            "The request is authenticated with the current certificate's key.",
            parent=self,
        ):
            return
        pins: "list[str]" = []

        def work(progress):
            return renew(self.ctx, state.alias, progress=progress, on_pin=pins.append, wait=False)

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Renewal failed", result)
                return
            if pins:
                PinDialog(self, pins[0], result.cn)
            self.after_change(f"Renewal for '{state.alias}' submitted")
            if messagebox.askyesno(
                "Renewal submitted", "Wait for the renewal to be signed now?", parent=self
            ):
                self.wait_selected()

        self.run_background(work, done)

    def revoke_selected(self) -> None:
        state = self._selected_state(require_cert=True)
        if state is None:
            return
        RevokeDialog(self, state)

    def import_p12_dialog(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Import PKCS#12", filetypes=[("PKCS#12", "*.p12 *.pfx"), ("All files", "*")]
        )
        if not path:
            return
        dialog = tk.Toplevel(self)
        dialog.title("PKCS#12 passphrase")
        dialog.transient(self)
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Passphrase of the file to import").pack(anchor="w")
        value = tk.StringVar()
        entry = ttk.Entry(body, textvariable=value, show="*", width=40)
        entry.pack(fill="x", pady=8)
        entry.focus_set()

        def do_import():
            password = value.get()
            dialog.destroy()
            from .workflow import import_p12

            alias = Path(path).stem

            def work(progress):
                state = import_p12(self.ctx, Path(path), password, alias=alias, progress=progress)
                export_p12(self.ctx, state, progress=progress)
                return state

            def done(result):
                if isinstance(result, Exception):
                    self.show_error("Import failed", result)
                    return
                self._selected_alias = result.alias
                self.after_change(f"Imported '{result.alias}'")

            self.run_background(work, done)

        ttk.Button(body, text="Import", command=do_import).pack(side="right")
        ttk.Button(body, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 8))
        dialog.bind("<Return>", lambda _e: do_import())
        dialog.grab_set()

    def ping_server(self) -> None:
        self.online_label.configure(text="checking CA...")

        def work(_progress):
            client = self.ctx.client()
            started = datetime.now(timezone.utc)
            ok = client.ping()
            return (
                ok,
                client.last_tls,
                (datetime.now(timezone.utc) - started).total_seconds(),
                client.last_error,
            )

        def done(result):
            if isinstance(result, Exception):
                self.online_label.configure(text="CA unreachable")
                self.show_error("Cannot reach the CA", result)
                return
            ok, tls, seconds, error = result
            if ok:
                self.online_label.configure(text=f"CA online ({seconds * 1000:.0f} ms)")
                self.log(f"CA online: {self.cfg.ca.base_url}")
                if tls:
                    self.log(f"TLS peer {tls.subject}, expires {tls.not_after.date()}")
            else:
                self.online_label.configure(text="CA unreachable")
                self.log(f"No response from {self.cfg.ca.base_url}" + (f": {error}" if error else ""))

        self.run_background(work, done)

    def show_ca_info(self) -> None:
        def work(progress):
            client = self.ctx.client()
            info = client.info()
            motd = ""
            try:
                motd = client.motd()
            except PyCertError:
                pass
            return info, motd

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Could not read CA info", result)
                return
            info, motd = result
            lines = []
            if motd:
                lines += ["Message of the day", motd, ""]
            lines.append(f"RAs ({len(info.ras)}): " + ", ".join(ra.label for ra in info.ras[:20]))
            if info.policy:
                lines.append("Policy: " + ", ".join(f"{k}={v}" for k, v in info.policy.items()))
            if info.certificates:
                lines.append("")
                lines.append("CA certificates published by the server (informational):")
                for cert in info.certificates:
                    description = certs.describe_certificate(cert)
                    lines.append(f"  {description.subject}")
                    lines.append(
                        f"    expires {description.not_after.date()}  {description.fingerprint_sha256}"
                    )
            messagebox.showinfo("CA information", "\n".join(lines), parent=self)

        self.run_background(work, done)

    def run_diagnostics(self) -> None:
        def work(_progress):
            from .diagnostics import run_doctor

            return run_doctor(self.ctx)

        def done(result):
            if isinstance(result, Exception):
                self.show_error("Diagnostics failed", result)
                return
            lines = [
                "[%s] %s%s" % (item.status.upper(), item.name, (": " + item.detail) if item.detail else "")
                for item in result
            ]
            failures = [item for item in result if item.status == "fail"]
            title = "Diagnostics: %d problem(s)" % len(failures) if failures else "Diagnostics: all clear"
            (messagebox.showerror if failures else messagebox.showinfo)(title, "\n".join(lines), parent=self)

        self.run_background(work, done)

    def show_secret_info(self) -> None:
        store = SecretStore(self.cfg.secrets, self.cfg.data_dir, self.cfg.profile)
        exists = store.exists(self.cfg.secrets.account)
        messagebox.showinfo(
            "Saved secret",
            f"Backend: {store}\n"
            f"Account: {self.cfg.secrets.account}\n"
            f"Stored:  {'yes' if exists else 'no'}\n\n"
            "The passphrase is never displayed by the GUI. Use\n"
            f"'pycert secret get --show --account {self.cfg.secrets.account}' if you must see it.",
            parent=self,
        )

    def show_details(self) -> None:
        self.notebook.select(1)

    def show_about(self) -> None:
        messagebox.showinfo(
            "About pyCert",
            f"pyCert {__version__}\n\n"
            "A Python replacement for the Java CertWizard client.\n"
            "Requests certificates from the UK e-Science CA, waits for signing,\n"
            "downloads the full chain and writes an encrypted PKCS#12 bundle.\n\n"
            "Cryptography: python-cryptography (OpenSSL).\n"
            f"Configuration: {self.cfg.path}",
            parent=self,
        )

    def _copy_fingerprint(self) -> None:
        state = self._selected_state()
        if state and state.cert.sha256:
            _clipboard(self, state.cert.sha256)
            self.log("Fingerprint copied to the clipboard")

    def _open_selected_folder(self) -> None:
        if not self._selected_alias:
            return
        try:
            state = self.ctx.store.get(self._selected_alias)
        except NotFound:
            return
        _open_path(self.ctx.store.path(state))

    # -- lifecycle ---------------------------------------------------------
    def _startup_ping(self) -> None:
        self.ping_server()

    def reload_config(self) -> None:
        self.cfg = load_config(self.config_path)
        self.ctx = AppContext.from_config(self.cfg)
        self.server_label.configure(text=self.cfg.ca.base_url)
        self.title(f"{APP_TITLE} - {self.cfg.profile}")
        self.refresh_list()

    def after_change(self, message: str) -> None:
        self.log(message)
        self.refresh_list()

    def show_error(self, title: str, error: BaseException) -> None:
        self.log(f"{title}: {error}")
        message = str(error) or error.__class__.__name__
        if isinstance(error, (PyCertError,)):
            messagebox.showerror(title, message, parent=self)
        else:
            messagebox.showerror(
                title,
                f"{message}\n\n{error.__class__.__name__}: see the activity log for details.",
                parent=self,
            )
            traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)

    def _on_close(self) -> None:
        self._stop_event.set()
        self.destroy()


# ---------------------------------------------------------------------------
# Helpers and entry point
# ---------------------------------------------------------------------------


def _open_text_file(path: Path) -> None:
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if editor:
        subprocess.Popen([*shlex.split(editor), str(path)])
    else:
        _open_path(path)


def _open_doc(relative: str) -> None:
    root = Path(__file__).resolve().parent.parent.parent
    candidate = root / relative
    if candidate.is_file():
        _open_path(candidate)
    else:
        messagebox.showinfo(
            "Documentation",
            f"The documentation is in the pyCert source tree: {relative}\n(looked in {root})",
        )


def run_gui(config_path: "str | None" = None) -> int:
    try:
        app = PyCertApp(config_path)
    except PyCertError as exc:
        # Without a working config there is no main window to parent a dialog to.
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("pyCert", f"Cannot start pyCert:\n\n{exc}", parent=root)
        root.destroy()
        return 1
    app.mainloop()
    return 0


def main(argv: "list[str] | None" = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="pycert-gui", description="pyCert graphical interface")
    parser.add_argument("--config", help="configuration file to use")
    parser.add_argument("--version", action="version", version=f"pyCert {__version__}")
    args = parser.parse_args(argv)
    return run_gui(args.config)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
