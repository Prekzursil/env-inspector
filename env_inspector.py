#!/usr/bin/env python3
"""Env Inspector entrypoint.

- CLI mode: `list/set/remove/export/backup/restore`
- GUI mode: launched when no subcommand is provided
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from env_inspector_core.cli import run_cli
from env_inspector_core.models import EnvRecord
from env_inspector_core.path_policy import PathPolicyError, resolve_scan_root
from env_inspector_core.secrets import mask_value
from env_inspector_core.service import EnvInspectorService

CLI_COMMANDS = {"list", "set", "remove", "export", "backup", "restore"}


def _is_windows() -> bool:
    return os.name == "nt"


class TargetPickerDialog:
    def __init__(self, parent: Any, targets: list[str], selected: list[str] | None = None) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.result: list[str] | None = None
        self._vars: list[tuple[str, tk.BooleanVar]] = []
        selected_set = set(selected or [])

        self.win = tk.Toplevel(parent)
        self.win.title("Select Targets")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.resizable(True, True)
        self.win.geometry("840x560")

        frame = ttk.Frame(self.win, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Choose one or more targets for this operation:").pack(anchor="w", pady=(0, 8))

        canvas = tk.Canvas(frame, highlightthickness=0)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)

        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        for target in targets:
            default = target in selected_set if selected else True
            var = tk.BooleanVar(value=default)
            self._vars.append((target, var))
            ttk.Checkbutton(body, text=target, variable=var).pack(anchor="w")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Apply", command=self._apply).pack(side="right")

        self.win.bind("<Escape>", lambda _e: self._cancel())

    def _apply(self) -> None:
        self.result = [name for name, var in self._vars if var.get()]
        self.win.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.win.destroy()


class DotenvTargetDialog:
    def __init__(self, parent: Any, key: str, targets: list[str]) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.result: list[str] | None = None
        self._vars: list[tuple[str, tk.BooleanVar]] = []

        self.win = tk.Toplevel(parent)
        self.win.title("Select .env Targets")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.resizable(False, False)

        frame = ttk.Frame(self.win, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=f"'{key}' appears in multiple .env targets. Choose which file(s) to modify:").pack(
            anchor="w", pady=(0, 8)
        )

        for target in targets:
            var = tk.BooleanVar(value=True)
            self._vars.append((target, var))
            ttk.Checkbutton(frame, text=target, variable=var).pack(anchor="w")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Apply", command=self._apply).pack(side="right")

    def _apply(self) -> None:
        self.result = [name for name, var in self._vars if var.get()]
        self.win.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.win.destroy()


class DiffPreviewDialog:
    def __init__(self, parent: Any, action: str, previews: list[dict[str, Any]]) -> None:
        import tkinter as tk
        from tkinter import scrolledtext, ttk

        self.confirmed = False

        self.win = tk.Toplevel(parent)
        self.win.title(f"Preview {action.title()} Changes")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.geometry("1000x680")

        frame = ttk.Frame(self.win, padding=10)
        frame.pack(fill="both", expand=True)

        txt = scrolledtext.ScrolledText(frame, wrap="none")
        txt.pack(fill="both", expand=True)

        lines: list[str] = []
        for preview in previews:
            lines.append("=" * 100)
            lines.append(f"Target: {preview.get('target')}")
            lines.append(f"Success: {preview.get('success')}")
            if preview.get("error_message"):
                lines.append(f"Error: {preview['error_message']}")
            lines.append("-" * 100)
            diff = preview.get("diff_preview") or "(no textual diff)"
            lines.append(diff)
            lines.append("")

        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Apply", command=self._apply).pack(side="right")

        self.win.bind("<Escape>", lambda _e: self._cancel())

    def _apply(self) -> None:
        self.confirmed = True
        self.win.destroy()

    def _cancel(self) -> None:
        self.confirmed = False
        self.win.destroy()


class BackupPickerDialog:
    def __init__(self, parent: Any, backups: list[str]) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.result: str | None = None

        self.win = tk.Toplevel(parent)
        self.win.title("Restore Backup")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.geometry("920x420")

        frame = ttk.Frame(self.win, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Select backup file to restore:").pack(anchor="w", pady=(0, 8))

        self.listbox = tk.Listbox(frame)
        self.listbox.pack(fill="both", expand=True)
        for item in backups:
            self.listbox.insert("end", item)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Restore", command=self._restore).pack(side="right")

    def _restore(self) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        self.result = str(self.listbox.get(sel[0]))
        self.win.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.win.destroy()


class EnvInspectorApp:
    def __init__(self, root_path: Path) -> None:
        try:
            import tkinter as tk
            from tkinter import filedialog, messagebox, ttk
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "Tkinter is not available in this Python installation. Install tkinter/python3-tk and retry."
            ) from exc

        self.tkmod = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox

        self.service = EnvInspectorService()
        self.root_path = resolve_scan_root(root_path)

        self.records_raw: list[EnvRecord] = []
        self.rows_by_item: dict[str, EnvRecord] = {}
        self.selected_targets: list[str] = []

        self.tk = tk.Tk()
        self.tk.title("Env Inspector (Core + GUI)")
        self.tk.geometry("1480x860")

        self.filter_text = tk.StringVar(value="")
        self.show_secrets = tk.BooleanVar(value=False)
        self.only_secrets = tk.BooleanVar(value=False)

        initial_contexts = self.service.list_contexts()
        default_context = initial_contexts[0] if initial_contexts else self.service.runtime_context
        self.context_var = tk.StringVar(value=default_context)
        self.wsl_distro_var = tk.StringVar(value="")
        self.wsl_path_var = tk.StringVar(value="")
        self.scan_depth_var = tk.IntVar(value=5)

        self.key_text = tk.StringVar(value="")
        self.value_text = tk.StringVar(value="")
        self.effective_value_var = tk.StringVar(value="Effective: (select key)")
        self.targets_summary_var = tk.StringVar(value="Targets: (none selected)")

        self._build_ui()
        self.refresh_data()

    def _build_ui(self) -> None:
        ttk = self.ttk

        top = ttk.Frame(self.tk, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Root folder:").grid(row=0, column=0, sticky="w")
        self.root_label = ttk.Label(top, text=str(self.root_path))
        self.root_label.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(top, text="Choose Folder", command=self.choose_folder).grid(row=0, column=2, padx=4)
        ttk.Button(top, text="Refresh", command=self.refresh_data).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="Context:").grid(row=0, column=4, sticky="e", padx=(16, 4))
        self.context_combo = ttk.Combobox(top, textvariable=self.context_var, state="readonly", width=28)
        self.context_combo.grid(row=0, column=5, sticky="w")
        self.context_combo.bind("<<ComboboxSelected>>", lambda _e: self.render_table())

        ttk.Checkbutton(top, text="Show secrets", variable=self.show_secrets, command=self.render_table).grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        ttk.Checkbutton(top, text="Only secrets", variable=self.only_secrets, command=self.render_table).grid(
            row=1, column=1, sticky="w", pady=(8, 0)
        )

        ttk.Label(top, text="Filter:").grid(row=1, column=2, sticky="e", pady=(8, 0))
        search = ttk.Entry(top, textvariable=self.filter_text)
        search.grid(row=1, column=3, columnspan=3, sticky="ew", padx=4, pady=(8, 0))
        search.bind("<KeyRelease>", lambda _e: self.render_table())
        top.columnconfigure(3, weight=1)

        scan = ttk.LabelFrame(self.tk, text="WSL Dotenv Scan", padding=10)
        scan.pack(fill="x", padx=10, pady=(0, 8))

        ttk.Label(scan, text="WSL distro:").grid(row=0, column=0, sticky="w")
        self.wsl_distro_combo = ttk.Combobox(scan, textvariable=self.wsl_distro_var, state="readonly", width=28)
        self.wsl_distro_combo.grid(row=0, column=1, sticky="w", padx=(4, 10))

        ttk.Label(scan, text="WSL path:").grid(row=0, column=2, sticky="w")
        self.wsl_path_entry = ttk.Entry(scan, textvariable=self.wsl_path_var, width=46)
        self.wsl_path_entry.grid(row=0, column=3, sticky="w", padx=(4, 10))

        ttk.Label(scan, text="Depth:").grid(row=0, column=4, sticky="w")
        self.wsl_depth_spinbox = ttk.Spinbox(scan, from_=1, to=20, textvariable=self.scan_depth_var, width=6)
        self.wsl_depth_spinbox.grid(row=0, column=5, sticky="w", padx=(4, 10))

        self.wsl_scan_button = ttk.Button(scan, text="Apply WSL Scan", command=self.refresh_data)
        self.wsl_scan_button.grid(row=0, column=6, sticky="w")

        mutate = ttk.LabelFrame(self.tk, text="Set / Remove", padding=10)
        mutate.pack(fill="x", padx=10, pady=(0, 8))

        ttk.Label(mutate, text="Key:").grid(row=0, column=0, sticky="w")
        ttk.Entry(mutate, textvariable=self.key_text, width=34).grid(row=0, column=1, sticky="w", padx=(4, 10))

        ttk.Label(mutate, text="Value:").grid(row=0, column=2, sticky="w")
        ttk.Entry(mutate, textvariable=self.value_text, width=52).grid(row=0, column=3, sticky="w", padx=(4, 10))

        ttk.Button(mutate, text="Load Selected", command=self.load_selected).grid(row=0, column=4, padx=(0, 6))
        ttk.Button(mutate, text="Choose Targets", command=self.choose_targets).grid(row=0, column=5, padx=(0, 6))
        ttk.Button(mutate, text="Preview Set", command=lambda: self._run_operation("set", preview=True)).grid(
            row=0, column=6, padx=(0, 6)
        )
        ttk.Button(mutate, text="Set", command=lambda: self._run_operation("set", preview=False)).grid(row=0, column=7, padx=(0, 6))
        ttk.Button(mutate, text="Preview Remove", command=lambda: self._run_operation("remove", preview=True)).grid(
            row=0, column=8, padx=(0, 6)
        )
        ttk.Button(mutate, text="Remove", command=lambda: self._run_operation("remove", preview=False)).grid(row=0, column=9)

        ttk.Label(mutate, textvariable=self.targets_summary_var).grid(row=1, column=0, columnspan=10, sticky="w", pady=(8, 0))
        ttk.Label(mutate, textvariable=self.effective_value_var).grid(row=2, column=0, columnspan=10, sticky="w", pady=(6, 0))

        mid = ttk.Frame(self.tk, padding=(10, 0, 10, 10))
        mid.pack(fill="both", expand=True)

        cols = (
            "context",
            "source",
            "name",
            "value",
            "secret",
            "persistent",
            "mutable",
            "source_path",
        )
        self.tree = ttk.Treeview(mid, columns=cols, show="headings")
        for col, title, width, anchor in [
            ("context", "Context", 140, "w"),
            ("source", "Source", 160, "w"),
            ("name", "Name", 220, "w"),
            ("value", "Value", 420, "w"),
            ("secret", "Secret", 70, "center"),
            ("persistent", "Persistent", 80, "center"),
            ("mutable", "Mutable", 70, "center"),
            ("source_path", "Source Path", 360, "w"),
        ]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor=anchor)

        yscroll = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(mid, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        mid.columnconfigure(0, weight=1)
        mid.rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_row_selected())

        bottom = ttk.Frame(self.tk, padding=10)
        bottom.pack(fill="x")

        ttk.Button(bottom, text="Copy Name", command=self.copy_selected_name).pack(side="left", padx=4)
        ttk.Button(bottom, text="Copy Value", command=self.copy_selected_value).pack(side="left", padx=4)
        ttk.Button(bottom, text="Copy Name=Value", command=self.copy_selected_pair).pack(side="left", padx=4)

        ttk.Button(bottom, text="Export JSON", command=lambda: self.export_records("json")).pack(side="left", padx=(20, 4))
        ttk.Button(bottom, text="Export CSV", command=lambda: self.export_records("csv")).pack(side="left", padx=4)
        ttk.Button(bottom, text="Restore Backup", command=self.restore_backup).pack(side="left", padx=(20, 4))

        self.status = ttk.Label(bottom, text="")
        self.status.pack(side="right")

    def _source_label(self, record: EnvRecord) -> str:
        return record.source_type

    def choose_folder(self) -> None:
        selected = self.filedialog.askdirectory(initialdir=str(self.root_path))
        if not selected:
            return
        self.root_path = resolve_scan_root(selected)
        self.root_label.configure(text=str(self.root_path))
        self.refresh_data()

    def _selected_record(self) -> EnvRecord | None:
        selected = self.tree.selection()
        if not selected:
            return None
        return self.rows_by_item.get(str(selected[0]))

    def _on_row_selected(self) -> None:
        rec = self._selected_record()
        if rec:
            self.key_text.set(rec.name)
            self._update_effective(rec.name)

    def _update_context_values(self) -> None:
        contexts = self.service.list_contexts()
        self.context_combo.configure(values=contexts)
        if self.context_var.get() not in contexts:
            self.context_var.set(contexts[0] if contexts else self.service.runtime_context)

        distros = [c.split(":", 1)[1] for c in contexts if c.startswith("wsl:")]
        self.wsl_distro_combo.configure(values=distros)
        if self.wsl_distro_var.get() not in distros:
            self.wsl_distro_var.set(distros[0] if distros else "")

        self._set_wsl_scan_state(enabled=bool(distros))

    def _set_wsl_scan_state(self, *, enabled: bool) -> None:
        self.wsl_distro_combo.configure(state=("readonly" if enabled else "disabled"))
        state = "normal" if enabled else "disabled"
        for widget in (self.wsl_path_entry, self.wsl_depth_spinbox, self.wsl_scan_button):
            widget.configure(state=state)

    def refresh_data(self) -> None:
        self._update_context_values()

        kwargs = {
            "root": self.root_path,
            "context": self.context_var.get() or None,
            "scan_depth": int(self.scan_depth_var.get() or 5),
        }

        distro = self.wsl_distro_var.get().strip()
        wsl_path = self.wsl_path_var.get().strip()
        if distro and wsl_path:
            kwargs["distro"] = distro
            kwargs["wsl_path"] = wsl_path

        self.records_raw = self.service.list_records_raw(**kwargs)
        self.render_table()

        available = self.service.available_targets(self.records_raw, context=self.context_var.get())
        if not self.selected_targets:
            self.selected_targets = available
        else:
            self.selected_targets = [t for t in self.selected_targets if t in available]
            if not self.selected_targets:
                self.selected_targets = available

        self.targets_summary_var.set(f"Targets: {len(self.selected_targets)} selected")

    def render_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows_by_item.clear()

        query = self.filter_text.get().strip().lower()
        only_secrets = self.only_secrets.get()
        reveal = self.show_secrets.get()

        shown = 0
        for rec in self.records_raw:
            if only_secrets and not rec.is_secret:
                continue
            if self.context_var.get() and rec.context != self.context_var.get():
                continue

            if query:
                hay = " ".join([rec.context, rec.source_type, rec.name, rec.value, rec.source_path]).lower()
                if query not in hay:
                    continue

            value = rec.value if (reveal or not rec.is_secret) else mask_value(rec.value)
            item = self.tree.insert(
                "",
                "end",
                values=(
                    rec.context,
                    self._source_label(rec),
                    rec.name,
                    value,
                    "yes" if rec.is_secret else "no",
                    "yes" if rec.is_persistent else "no",
                    "yes" if rec.is_mutable else "no",
                    rec.source_path,
                ),
            )
            self.rows_by_item[str(item)] = rec
            shown += 1

        self.status.configure(text=f"Showing {shown} / {len(self.records_raw)} entries")

    def _update_effective(self, key: str) -> None:
        context = self.context_var.get() or self.service.runtime_context
        rec = self.service.resolve_effective(key, context, self.records_raw)
        if rec is None:
            self.effective_value_var.set("Effective: (not found)")
            return
        value = rec.value if (self.show_secrets.get() or not rec.is_secret) else mask_value(rec.value)
        self.effective_value_var.set(f"Effective ({context}): {key}={value} from {rec.source_type}")

    def choose_targets(self) -> None:
        available = self.service.available_targets(self.records_raw, context=self.context_var.get())
        if not available:
            self.messagebox.showinfo("Env Inspector", "No writable targets found in current context.")
            return

        dialog = TargetPickerDialog(self.tk, targets=available, selected=self.selected_targets)
        self.tk.wait_window(dialog.win)
        if dialog.result is None:
            return
        if not dialog.result:
            self.messagebox.showinfo("Env Inspector", "No targets selected.")
            return
        self.selected_targets = dialog.result
        self.targets_summary_var.set(f"Targets: {len(self.selected_targets)} selected")

    def _maybe_choose_dotenv_targets(self, key: str, targets: list[str]) -> list[str] | None:
        dotenv_targets = [t for t in targets if t.startswith("dotenv:") or t.startswith("wsl_dotenv:")]
        if len(dotenv_targets) <= 1:
            return targets

        matches = [
            r
            for r in self.records_raw
            if r.name == key and (r.source_type in {"dotenv", "wsl_dotenv"})
        ]
        if len(matches) <= 1:
            return targets

        dialog = DotenvTargetDialog(self.tk, key, dotenv_targets)
        self.tk.wait_window(dialog.win)
        if dialog.result is None:
            return None
        keep = set(dialog.result)
        merged = [t for t in targets if t not in dotenv_targets or t in keep]
        return merged

    def _run_operation(self, action: str, *, preview: bool) -> None:
        key = self.key_text.get().strip()
        value = self.value_text.get()

        if not key:
            self.messagebox.showerror("Env Inspector", "Key is required.")
            return

        targets = list(self.selected_targets)
        if not targets:
            self.choose_targets()
            targets = list(self.selected_targets)
            if not targets:
                return

        scoped_targets = self._maybe_choose_dotenv_targets(key, targets)
        if scoped_targets is None:
            return
        targets = scoped_targets

        try:
            if action == "set":
                previews = self.service.preview_set(key=key, value=value, targets=targets, scope_roots=[self.root_path])
            else:
                previews = self.service.preview_remove(key=key, targets=targets, scope_roots=[self.root_path])
        except Exception as exc:
            self.messagebox.showerror("Env Inspector", f"Failed to compute preview: {exc}")
            return

        dialog = DiffPreviewDialog(self.tk, action=action, previews=previews)
        self.tk.wait_window(dialog.win)
        if not dialog.confirmed:
            return

        if preview:
            self.status.configure(text=f"Previewed {action} for {len(targets)} target(s)")
            return

        try:
            if action == "set":
                result = self.service.set_key(key=key, value=value, targets=targets, scope_roots=[self.root_path])
            else:
                result = self.service.remove_key(key=key, targets=targets, scope_roots=[self.root_path])
        except Exception as exc:
            self.messagebox.showerror("Env Inspector", f"{action.title()} failed: {exc}")
            return

        if isinstance(result, dict) and "results" in result:
            failed = [x for x in result["results"] if not x.get("success")]
            if failed:
                self.messagebox.showerror("Env Inspector", f"{action.title()} had failures:\n" + "\n".join(x.get("error_message", "") for x in failed))
            else:
                self.status.configure(text=f"{action.title()} succeeded for {len(result['results'])} targets")
        else:
            if result.get("success"):
                self.status.configure(text=f"{action.title()} succeeded ({result.get('operation_id')})")
            else:
                self.messagebox.showerror("Env Inspector", f"{action.title()} failed: {result.get('error_message')}")

        self.refresh_data()

    def load_selected(self) -> None:
        rec = self._selected_record()
        if not rec:
            self.messagebox.showinfo("Env Inspector", "Select a row first.")
            return
        self.key_text.set(rec.name)
        self.value_text.set(rec.value)
        self._update_effective(rec.name)

    def _selected_name_value(self) -> tuple[str, str] | None:
        rec = self._selected_record()
        if rec is None:
            self.messagebox.showinfo("Env Inspector", "Select a row first.")
            return None
        return rec.name, rec.value

    def copy_selected_name(self) -> None:
        selected = self._selected_name_value()
        if not selected:
            return
        name, _ = selected
        self.tk.clipboard_clear()
        self.tk.clipboard_append(name)
        self.status.configure(text=f"Copied name: {name}")

    def copy_selected_value(self) -> None:
        selected = self._selected_name_value()
        if not selected:
            return
        name, value = selected
        self.tk.clipboard_clear()
        self.tk.clipboard_append(value)
        self.status.configure(text=f"Copied value for: {name}")

    def copy_selected_pair(self) -> None:
        selected = self._selected_name_value()
        if not selected:
            return
        name, value = selected
        self.tk.clipboard_clear()
        self.tk.clipboard_append(f"{name}={value}")
        self.status.configure(text=f"Copied pair: {name}=...")

    def export_records(self, output: str) -> None:
        context = self.context_var.get() or None
        distro = self.wsl_distro_var.get().strip() or None
        wsl_path = self.wsl_path_var.get().strip() or None

        content = self.service.export_records(
            output=output,
            include_raw_secrets=self.show_secrets.get(),
            root=self.root_path,
            context=context,
            distro=distro,
            wsl_path=wsl_path,
            scan_depth=int(self.scan_depth_var.get() or 5),
        )

        ext = ".json" if output == "json" else ".csv" if output == "csv" else ".txt"
        path = self.filedialog.asksaveasfilename(
            title=f"Export {output.upper()}",
            defaultextension=ext,
            filetypes=[(f"{output.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"env-inspector-export{ext}",
        )
        if not path:
            return
        Path(path).write_text(content, encoding="utf-8")
        self.status.configure(text=f"Exported {output.upper()} to {path}")

    def restore_backup(self) -> None:
        backups = self.service.list_backups()
        if not backups:
            self.messagebox.showinfo("Env Inspector", "No backups found.")
            return

        dialog = BackupPickerDialog(self.tk, backups)
        self.tk.wait_window(dialog.win)
        if not dialog.result:
            return

        result = self.service.restore_backup(backup=dialog.result, scope_roots=[self.root_path])
        if result.get("success"):
            self.status.configure(text=f"Restored backup ({result.get('operation_id')})")
            self.refresh_data()
        else:
            self.messagebox.showerror("Env Inspector", f"Restore failed: {result.get('error_message')}")

    def run(self) -> None:
        self.tk.mainloop()


def _legacy_print_secrets(root: Path) -> int:
    svc = EnvInspectorService()
    rows = svc.list_records(root=root, include_raw_secrets=True)
    for row in rows:
        if row.get("is_secret"):
            print(f"{row.get('source_type')}:{row.get('source_id')}\t{row.get('name')}")
    return 0


def _parse_gui_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Env Inspector GUI")
    parser.add_argument("--root", default=os.getcwd(), help="Root path to scan for .env files")
    parser.add_argument("--print-secrets", action="store_true", help="Print detected secret keys and exit")
    return parser.parse_args(argv)


def main() -> int:
    argv = sys.argv[1:]

    if argv and (argv[0] in CLI_COMMANDS or argv[0] in {"-h", "--help"}):
        return run_cli(argv)

    args = _parse_gui_args(argv)
    try:
        root = resolve_scan_root(args.root)
    except PathPolicyError as exc:
        print(f"Invalid --root: {exc}", file=sys.stderr)
        return 2

    if args.print_secrets:
        return _legacy_print_secrets(root)

    app = EnvInspectorApp(root)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
