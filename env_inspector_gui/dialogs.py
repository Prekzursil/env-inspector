from __future__ import annotations

from collections.abc import Callable
from typing import Any


class TargetPickerDialog:
    def __init__(self, parent: Any, targets: list[str], selected: list[str] | None = None) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.result: list[str] | None = None
        self._targets = list(targets)
        self._vars: dict[str, tk.BooleanVar] = {}
        self._checks: dict[str, Any] = {}
        selected_set = set(selected or [])

        self.win = tk.Toplevel(parent)
        self.win.title("Select Targets")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.resizable(True, True)
        self.win.geometry("900x620")

        frame = ttk.Frame(self.win, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Choose one or more targets for this operation:").pack(anchor="w", pady=(0, 8))
        self._build_search_row(frame, tk, ttk)
        self._build_preset_row(frame, ttk)

        canvas = tk.Canvas(frame, highlightthickness=0)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)

        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._build_target_checks(body, selected_set, selected is not None, tk, ttk)

        self.selected_count_label = ttk.Label(frame, text="")
        self.selected_count_label.pack(anchor="w", pady=(8, 0))
        self._build_buttons(frame, ttk)

        self.win.bind("<Escape>", lambda _e: self._cancel())

        self._apply_filter()
        self._update_selected_count()
        self.search_entry.focus_set()

    def _build_search_row(self, frame: Any, tk: Any, ttk: Any) -> None:
        search_row = ttk.Frame(frame)
        search_row.pack(fill="x", pady=(0, 8))
        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar(value="")
        self.search_entry = ttk.Entry(search_row, textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.search_entry.bind("<KeyRelease>", lambda _e: self._apply_filter())

    def _build_preset_row(self, frame: Any, ttk: Any) -> None:
        preset_row = ttk.Frame(frame)
        preset_row.pack(fill="x", pady=(0, 8))
        ttk.Button(preset_row, text="Select All", command=self._select_all).pack(side="left", padx=(0, 6))
        ttk.Button(preset_row, text="Select None", command=self._select_none).pack(side="left", padx=(0, 6))
        ttk.Button(preset_row, text="Select Dotenv Only", command=self._select_dotenv).pack(side="left", padx=(0, 6))
        ttk.Button(preset_row, text="Select Windows Only", command=self._select_windows).pack(side="left", padx=(0, 6))
        ttk.Button(preset_row, text="Select WSL Only", command=self._select_wsl).pack(side="left", padx=(0, 6))

    def _build_target_checks(self, body: Any, selected_set: set[str], has_selected: bool, tk: Any, ttk: Any) -> None:
        for target in self._targets:
            default = target in selected_set if has_selected else True
            var = tk.BooleanVar(value=default)
            var.trace_add("write", lambda *_args: self._update_selected_count())
            check = ttk.Checkbutton(body, text=target, variable=var)
            check.pack(anchor="w")
            self._vars[target] = var
            self._checks[target] = check

    def _build_buttons(self, frame: Any, ttk: Any) -> None:
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Apply", command=self._apply).pack(side="right")

    def _apply_filter(self) -> None:
        text = self.search_var.get().strip().lower()
        for target, check in self._checks.items():
            visible = not text or text in target.lower()
            if visible:
                if not check.winfo_manager():
                    check.pack(anchor="w")
            else:
                if check.winfo_manager():
                    check.pack_forget()

    def _set_by_predicate(self, predicate: Callable[[str], bool]) -> None:
        for target, var in self._vars.items():
            var.set(predicate(target))
        self._update_selected_count()

    def _select_all(self) -> None:
        self._set_by_predicate(lambda _target: True)

    def _select_none(self) -> None:
        self._set_by_predicate(lambda _target: False)

    def _select_dotenv(self) -> None:
        self._set_by_predicate(lambda target: target.startswith("dotenv:") or target.startswith("wsl_dotenv:"))

    def _select_windows(self) -> None:
        self._set_by_predicate(lambda target: target.startswith("windows:") or target.startswith("powershell:"))

    def _select_wsl(self) -> None:
        self._set_by_predicate(lambda target: target.startswith("wsl:") or target.startswith("wsl_dotenv:"))

    def _update_selected_count(self) -> None:
        count = sum(1 for var in self._vars.values() if var.get())
        self.selected_count_label.configure(text=f"{count} selected")

    def _apply(self) -> None:
        self.result = [name for name, var in self._vars.items() if var.get()]
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
    def __init__(
        self,
        parent: Any,
        *,
        action: str,
        previews: list[dict[str, Any]],
        preview_only: bool = False,
    ) -> None:
        import tkinter as tk
        from tkinter import font as tkfont
        from tkinter import scrolledtext, ttk

        self.confirmed = False

        self.win = tk.Toplevel(parent)
        self.win.title(f"Preview {action.title()} Changes")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.geometry("1100x760")

        frame = ttk.Frame(self.win, padding=10)
        frame.pack(fill="both", expand=True)

        notebook = ttk.Notebook(frame)
        notebook.pack(fill="both", expand=True)

        mono = tkfont.nametofont("TkFixedFont")
        self._build_preview_tabs(notebook, previews, mono, ttk, scrolledtext)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        self._build_buttons(btns, preview_only, ttk)

        self.win.bind("<Escape>", lambda _e: self._cancel())

    def _build_preview_tabs(self, notebook: Any, previews: list[dict[str, Any]], mono: Any, ttk: Any, scrolledtext: Any) -> None:
        for idx, preview in enumerate(previews):
            self._build_preview_tab(notebook, idx, preview, mono, ttk, scrolledtext)

    def _build_preview_tab(
        self,
        notebook: Any,
        idx: int,
        preview: dict[str, Any],
        mono: Any,
        ttk: Any,
        scrolledtext: Any,
    ) -> None:
        tab = ttk.Frame(notebook, padding=8)
        target = str(preview.get("target", f"target-{idx + 1}"))
        notebook.add(tab, text=f"{idx + 1}. {target}")
        self._build_summary(tab, preview, target, ttk)

        txt = scrolledtext.ScrolledText(tab, wrap="none", font=mono)
        txt.pack(fill="both", expand=True)
        txt.tag_configure("diff_add", foreground="#1f7a1f")
        txt.tag_configure("diff_remove", foreground="#9b1c1c")
        txt.tag_configure("diff_hunk", foreground="#005a9c")
        self._render_diff_text(txt, str(preview.get("diff_preview") or "(no textual diff)"))
        txt.configure(state="disabled")

    def _build_summary(self, tab: Any, preview: dict[str, Any], target: str, ttk: Any) -> None:
        summary = ttk.Frame(tab)
        summary.pack(fill="x", pady=(0, 6))
        ttk.Label(summary, text=f"Target: {target}").pack(anchor="w")
        ttk.Label(summary, text=f"Success: {preview.get('success')}").pack(anchor="w")
        error_message = preview.get("error_message")
        if error_message:
            ttk.Label(summary, text=f"Error: {error_message}").pack(anchor="w")

    def _render_diff_text(self, widget: Any, diff: str) -> None:
        for line in diff.splitlines():
            tag = self._diff_tag(line)
            if tag is None:
                widget.insert("end", line + "\n")
            else:
                widget.insert("end", line + "\n", (tag,))

    def _diff_tag(self, line: str) -> str | None:
        if line.startswith("@@"):
            return "diff_hunk"
        if line.startswith("+") and not line.startswith("+++"):
            return "diff_add"
        if line.startswith("-") and not line.startswith("---"):
            return "diff_remove"
        return None

    def _build_buttons(self, btns: Any, preview_only: bool, ttk: Any) -> None:
        if preview_only:
            ttk.Button(btns, text="Close", command=self._cancel).pack(side="right")
            return
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Apply Changes", command=self._apply).pack(side="right")

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
