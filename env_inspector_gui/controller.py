from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

from env_inspector_core.models import EnvRecord
from env_inspector_core.path_policy import PathPolicyError, resolve_scan_root
from env_inspector_core.service import EnvInspectorService

from .controller_actions import APP_NAME, EnvInspectorControllerActionsMixin
from .dialogs import DiffPreviewDialog, DotenvTargetDialog, TargetPickerDialog
from .models import DisplayedRow, PersistedUiState, SortState
from .path_actions import is_openable_local_path
from .secret_policy import resolve_copy_payload
from .state_store import load_ui_state, sanitize_loaded_state, save_ui_state
from .table_logic import build_display_rows, sort_display_rows, toggle_sort
from .view import EnvInspectorView


class EnvInspectorController(EnvInspectorControllerActionsMixin):
    def __init__(self, root_path: Path) -> None:
        tk, filedialog, messagebox, ttk = self._load_tk_modules()
        self._assign_tk_modules(tk, filedialog, messagebox, ttk)
        self.service = EnvInspectorService()
        self.state_dir = self.service.state_dir

        self._init_root_window(tk)
        self._apply_theme()

        boot_state, fallback_root = self._load_boot_state(root_path)
        self._initialize_runtime_state(tk, boot_state, fallback_root)
        self.sort_state = SortState(column=boot_state.sort_column, descending=boot_state.sort_descending)
        self._initialize_view(tk, ttk, boot_state)
        self._bind_shortcuts()
        self.tk.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh_data()
        self.tk.after_idle(self.view.focus_filter)

    def _load_tk_modules(self):
        try:
            import tkinter as tk
            from tkinter import filedialog, messagebox, ttk
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "Tkinter is not available in this Python installation. Install tkinter/python3-tk and retry."
            ) from exc
        return tk, filedialog, messagebox, ttk

    def _assign_tk_modules(self, tk: Any, filedialog: Any, messagebox: Any, ttk: Any) -> None:
        self.tkmod = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox

    def _init_root_window(self, tk: Any) -> None:
        self.tk = tk.Tk()
        self.tk.title(f"{APP_NAME} (Core + GUI)")

    def _load_boot_state(self, root_path: Path) -> tuple[PersistedUiState, Path]:
        loaded = load_ui_state(self.state_dir)
        fallback_root = resolve_scan_root(root_path)
        boot_state = sanitize_loaded_state(
            loaded,
            available_contexts=self.service.list_contexts(),
            available_targets=[],
            fallback_root=fallback_root,
        )
        return boot_state, fallback_root

    def _initialize_runtime_state(self, tk: Any, boot_state: PersistedUiState, fallback_root: Path) -> None:
        self.root_path = self._resolve_root_path(boot_state, fallback_root)
        self.records_raw: list[EnvRecord] = []
        self.displayed_rows: list[DisplayedRow] = []
        self.rows_by_item: dict[str, DisplayedRow] = {}
        self.selected_targets = list(boot_state.selected_targets)
        self.last_refresh_at: datetime | None = None

        self.filter_text = tk.StringVar(value=boot_state.filter_text)
        self.show_secrets = tk.BooleanVar(value=boot_state.show_secrets)
        self.only_secrets = tk.BooleanVar(value=boot_state.only_secrets)
        self.context_var = tk.StringVar(value=boot_state.context)
        self.wsl_distro_var = tk.StringVar(value=boot_state.wsl_distro)
        self.wsl_path_var = tk.StringVar(value=boot_state.wsl_path)
        self.scan_depth_var = tk.IntVar(value=boot_state.scan_depth)
        self.key_text = tk.StringVar(value="")
        self.value_text = tk.StringVar(value="")
        self.effective_value_var = tk.StringVar(value="Effective: (select key)")
        self.targets_summary_var = tk.StringVar(value="Targets: (none selected)")

    def _resolve_root_path(self, boot_state: PersistedUiState, fallback_root: Path) -> Path:
        try:
            return resolve_scan_root(boot_state.root_path or fallback_root)
        except PathPolicyError:
            return fallback_root

    def _initialize_view(self, tk: Any, ttk: Any, boot_state: PersistedUiState) -> None:
        self.view = EnvInspectorView(tk, ttk, self)
        self.view.set_root_label(str(self.root_path))
        self.view.configure_row_styles()
        self.tk.geometry(boot_state.window_geometry or "1480x860")

    def _apply_theme(self) -> None:
        style = self.ttk.Style(self.tk)
        themes = set(style.theme_names())

        if os.name == "nt":
            for preferred in ("vista", "xpnative"):
                if preferred in themes:
                    style.theme_use(preferred)
                    break
            else:
                if "clam" in themes:
                    style.theme_use("clam")
        else:
            if "clam" in themes:
                style.theme_use("clam")

        style.configure("Treeview", rowheight=24)

    def _bind_shortcuts(self) -> None:
        self.tk.bind("<Control-f>", self._on_ctrl_f)
        self.tk.bind("<F5>", self._on_f5)
        self.tk.bind("<Control-c>", self._on_ctrl_c)

    def _on_ctrl_f(self, _event: Any) -> str:
        self.view.focus_filter()
        return "break"

    def _on_f5(self, _event: Any) -> str:
        self.refresh_data()
        return "break"

    def _on_ctrl_c(self, _event: Any) -> str | None:
        focused = self.tk.focus_get()
        if focused == self.view.tree:
            self.copy_selected_value()
            return "break"
        return None

    def on_close(self) -> None:
        self._persist_state()
        self.tk.destroy()

    def _build_state(self) -> PersistedUiState:
        return PersistedUiState(
            window_geometry=self.tk.geometry(),
            root_path=str(self.root_path),
            context=self.context_var.get(),
            show_secrets=bool(self.show_secrets.get()),
            only_secrets=bool(self.only_secrets.get()),
            filter_text=self.filter_text.get(),
            selected_targets=list(self.selected_targets),
            sort_column=self.sort_state.column,
            sort_descending=self.sort_state.descending,
            wsl_distro=self.wsl_distro_var.get(),
            wsl_path=self.wsl_path_var.get(),
            scan_depth=int(self.scan_depth_var.get() or 5),
        )

    def _persist_state(self) -> None:
        save_ui_state(self.state_dir, self._build_state())

    def run(self) -> None:
        self.tk.mainloop()

    def on_context_selected(self) -> None:
        self.refresh_data()

    def on_filter_changed(self) -> None:
        self._render_table()
        key = self.key_text.get().strip()
        if key:
            self._update_effective(key)
        self._persist_state()

    def on_filter_escape(self) -> None:
        if self.filter_text.get():
            self.filter_text.set("")
            self.on_filter_changed()

    def on_sort_column(self, column: str) -> None:
        self.sort_state = toggle_sort(self.sort_state, column)
        self._render_table()
        self._persist_state()

    def choose_folder(self) -> None:
        selected = self.filedialog.askdirectory(initialdir=str(self.root_path))
        if not selected:
            return
        self.root_path = resolve_scan_root(selected)
        self.view.set_root_label(str(self.root_path))
        self.refresh_data()

    def _selected_row(self) -> DisplayedRow | None:
        selected = self.view.tree.selection()
        if not selected:
            return None
        return self.rows_by_item.get(str(selected[0]))

    def _on_row_selected_update_details(self, row: DisplayedRow | None) -> None:
        if row is None:
            self._clear_details()
            return

        rec = row.record
        self._set_detail_pairs(
            (
                ("name", rec.name),
                ("context", rec.context),
                ("source", rec.source_type),
                ("source_path", rec.source_path),
                ("secret", "yes" if rec.is_secret else "no"),
                ("persistent", "yes" if rec.is_persistent else "no"),
                ("mutable", "yes" if rec.is_mutable else "no"),
                ("writable", "yes" if rec.writable else "no"),
                ("requires_privilege", "yes" if rec.requires_privilege else "no"),
                ("precedence_rank", str(rec.precedence_rank)),
            )
        )
        self.view.update_details_value(row.visible_value)
        self.view.set_details_enabled(True)
        self.view.detail_open_button.configure(state=("normal" if is_openable_local_path(rec.source_path) else "disabled"))

    def _clear_details(self) -> None:
        self._set_detail_values(dict.fromkeys(self.view.details_vars, ""))
        self.view.update_details_value("")
        self.view.set_details_enabled(False)

    def _set_detail_values(self, values: dict[str, str]) -> None:
        for key, value in values.items():
            if key in self.view.details_vars:
                self.view.details_vars[key].set(value)

    def _set_detail_pairs(self, pairs: tuple[tuple[str, str], ...]) -> None:
        for key, value in pairs:
            if key in self.view.details_vars:
                self.view.details_vars[key].set(value)

    def on_tree_selected(self) -> None:
        row = self._selected_row()
        if row:
            self.key_text.set(row.record.name)
            self._update_effective(row.record.name)
        self._on_row_selected_update_details(row)

    def _update_context_values(self) -> None:
        contexts = self.service.list_contexts()
        self.view.set_context_values(contexts)

        if self.context_var.get() not in contexts:
            self.context_var.set(contexts[0] if contexts else self.service.runtime_context)

        distros = [c.split(":", 1)[1] for c in contexts if c.startswith("wsl:")]
        if self.wsl_distro_var.get() not in distros:
            self.wsl_distro_var.set(distros[0] if distros else "")
        self.view.set_wsl_distros(distros, enabled=bool(distros))

    def _fetch_records(self) -> None:
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

    def _reconcile_targets(self) -> None:
        available = self.service.available_targets(self.records_raw, context=self.context_var.get())
        if not self.selected_targets:
            self.selected_targets = available
        else:
            self.selected_targets = [target for target in self.selected_targets if target in available]
            if not self.selected_targets:
                self.selected_targets = available

        self.targets_summary_var.set(f"Targets: {len(self.selected_targets)} selected")

    def _render_table(self) -> None:
        self.view.clear_table()
        self.rows_by_item.clear()

        filtered = build_display_rows(
            self.records_raw,
            context=self.context_var.get(),
            query=self.filter_text.get(),
            only_secrets=bool(self.only_secrets.get()),
            show_secrets=bool(self.show_secrets.get()),
        )
        self.displayed_rows = sort_display_rows(filtered, self.sort_state)

        for idx, row in enumerate(self.displayed_rows):
            item = self.view.insert_table_row(
                (
                    row.record.context,
                    row.source_label,
                    row.record.name,
                    row.visible_value,
                    row.secret_text,
                    row.persistent_text,
                    row.mutable_text,
                    row.record.source_path,
                ),
                striped=(idx % 2 == 0),
            )
            self.rows_by_item[item] = row

        self._update_status_line(len(self.displayed_rows), len(self.records_raw))

    def _update_status_line(self, shown: int, total: int) -> None:
        context = self.context_var.get() or self.service.runtime_context
        if self.last_refresh_at is None:
            when = "-"
        else:
            when = self.last_refresh_at.strftime("%H:%M:%S")
        self._set_status(f"Showing {shown} / {total} entries | Context: {context} | Last refresh: {when}")

    def _set_status(self, text: str) -> None:
        view = getattr(self, "view", None)
        if view is not None:
            view.set_status(text)

    def _set_busy(self, busy: bool) -> None:
        view = getattr(self, "view", None)
        if view is not None:
            view.set_mutation_actions_enabled(not busy)
            view.set_refresh_busy(busy)

    def refresh_data(self) -> None:
        self._set_busy(True)
        self._set_status("Refreshing...")

        try:
            self._update_context_values()
            self._fetch_records()
            self._reconcile_targets()
            self.last_refresh_at = datetime.now()
            self._render_table()

            key = self.key_text.get().strip()
            if key:
                self._update_effective(key)
            else:
                self.effective_value_var.set("Effective: (select key)")

            if getattr(self, "view", None) is not None:
                self._on_row_selected_update_details(self._selected_row())
            if getattr(self, "tk", None) is not None:
                self._persist_state()
        finally:
            self._set_busy(False)

    def _update_effective(self, key: str) -> None:
        context = self.context_var.get() or self.service.runtime_context
        rec = self.service.resolve_effective(key, context, self.records_raw)
        if rec is None:
            self.effective_value_var.set("Effective: (not found)")
            return

        row_value, _ = resolve_copy_payload(
            rec,
            show_secrets=bool(self.show_secrets.get()),
            confirm_raw=lambda: False,
            as_pair=False,
        )
        self.effective_value_var.set(f"Effective ({context}): {key}={row_value} from {rec.source_type}")

    def choose_targets(self) -> None:
        available = self.service.available_targets(self.records_raw, context=self.context_var.get())
        if not available:
            self.messagebox.showinfo(APP_NAME, "No writable targets found in current context.")
            return

        dialog = TargetPickerDialog(self.tk, targets=available, selected=self.selected_targets)
        self.tk.wait_window(dialog.win)
        if dialog.result is None:
            return
        if not dialog.result:
            self.messagebox.showinfo(APP_NAME, "No targets selected.")
            return

        self.selected_targets = dialog.result
        self.targets_summary_var.set(f"Targets: {len(self.selected_targets)} selected")
        self._persist_state()

    def _maybe_choose_dotenv_targets(self, key: str, targets: list[str]) -> list[str] | None:
        dotenv_targets = self._collect_dotenv_targets(targets)
        if len(dotenv_targets) <= 1 or not self._has_multiple_dotenv_matches(key):
            return targets

        dialog = DotenvTargetDialog(self.tk, key, dotenv_targets)
        self.tk.wait_window(dialog.win)
        if dialog.result is None:
            return None

        keep = set(dialog.result)
        return [target for target in targets if target not in dotenv_targets or target in keep]

    def _collect_dotenv_targets(self, targets: list[str]) -> list[str]:
        return [target for target in targets if target.startswith(("dotenv:", "wsl_dotenv:"))]

    def _has_multiple_dotenv_matches(self, key: str) -> bool:
        found = 0
        for rec in self.records_raw:
            if rec.name == key and rec.source_type in {"dotenv", "wsl_dotenv"}:
                found += 1
                if found > 1:
                    return True
        return False

    def _preview_operation(self, action: str, key: str, value: str, targets: list[str]) -> list[dict[str, Any]]:
        if action == "set":
            return self.service.preview_set(key=key, value=value, targets=targets, scope_roots=[self.root_path])
        return self.service.preview_remove(key=key, targets=targets, scope_roots=[self.root_path])

    def _confirm_diff(self, action: str, previews: list[dict[str, Any]], preview_only: bool = False) -> bool:
        dialog = DiffPreviewDialog(self.tk, action=action, previews=previews, preview_only=preview_only)
        self.tk.wait_window(dialog.win)
        return bool(dialog.confirmed)

    def _apply_operation(self, action: str, key: str, value: str, targets: list[str]) -> dict[str, Any]:
        if action == "set":
            return self.service.set_key(key=key, value=value, targets=targets, scope_roots=[self.root_path])
        return self.service.remove_key(key=key, targets=targets, scope_roots=[self.root_path])

    def _run_operation(self, action: str) -> None:
        resolved = self._resolve_operation_inputs()
        if resolved is None:
            return

        key, value, targets = resolved
        previews = self._safe_preview(action, key, value, targets)
        if previews is None:
            return

        if not self._confirm_diff(action, previews, preview_only=False):
            return

        result = self._safe_apply(action, key, value, targets)
        if result is None:
            return

        self._report_operation_result(action, result)
        self.refresh_data()

    def _resolve_operation_inputs(self) -> tuple[str, str, list[str]] | None:
        key = self.key_text.get().strip()
        value = self.value_text.get()
        if not key:
            self.messagebox.showerror(APP_NAME, "Key is required.")
            return None

        targets = list(self.selected_targets)
        if not targets:
            self.choose_targets()
            targets = list(self.selected_targets)
            if not targets:
                return None

        scoped_targets = self._maybe_choose_dotenv_targets(key, targets)
        if scoped_targets is None:
            return None
        return key, value, scoped_targets

    def _safe_preview(self, action: str, key: str, value: str, targets: list[str]) -> list[dict[str, Any]] | None:
        try:
            return self._preview_operation(action, key, value, targets)
        except (RuntimeError, ValueError, OSError, PathPolicyError) as exc:
            self.messagebox.showerror(APP_NAME, f"Failed to compute preview: {exc}")
            return None

    def _safe_apply(self, action: str, key: str, value: str, targets: list[str]) -> dict[str, Any] | None:
        try:
            return self._apply_operation(action, key, value, targets)
        except (RuntimeError, ValueError, OSError, PathPolicyError) as exc:
            self.messagebox.showerror(APP_NAME, f"{action.title()} failed: {exc}")
            return None

    def _report_operation_result(self, action: str, result: dict[str, Any]) -> None:
        if isinstance(result, dict) and "results" in result:
            failed = [x for x in result["results"] if not x.get("success")]
            if failed:
                self.messagebox.showerror(
                    APP_NAME,
                    f"{action.title()} had failures:\n" + "\n".join(x.get("error_message", "") for x in failed),
                )
            else:
                self._set_status(f"{action.title()} succeeded for {len(result['results'])} targets")
            return

        if result.get("success"):
            self._set_status(f"{action.title()} succeeded ({result.get('operation_id')})")
        else:
            self.messagebox.showerror(APP_NAME, f"{action.title()} failed: {result.get('error_message')}")

class EnvInspectorApp:
    def __init__(self, root_path: Path) -> None:
        self._controller = EnvInspectorController(root_path)

    def run(self) -> None:
        self._controller.run()


