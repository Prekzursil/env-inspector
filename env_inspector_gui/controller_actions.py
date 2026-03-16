from __future__ import absolute_import, division

from pathlib import Path
from typing import Any

from env_inspector_core.models import EnvRecord

from .dialogs import BackupPickerDialog
from .path_actions import open_source_path
from .secret_policy import resolve_copy_payload, resolve_load_value

APP_NAME = "Env Inspector"
MSG_SELECT_ROW_FIRST = "Select a row first."
COPY_PROMPT_TITLE = "Confirm Sensitive Value"


class EnvInspectorControllerActionsMixin:
    tk: Any
    messagebox: Any
    filedialog: Any
    service: Any
    show_secrets: Any
    key_text: Any
    value_text: Any
    context_var: Any
    wsl_distro_var: Any
    wsl_path_var: Any
    scan_depth_var: Any
    root_path: Path

    def _selected_row(self) -> Any:
        raise NotImplementedError

    def _set_status(self, text: str) -> None:
        raise NotImplementedError

    def _update_effective(self, key: str) -> None:
        raise NotImplementedError

    def refresh_data(self) -> None:
        raise NotImplementedError

    def load_selected(self) -> None:
        row = self._selected_row()
        if not row:
            self._show_select_row_required()
            return

        rec = row.record
        self.key_text.set(rec.name)

        loaded, raw = resolve_load_value(
            rec,
            show_secrets=bool(self.show_secrets.get()),
            confirm_raw=lambda: self._confirm_hidden_secret(
                "This value appears to be a secret and is hidden. Load raw value into the editor?"
            ),
        )

        if loaded is not None:
            self.value_text.set(loaded)
            if rec.is_secret and not raw:
                self._set_status(f"Loaded masked value for: {rec.name}")
            else:
                self._set_status(f"Loaded value for: {rec.name}")
        else:
            self._set_status(f"Skipped loading hidden secret for: {rec.name}")

        self._update_effective(rec.name)

    def _selected_record(self) -> EnvRecord | None:
        row = self._selected_row()
        return row.record if row else None

    def copy_selected_name(self) -> None:
        rec = self._selected_record()
        if rec is None:
            self._show_select_row_required()
            return

        self.tk.clipboard_clear()
        self.tk.clipboard_append(rec.name)
        self._set_status(f"Copied name: {rec.name}")

    def copy_selected_value(self) -> None:
        rec = self._selected_record()
        if rec is None:
            self._show_select_row_required()
            return

        payload, raw = resolve_copy_payload(
            rec,
            show_secrets=bool(self.show_secrets.get()),
            confirm_raw=lambda: self._confirm_hidden_secret(
                "This value appears to be a secret and is hidden. Copy raw value to clipboard?"
            ),
            as_pair=False,
        )

        self.tk.clipboard_clear()
        self.tk.clipboard_append(payload)
        if rec.is_secret and not raw:
            self._set_status(f"Copied masked value for: {rec.name}")
        else:
            self._set_status(f"Copied value for: {rec.name}")

    def copy_selected_pair(self) -> None:
        rec = self._selected_record()
        if rec is None:
            self._show_select_row_required()
            return

        payload, raw = resolve_copy_payload(
            rec,
            show_secrets=bool(self.show_secrets.get()),
            confirm_raw=lambda: self._confirm_hidden_secret(
                "This value appears to be a secret and is hidden. Copy raw name=value to clipboard?"
            ),
            as_pair=True,
        )

        self.tk.clipboard_clear()
        self.tk.clipboard_append(payload)
        if rec.is_secret and not raw:
            self._set_status(f"Copied masked pair for: {rec.name}")
        else:
            self._set_status(f"Copied pair: {rec.name}=...")

    def copy_selected_source_path(self) -> None:
        rec = self._selected_record()
        if rec is None:
            self._show_select_row_required()
            return

        self.tk.clipboard_clear()
        self.tk.clipboard_append(rec.source_path)
        self._set_status("Copied source path")

    def open_selected_source(self) -> None:
        rec = self._selected_record()
        if rec is None:
            self._show_select_row_required()
            return

        ok, err = open_source_path(rec.source_path)
        if ok:
            self._set_status("Opened source path")
        else:
            self.messagebox.showinfo(APP_NAME, err or "Cannot open this source path")

    def export_records(self, output: str) -> None:
        context = self.context_var.get() or None
        distro = self.wsl_distro_var.get().strip() or None
        wsl_path = self.wsl_path_var.get().strip() or None

        content = self.service.export_records(
            output=output,
            include_raw_secrets=bool(self.show_secrets.get()),
            root=self.root_path,
            context=context,
            distro=distro,
            wsl_path=wsl_path,
            scan_depth=int(self.scan_depth_var.get() or 5),
        )

        ext = {"json": ".json", "csv": ".csv"}.get(output, ".txt")
        path = self.filedialog.asksaveasfilename(
            title=f"Export {output.upper()}",
            defaultextension=ext,
            filetypes=[(f"{output.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"env-inspector-export{ext}",
        )
        if not path:
            return

        Path(path).write_text(content, encoding="utf-8")
        self._set_status(f"Exported {output.upper()} to {path}")

    def restore_backup(self) -> None:
        backups = self.service.list_backups()
        if not backups:
            self.messagebox.showinfo(APP_NAME, "No backups found.")
            return

        dialog = BackupPickerDialog(self.tk, backups)
        self.tk.wait_window(dialog.win)
        if not dialog.result:
            return

        result = self.service.restore_backup(backup=dialog.result, scope_roots=[self.root_path])
        if result.get("success"):
            self._set_status(f"Restored backup ({result.get('operation_id')})")
            self.refresh_data()
        else:
            self.messagebox.showerror(APP_NAME, f"Restore failed: {result.get('error_message')}")

    def _show_select_row_required(self) -> None:
        self.messagebox.showinfo(APP_NAME, MSG_SELECT_ROW_FIRST)

    def _confirm_hidden_secret(self, prompt: str) -> bool:
        return bool(self.messagebox.askyesno(COPY_PROMPT_TITLE, prompt))
