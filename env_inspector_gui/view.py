"""View module."""

from typing import Any, Dict, List, Tuple


class EnvInspectorView:
    """Tkinter-based GUI view for the environment inspector."""

    def __init__(self, tkmod: Any, ttk: Any, controller: Any) -> None:
        self.tkmod = tkmod
        self.ttk = ttk
        self.controller = controller

        self.tk = controller.tk

        self.root_label: Any = None
        self.filter_entry: Any = None
        self.details_value_text: Any = None
        self.details_value_scroll_x: Any = None
        self.details_vars: Dict[str, Any] = {}

        self.context_combo: Any = None
        self.wsl_distro_combo: Any = None
        self.wsl_path_entry: Any = None
        self.wsl_depth_spinbox: Any = None
        self.wsl_scan_button: Any = None

        self.key_entry: Any = None
        self.value_entry: Any = None

        self.refresh_button: Any = None
        self.load_button: Any = None
        self.choose_targets_button: Any = None
        self.set_button: Any = None
        self.remove_button: Any = None

        self.tree: Any = None
        self.status: Any = None
        self.progress: Any = None

        self.copy_name_button: Any = None
        self.copy_value_button: Any = None
        self.copy_pair_button: Any = None
        self.copy_source_path_button: Any = None
        self.detail_open_button: Any = None

        self._build_ui()

    def _build_ui(self) -> None:
        """Build ui."""
        self._build_top_controls()
        self._build_scan_section()
        self._build_mutation_section()
        detail_wrap = self._build_mid_section()
        self._build_details_section(detail_wrap)
        self._build_bottom_bar()

    def _build_top_controls(self) -> None:
        """Build top controls."""
        ttk = self.ttk
        top = ttk.Frame(self.tk, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Root folder:").grid(row=0, column=0, sticky="w")
        self.root_label = ttk.Label(top, text=str(self.controller.root_path))
        self.root_label.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(
            top, text="Choose Folder", command=self.controller.choose_folder
        ).grid(row=0, column=2, padx=4)
        self.refresh_button = ttk.Button(
            top, text="Refresh", command=self.controller.refresh_data
        )
        self.refresh_button.grid(row=0, column=3, padx=4)

        ttk.Label(top, text="Context:").grid(row=0, column=4, sticky="e", padx=(16, 4))
        self.context_combo = ttk.Combobox(
            top, textvariable=self.controller.context_var, state="readonly", width=28
        )
        self.context_combo.grid(row=0, column=5, sticky="w")
        self.context_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self.controller.on_context_selected()
        )

        ttk.Checkbutton(
            top,
            text="Show secrets",
            variable=self.controller.show_secrets,
            command=self.controller.on_filter_changed,
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            top,
            text="Only secrets",
            variable=self.controller.only_secrets,
            command=self.controller.on_filter_changed,
        ).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Label(top, text="Filter:").grid(row=1, column=2, sticky="e", pady=(8, 0))
        self.filter_entry = ttk.Entry(top, textvariable=self.controller.filter_text)
        self.filter_entry.grid(
            row=1, column=3, columnspan=3, sticky="ew", padx=4, pady=(8, 0)
        )
        self.filter_entry.bind(
            "<KeyRelease>", lambda _e: self.controller.on_filter_changed()
        )
        self.filter_entry.bind(
            "<Escape>", lambda _e: self.controller.on_filter_escape()
        )
        top.columnconfigure(3, weight=1)

    def _build_scan_section(self) -> None:
        """Build scan section."""
        ttk = self.ttk
        scan = ttk.LabelFrame(self.tk, text="WSL Dotenv Scan", padding=10)
        scan.pack(fill="x", padx=10, pady=(0, 8))

        ttk.Label(scan, text="WSL distro:").grid(row=0, column=0, sticky="w")
        self.wsl_distro_combo = ttk.Combobox(
            scan,
            textvariable=self.controller.wsl_distro_var,
            state="readonly",
            width=28,
        )
        self.wsl_distro_combo.grid(row=0, column=1, sticky="w", padx=(4, 10))

        ttk.Label(scan, text="WSL path:").grid(row=0, column=2, sticky="w")
        self.wsl_path_entry = ttk.Entry(
            scan, textvariable=self.controller.wsl_path_var, width=46
        )
        self.wsl_path_entry.grid(row=0, column=3, sticky="w", padx=(4, 10))

        ttk.Label(scan, text="Depth:").grid(row=0, column=4, sticky="w")
        self.wsl_depth_spinbox = ttk.Spinbox(
            scan, from_=1, to=20, textvariable=self.controller.scan_depth_var, width=6
        )
        self.wsl_depth_spinbox.grid(row=0, column=5, sticky="w", padx=(4, 10))

        self.wsl_scan_button = ttk.Button(
            scan, text="Apply WSL Scan", command=self.controller.refresh_data
        )
        self.wsl_scan_button.grid(row=0, column=6, sticky="w")

    def _build_mutation_section(self) -> None:
        """Build mutation section."""
        ttk = self.ttk
        mutate = ttk.LabelFrame(self.tk, text="Set / Remove", padding=10)
        mutate.pack(fill="x", padx=10, pady=(0, 8))

        ttk.Label(mutate, text="Key:").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(
            mutate, textvariable=self.controller.key_text, width=34
        )
        self.key_entry.grid(row=0, column=1, sticky="w", padx=(4, 10))

        ttk.Label(mutate, text="Value:").grid(row=0, column=2, sticky="w")
        self.value_entry = ttk.Entry(
            mutate, textvariable=self.controller.value_text, width=52
        )
        self.value_entry.grid(row=0, column=3, sticky="w", padx=(4, 10))

        self.load_button = ttk.Button(
            mutate, text="Load Selected", command=self.controller.load_selected
        )
        self.load_button.grid(row=0, column=4, padx=(0, 6))
        self.choose_targets_button = ttk.Button(
            mutate, text="Choose Targets", command=self.controller.choose_targets
        )
        self.choose_targets_button.grid(row=0, column=5, padx=(0, 6))
        self.set_button = ttk.Button(
            mutate, text="Set", command=lambda: self.controller.run_operation("set")
        )
        self.set_button.grid(row=0, column=6, padx=(0, 6))
        self.remove_button = ttk.Button(
            mutate,
            text="Remove",
            command=lambda: self.controller.run_operation("remove"),
        )
        self.remove_button.grid(row=0, column=7)

        ttk.Label(mutate, textvariable=self.controller.targets_summary_var).grid(
            row=1, column=0, columnspan=8, sticky="w", pady=(8, 0)
        )
        ttk.Label(mutate, textvariable=self.controller.effective_value_var).grid(
            row=2, column=0, columnspan=8, sticky="w", pady=(6, 0)
        )

    def _build_mid_section(self) -> Any:
        """Build mid section."""
        ttk = self.ttk
        mid = ttk.PanedWindow(self.tk, orient="horizontal")
        mid.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        table_wrap = ttk.Frame(mid)
        detail_wrap = ttk.LabelFrame(mid, text="Details", padding=10)
        mid.add(table_wrap, weight=5)
        mid.add(detail_wrap, weight=3)

        self._build_table(table_wrap)
        return detail_wrap

    def _build_table(self, table_wrap: Any) -> None:
        """Build table."""
        ttk = self.ttk
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
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings")
        for col, title, width, anchor in [
            ("context", "Context", 140, "w"),
            ("source", "Source", 160, "w"),
            ("name", "Name", 220, "w"),
            ("value", "Value", 360, "w"),
            ("secret", "Secret", 70, "center"),
            ("persistent", "Persistent", 90, "center"),
            ("mutable", "Mutable", 80, "center"),
            ("source_path", "Source Path", 320, "w"),
        ]:
            self.tree.heading(
                col, text=title, command=lambda c=col: self.controller.on_sort_column(c)
            )
            self.tree.column(col, width=width, anchor=anchor)

        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(
            table_wrap, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)
        self.tree.bind(
            "<<TreeviewSelect>>", lambda _e: self.controller.on_tree_selected()
        )

    def _create_details_var_map(self) -> Dict[str, Any]:
        """Create details var map."""
        self.details_vars = {
            "name": self.tkmod.StringVar(value=""),
            "context": self.tkmod.StringVar(value=""),
            "source": self.tkmod.StringVar(value=""),
            "source_path": self.tkmod.StringVar(value=""),
            "secret": self.tkmod.StringVar(value=""),
            "persistent": self.tkmod.StringVar(value=""),
            "mutable": self.tkmod.StringVar(value=""),
            "writable": self.tkmod.StringVar(value=""),
            "requires_privilege": self.tkmod.StringVar(value=""),
            "precedence_rank": self.tkmod.StringVar(value=""),
        }
        return self.details_vars

    def _build_details_value_widgets(self, detail_wrap: Any) -> None:
        """Build details value widgets."""
        ttk = self.ttk

        ttk.Label(detail_wrap, text="Name:").grid(row=0, column=0, sticky="nw")
        ttk.Label(detail_wrap, textvariable=self.details_vars["name"]).grid(
            row=0, column=1, sticky="nw", padx=(6, 0)
        )

        ttk.Label(detail_wrap, text="Value:").grid(
            row=1, column=0, sticky="nw", pady=(6, 0)
        )
        self.details_value_text = self.tkmod.Text(
            detail_wrap, height=4, wrap="none", font="TkFixedFont"
        )
        self.details_value_text.grid(
            row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0)
        )
        self.details_value_text.configure(state="disabled")
        self.details_value_scroll_x = ttk.Scrollbar(
            detail_wrap, orient="horizontal", command=self.details_value_text.xview
        )
        self.details_value_text.configure(
            xscrollcommand=self.details_value_scroll_x.set
        )
        self.details_value_scroll_x.grid(row=2, column=1, sticky="ew", padx=(6, 0))

    def _build_details_metadata_rows(self, detail_wrap: Any, *, start_row: int) -> int:
        """Build details metadata rows."""
        ttk = self.ttk
        meta_fields = (
            ("Context", "context"),
            ("Source", "source"),
            ("Source Path", "source_path"),
            ("Secret", "secret"),
            ("Persistent", "persistent"),
            ("Mutable", "mutable"),
            ("Writable", "writable"),
            ("Requires Privilege", "requires_privilege"),
            ("Precedence Rank", "precedence_rank"),
        )
        for idx, (label, key) in enumerate(meta_fields):
            row = start_row + idx
            ttk.Label(detail_wrap, text=f"{label}:").grid(
                row=row, column=0, sticky="nw", pady=(4, 0)
            )
            ttk.Label(detail_wrap, textvariable=self.details_vars[key]).grid(
                row=row, column=1, sticky="nw", padx=(6, 0), pady=(4, 0)
            )
        return start_row + len(meta_fields)

    def _build_details_action_rows(self, detail_wrap: Any, *, start_row: int) -> None:
        """Build details action rows."""
        ttk = self.ttk
        btn_row = ttk.Frame(detail_wrap)
        btn_row.grid(row=start_row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.copy_name_button = ttk.Button(
            btn_row, text="Copy Name", command=self.controller.copy_selected_name
        )
        self.copy_name_button.pack(side="left", padx=(0, 6))
        self.copy_value_button = ttk.Button(
            btn_row, text="Copy Value", command=self.controller.copy_selected_value
        )
        self.copy_value_button.pack(side="left", padx=(0, 6))
        self.copy_pair_button = ttk.Button(
            btn_row, text="Copy Name=Value", command=self.controller.copy_selected_pair
        )
        self.copy_pair_button.pack(side="left", padx=(0, 6))

        btn_row_2 = ttk.Frame(detail_wrap)
        btn_row_2.grid(
            row=start_row + 1, column=0, columnspan=2, sticky="ew", pady=(6, 0)
        )
        self.copy_source_path_button = ttk.Button(
            btn_row_2,
            text="Copy Source Path",
            command=self.controller.copy_selected_source_path,
        )
        self.copy_source_path_button.pack(side="left", padx=(0, 6))
        self.detail_open_button = ttk.Button(
            btn_row_2, text="Open Source", command=self.controller.open_selected_source
        )
        self.detail_open_button.pack(side="left")

    def _build_details_section(self, detail_wrap: Any) -> None:
        """Build details section."""
        self._create_details_var_map()
        self._build_details_value_widgets(detail_wrap)
        next_row = self._build_details_metadata_rows(detail_wrap, start_row=3)
        self._build_details_action_rows(detail_wrap, start_row=next_row)
        detail_wrap.columnconfigure(1, weight=1)
        detail_wrap.rowconfigure(1, weight=1)

    def _build_bottom_bar(self) -> None:
        """Build bottom bar."""
        ttk = self.ttk
        bottom = ttk.Frame(self.tk, padding=10)
        bottom.pack(fill="x")

        ttk.Button(
            bottom,
            text="Export JSON",
            command=lambda: self.controller.export_records("json"),
        ).pack(side="left", padx=4)
        ttk.Button(
            bottom,
            text="Export CSV",
            command=lambda: self.controller.export_records("csv"),
        ).pack(side="left", padx=4)
        ttk.Button(
            bottom, text="Restore Backup", command=self.controller.restore_backup
        ).pack(side="left", padx=(20, 4))

        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=120)
        self.progress.pack(side="right", padx=(8, 0))

        self.status = ttk.Label(bottom, text="")
        self.status.pack(side="right")

    def set_context_values(self, contexts: List[str]) -> None:
        """Set context values."""
        self.context_combo.configure(values=contexts)

    def set_wsl_distros(self, distros: List[str], *, enabled: bool) -> None:
        """Set wsl distros."""
        self.wsl_distro_combo.configure(values=distros)
        self.wsl_distro_combo.configure(state=("readonly" if enabled else "disabled"))
        state = "normal" if enabled else "disabled"
        for widget in (
            self.wsl_path_entry,
            self.wsl_depth_spinbox,
            self.wsl_scan_button,
        ):
            widget.configure(state=state)

    def set_root_label(self, text: str) -> None:
        """Set root label."""
        self.root_label.configure(text=text)

    def set_status(self, text: str) -> None:
        """Set status."""
        self.status.configure(text=text)

    def set_refresh_busy(self, busy: bool) -> None:
        """Set refresh busy."""
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def set_mutation_actions_enabled(self, enabled: bool) -> None:
        """Set mutation actions enabled."""
        state = "normal" if enabled else "disabled"
        for widget in (
            self.refresh_button,
            self.load_button,
            self.choose_targets_button,
            self.set_button,
            self.remove_button,
        ):
            widget.configure(state=state)

    def clear_table(self) -> None:
        """Clear table."""
        for item in self.tree.get_children():
            self.tree.delete(item)

    def insert_table_row(self, values: Tuple[Any, ...], *, striped: bool) -> str:
        """Insert table row."""
        tag = "row_even" if striped else "row_odd"
        return str(self.tree.insert("", "end", values=values, tags=(tag,)))

    def configure_row_styles(self) -> None:
        """Configure row styles."""
        self.tree.tag_configure("row_even", background="#f8f8f8")
        self.tree.tag_configure("row_odd", background="#ffffff")

    def update_details_value(self, text: str) -> None:
        """Update details value."""
        self.details_value_text.configure(state="normal")
        self.details_value_text.delete("1.0", "end")
        self.details_value_text.insert("1.0", text)
        self.details_value_text.configure(state="disabled")

    def set_details_enabled(self, enabled: bool) -> None:
        """Set details enabled."""
        state = "normal" if enabled else "disabled"
        for widget in (
            self.copy_name_button,
            self.copy_value_button,
            self.copy_pair_button,
            self.copy_source_path_button,
            self.detail_open_button,
        ):
            widget.configure(state=state)

    def focus_filter(self) -> None:
        """Focus filter."""
        self.filter_entry.focus_set()
        self.filter_entry.selection_range(0, "end")
