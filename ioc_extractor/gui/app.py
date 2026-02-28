"""
app.py - Main application window.

The IOCExtractorApp class builds the GUI, wires up button commands,
and delegates heavy lifting to the backend modules.

Layout philosophy: **Toolbar is the action hub, tabs are for results.**
  - Menu bar (File / Edit / Tools / Help)
  - FlowFrame toolbar with grouped actions (Parse, VT, Jsluice)
  - Toggleable Find/Replace bar (Ctrl+H)
  - PanedWindow: Input area + Output tabs
  - Tabs have minimal Save/Clear controls
  - Status bar at the bottom
"""

from __future__ import annotations

if __package__ in (None, ""):
    import sys
    from pathlib import Path

    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

import os
import re
import secrets
import threading
import time
import webbrowser
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from ioc_extractor.constants import (
    APP_GEOMETRY,
    APP_MIN_HEIGHT,
    APP_MIN_WIDTH,
    APP_TITLE,
    COLORS,
    FONTS,
    INPUT_PLACEHOLDER,
    IOC_REVIEW_HELP,
    JSLUICE_HELP,
    JSLUICE_OPTIONS_HELP,
    KEYBOARD_SHORTCUTS,
    NMAP_HELP,
    NMAP_SCAN_TYPES,
    NMAP_SUDO_SCAN_FLAGS,
    NMAP_TIMING_TEMPLATES,
    SHELL_HELP,
    VT_HELP,
    IOC_PATTERN_GROUPS,
)
from ioc_extractor import ioc_parser
from ioc_extractor import app_settings as settings_store
from ioc_extractor import ioc_history_db
from ioc_extractor.patterns import IOC_PATTERNS
from ioc_extractor import virustotal as vt
from ioc_extractor import keychain
from ioc_extractor.jsluice_handler import JsluiceHandler
from ioc_extractor.jsluice_installer import JsluiceInstaller
from ioc_extractor.nmap_handler import NmapHandler
from ioc_extractor.nmap_installer import NmapInstaller
from ioc_extractor import shell_runner
from ioc_extractor import file_operations
from ioc_extractor.ansi_parser import (
    setup_ansi_tags, insert_ansi_text, insert_nmap_highlighted,
    insert_nmap_structured_highlighted, setup_nmap_tags, strip_ansi,
)
try:
    from .widgets import (
        LoadingOverlay,
        ToastManager,
        create_find_replace_frame,
        create_input_area,
        create_menu_bar,
        create_output_notebook,
        create_primary_toolbar,
        create_status_bar,
        insert_with_links,
    )
except Exception:
    from legacy_tk_app.widgets import (  # type: ignore
        LoadingOverlay,
        ToastManager,
        create_find_replace_frame,
        create_input_area,
        create_menu_bar,
        create_output_notebook,
        create_primary_toolbar,
        create_status_bar,
        insert_with_links,
    )


class IOCExtractorApp(tk.Tk):
    """Top-level application window for IOC Citadel."""

    def __init__(self):
        super().__init__()
        self.settings = settings_store.load_settings()
        self.title(APP_TITLE)
        self.geometry(APP_GEOMETRY)
        self.minsize(APP_MIN_WIDTH, APP_MIN_HEIGHT)
        self.configure(bg=COLORS["bg_primary"])
        self._apply_ui_density_scale()
        self.option_add("*Font", FONTS["body"])

        # --- Backend state ---
        self.vt_api_key: str | None = None
        self.found_iocs: dict = {}
        self._review_tree_source_label = "Parser"
        self.jsluice = JsluiceHandler(
            temp_max_age=self.settings.jsluice_temp_max_age_seconds
        )
        self.nmap = NmapHandler()
        try:
            self.history_db = ioc_history_db.IOCHistoryDB()
            self._history_db_error: str | None = None
        except Exception as exc:
            self.history_db = None
            self._history_db_error = f"{type(exc).__name__}: {exc}"
        self._vt_running = False
        self._nmap_running = False
        self._jsluice_running = False
        self._shell_running = False
        self._parsing_iocs = False
        self._find_replace_visible = False
        self._last_nmap_structured: dict | None = None
        self._nmap_maximized_pane: str | None = None  # "raw" or "struct" or None
        self._history_bottom_maximized_pane: str | None = None  # "entries" / "details" / None
        self._review_tree_nodes_by_ioc: dict[str, list[str]] = {}
        self._review_tree_status: dict[str, str] = {}
        self._history_collection_nodes: dict[str, int] = {}
        self._history_loaded_collection_id: int | None = None
        self._history_last_query: str = ""
        self._api_server = None
        self._api_server_thread: threading.Thread | None = None
        self._api_service = None
        self._api_running = False
        self._api_starting = False
        self._api_start_attempt_started: float = 0.0
        self._api_last_error: str | None = None
        self._api_runtime_url: str = ""
        self._api_runtime_lock = threading.RLock()

        # IOC pattern filter — BooleanVar per pattern, none checked by default.
        # Users pick specific types via the ▾ dropdown, or "Select All" / "Parse All".
        self._selected_patterns: dict[str, tk.BooleanVar] = {
            name: tk.BooleanVar(value=False)
            for name in IOC_PATTERNS
        }

        # --- Build UI ---
        self._build_ui()
        self._apply_runtime_settings()
        self._wire_commands()
        self._build_parse_menu()
        self._apply_default_parse_groups()
        self._bind_keyboard_shortcuts()
        self._populate_initial_text()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ==================================================================
    # UI construction
    # ==================================================================

    def _build_ui(self):
        # Status bar (BOTTOM first — always visible)
        self._status = create_status_bar(self)

        # Menu bar
        self._menus = create_menu_bar(self)

        # Primary toolbar (FlowFrame — wraps responsively)
        self._toolbar = create_primary_toolbar(
            self,
            jsluice_available=self.jsluice.available,
            nmap_available=self.nmap.available,
        )

        # Find/Replace (hidden by default)
        self._fr = create_find_replace_frame(self)

        # Main paned window
        self.main_pane = tk.PanedWindow(
            self, orient=tk.VERTICAL, sashrelief=tk.FLAT,
            sashwidth=4, bg=COLORS["bg_primary"], bd=0,
        )
        self.main_pane.pack(expand=True, fill="both", padx=6, pady=(2, 0))

        # Input area
        self._input = create_input_area(self.main_pane)

        # Output tabs (lean — Save/Clear only)
        self._output = create_output_notebook(self.main_pane)

        # Set up ANSI color tags on shell output widget
        setup_ansi_tags(self._output["shell_output"])
        # Set up ANSI + nmap-specific color tags on nmap widgets
        setup_ansi_tags(self._output["nmap_output"])
        setup_nmap_tags(self._output["nmap_output"])
        setup_nmap_tags(self._output["nmap_structured"])

        # Loading overlay (hidden by default)
        self._loading = LoadingOverlay(self)
        self._toasts = ToastManager(self)

    def _wire_commands(self):
        """Connect all button/entry commands to handler methods."""
        # -- Menu commands --
        fm = self._menus["file_menu"]
        fm.entryconfigure("Open File...", command=self._open_file)
        fm.entryconfigure("Save Input...", command=self._save_input_text)
        fm.entryconfigure("Save Parsed IOCs to History...", command=self._save_current_iocs_to_history)
        fm.entryconfigure("Save VT Output...", command=self._save_vt_output)
        fm.entryconfigure("Save Jsluice Output...", command=self._save_jsluice_output)
        fm.entryconfigure("Save Nmap Output...", command=self._save_nmap_raw)
        fm.entryconfigure("Save Nmap Structured (JSON)...", command=self._save_nmap_json)
        fm.entryconfigure("Exit", command=self._on_close)

        sm = self._menus["save_iocs_menu"]
        sm.entryconfigure("As Group...", command=self._save_iocs_grouped)
        sm.entryconfigure("Per Category...", command=self._save_iocs_individually)
        sm.entryconfigure("As JSON...", command=self._save_iocs_json)
        sm.entryconfigure("As CSV...", command=self._save_iocs_csv)

        em = self._menus["edit_menu"]
        em.entryconfigure("Find & Replace", command=self._toggle_find_replace)
        em.entryconfigure("Clear Input", command=self._clear_input_text)
        em.entryconfigure("Clear IOC Review", command=self._clear_review_output)
        em.entryconfigure("Clear VT Results", command=self._clear_vt_output)
        em.entryconfigure("Clear Jsluice Output", command=self._clear_jsluice_output)
        em.entryconfigure("Clear Nmap Output", command=self._clear_nmap_output)
        em.entryconfigure("Settings...", command=self._show_settings_dialog)
        em.entryconfigure("Clear VT API Key", command=self._clear_vt_api_key)

        tm = self._menus["tools_menu"]
        tm.entryconfigure("Parse IOCs", command=self._parse_iocs)
        tm.entryconfigure("Defang IOCs", command=self._defang_iocs)
        tm.entryconfigure("Refang IOCs", command=self._refang_iocs)
        tm.entryconfigure("Open IOC History", command=self._open_history_tab)
        tm.entryconfigure("Run Jsluice", command=self._run_jsluice)
        tm.entryconfigure("VT Check Selected", command=self._on_vt_check)
        tm.entryconfigure("VT Submit URL(s)", command=self._submit_url_for_analysis)
        tm.entryconfigure("VT Hash Check", command=self._on_vt_check)
        tm.entryconfigure("VT Hash Details", command=self._get_all_hash_details)
        tm.entryconfigure("VT MITRE TTPs", command=self._submit_for_mitre_ttps)
        tm.entryconfigure("VT Behavior Analysis", command=self._get_file_behavior)
        tm.entryconfigure("VT DNS Resolutions", command=self._get_resolutions)
        tm.entryconfigure("VT Communicating Files", command=self._get_communicating_files)
        tm.entryconfigure("Run Nmap", command=self._run_nmap)
        tm.entryconfigure("Start REST API", command=self._start_rest_api)
        tm.entryconfigure("Stop REST API", command=self._stop_rest_api)
        tm.entryconfigure("Copy REST API Token", command=self._copy_rest_api_token)
        tm.entryconfigure("Open REST API Docs", command=self._open_rest_api_docs)

        hm = self._menus["help_menu"]
        hm.entryconfigure("Keyboard Shortcuts", command=self._show_shortcuts)
        hm.entryconfigure("Jsluice Options Help", command=self._show_jsluice_help)
        hm.entryconfigure("About IOC Citadel", command=self._show_about)

        # -- Toolbar buttons (action hub) --
        tb = self._toolbar
        tb["open_btn"].configure(command=self._open_file)
        tb["parse_btn"].configure(command=self._parse_iocs)
        tb["defang_btn"].configure(command=self._defang_iocs)
        tb["refang_btn"].configure(command=self._refang_iocs)
        # VirusTotal SplitButton — main click = VT Check, dropdown = all ops
        tb["vt_btn"].configure(command=self._on_vt_check)
        self._build_vt_menu()
        tb["run_jsluice_btn"].configure(command=self._run_jsluice)
        if "install_jsluice_btn" in tb:
            tb["install_jsluice_btn"].configure(command=self._install_jsluice)
        tb["run_nmap_btn"].configure(command=self._run_nmap)
        if "install_nmap_btn" in tb:
            tb["install_nmap_btn"].configure(command=self._install_nmap)

        # -- Find/Replace --
        fr = self._fr
        fr["find_entry"].bind("<KeyRelease>", lambda _: self._highlight_text())
        fr["find_replace_btn"].configure(command=self._find_and_replace)
        fr["regex_cb"].configure(command=self._highlight_text)
        fr["close_btn"].configure(command=self._toggle_find_replace)

        # -- Input text --
        inp = self._input["text"]
        inp.bind("<FocusIn>", self._on_input_focus_in)
        inp.bind("<FocusOut>", self._on_input_focus_out)

        # -- Tab action bars (Save/Clear + Jsluice config) --
        out = self._output

        # IOC Review — Save dropdown
        save_menu = out["save_menu"]
        indices = out["save_menu_indices"]
        save_menu.entryconfigure(indices["save_group_btn"],
                                 command=self._save_iocs_grouped)
        save_menu.entryconfigure(indices["save_history_btn"],
                                 command=self._save_current_iocs_to_history)
        save_menu.entryconfigure(indices["save_individual_btn"],
                                 command=self._save_iocs_individually)
        save_menu.entryconfigure(indices["save_json_btn"],
                                 command=self._save_iocs_json)
        save_menu.entryconfigure(indices["save_csv_btn"],
                                 command=self._save_iocs_csv)
        out["clear_ioc_btn"].configure(command=self._clear_review_output)
        out["select_all_ioc_rows_btn"].configure(command=self._review_tree_select_all_iocs)
        out["clear_ioc_selection_btn"].configure(command=self._review_tree_clear_selection)
        out["copy_selected_ioc_btn"].configure(command=self._copy_selected_review_iocs)
        out["review_vt_btn"].configure(command=self._on_vt_check)
        out["save_iocs_history_btn"].configure(command=self._save_current_iocs_to_history)
        out["open_history_tab_btn"].configure(command=self._open_history_tab)
        out["review_tree"].bind("<<TreeviewSelect>>", self._on_review_tree_select)
        out["review_tree"].bind("<Double-1>", self._on_review_tree_double_click)

        # VirusTotal tab
        out["save_vt_btn"].configure(command=self._save_vt_output)
        out["clear_vt_btn"].configure(command=self._clear_vt_output)

        # Jsluice tab
        out["help_btn"].configure(command=self._show_jsluice_help)
        out["save_jsluice_btn"].configure(command=self._save_jsluice_output)
        out["clear_jsluice_btn"].configure(command=self._clear_jsluice_output)

        # Shell tab
        out["shell_entry"].bind("<Return>", lambda _: self._run_shell_command())
        out["shell_run_btn"].configure(command=self._run_shell_command)

        # Nmap tab
        out["nmap_tab_run_btn"].configure(command=self._run_nmap)
        out["nmap_stop_btn"].configure(command=self._stop_nmap)
        out["nmap_target"].bind("<Return>", lambda _: self._run_nmap())
        out["clear_nmap_btn"].configure(command=self._clear_nmap_output)
        out["nmap_scan_combo"].bind(
            "<<ComboboxSelected>>", self._on_nmap_scan_type_changed
        )

        # Pane toggle buttons
        out["nmap_toggle_raw_btn"].configure(
            command=lambda: self._toggle_nmap_pane("raw")
        )
        out["nmap_toggle_struct_btn"].configure(
            command=lambda: self._toggle_nmap_pane("struct")
        )

        nmap_save_menu = out["save_nmap_menu"]
        nmap_indices = out["save_nmap_menu_indices"]
        nmap_save_menu.entryconfigure(
            nmap_indices["save_nmap_raw"], command=self._save_nmap_raw
        )
        nmap_save_menu.entryconfigure(
            nmap_indices["save_nmap_json"], command=self._save_nmap_json
        )

        # IOC History tab
        out["history_search_btn"].configure(command=self._search_history)
        out["history_refresh_btn"].configure(command=self._refresh_history_tab)
        out["history_clear_search_btn"].configure(command=self._clear_history_search)
        out["history_save_current_btn"].configure(command=self._save_current_iocs_to_history)
        out["history_load_btn"].configure(command=self._load_selected_history_collection_into_review)
        out["history_copy_btn"].configure(command=self._copy_selected_history_iocs)
        out["history_reload_btn"].configure(command=self._refresh_history_tab)
        out["history_toggle_entries_btn"].configure(
            command=lambda: self._toggle_history_bottom_pane("entries")
        )
        out["history_toggle_details_btn"].configure(
            command=lambda: self._toggle_history_bottom_pane("details")
        )
        out["history_search_entry"].bind("<Return>", lambda _e: self._search_history())
        out["history_collections_tree"].bind(
            "<<TreeviewSelect>>", self._on_history_collection_select
        )
        out["history_collections_tree"].bind(
            "<Double-1>", lambda _e: self._load_selected_history_collection_into_review()
        )

        self._refresh_rest_api_menu_state()

    def _build_parse_menu(self):
        """Populate the Parse IOCs dropdown with grouped checkboxes.

        Default state: nothing checked.  Clicking the main "Parse IOCs"
        button with nothing checked runs ALL patterns.  Users check
        individual types when they want a targeted parse.
        """
        menu = self._toolbar["parse_menu"]
        menu_style = dict(
            bg=COLORS["bg_secondary"], fg=COLORS["fg_primary"],
            activebackground=COLORS["blue_dim"],
            activeforeground=COLORS["fg_heading"],
            font=FONTS["body"],
        )

        def _select_all():
            for var in self._selected_patterns.values():
                var.set(True)

        def _deselect_all():
            for var in self._selected_patterns.values():
                var.set(False)

        menu.add_command(label="✓  Select All", command=_select_all)
        menu.add_command(label="✗  Deselect All", command=_deselect_all)
        menu.add_separator()

        group_emojis = {
            "Network": "🌐",
            "URLs": "🔗",
            "Hashes & Fingerprints": "🔑",
            "Identifiers": "🏷️",
            "Files": "📁",
            "Identity": "📧",
            "Registry": "🗂️",
            "Hardware": "🖥️",
            "Crypto": "💰",
            "Dark Web": "🧅",
            "Rules": "📜",
            "Malware Behavior": "🐛",
            "Infrastructure": "🏗️",
        }

        for group_name, pattern_names in IOC_PATTERN_GROUPS.items():
            submenu = tk.Menu(menu, tearoff=False, **menu_style)

            # "Toggle All" for this group
            def _toggle_group(names=pattern_names):
                all_on = all(
                    self._selected_patterns[n].get() for n in names
                )
                for n in names:
                    self._selected_patterns[n].set(not all_on)

            submenu.add_command(
                label=f"Toggle All {group_name}",
                command=_toggle_group,
            )
            submenu.add_separator()

            for pat_name in pattern_names:
                if pat_name in self._selected_patterns:
                    submenu.add_checkbutton(
                        label=pat_name,
                        variable=self._selected_patterns[pat_name],
                    )

            emoji = group_emojis.get(group_name, "")
            display_label = f"{emoji}  {group_name}" if emoji else group_name
            menu.add_cascade(label=display_label, menu=submenu)

    def _build_vt_menu(self):
        """Populate the VirusTotal SplitButton dropdown with all VT operations."""
        menu = self._toolbar["vt_menu"]

        vt_items = [
            ("🔍  VT Check Selected", self._on_vt_check),
            ("📤  Submit URL(s)", self._submit_url_for_analysis),
            ("🔎  Hash Details", self._get_all_hash_details),
            ("🛡️  MITRE TTPs", self._submit_for_mitre_ttps),
            ("🧬  Behavior Analysis", self._get_file_behavior),
            ("🌐  DNS Resolutions", self._get_resolutions),
            ("📡  Communicating Files", self._get_communicating_files),
        ]

        for label, cmd in vt_items:
            menu.add_command(label=label, command=cmd)

    def _bind_keyboard_shortcuts(self):
        """Register global keyboard shortcuts."""
        self.bind(KEYBOARD_SHORTCUTS["parse"][1], lambda _: self._parse_iocs())
        self.bind(KEYBOARD_SHORTCUTS["defang"][1], lambda _: self._defang_iocs())
        self.bind(KEYBOARD_SHORTCUTS["find_replace"][1], lambda _: self._toggle_find_replace())
        self.bind(KEYBOARD_SHORTCUTS["save_input"][1], lambda _: self._save_input_text())
        self.bind(KEYBOARD_SHORTCUTS["clear_input"][1], lambda _: self._clear_input_text())
        self.bind(KEYBOARD_SHORTCUTS["run_jsluice"][1], lambda _: self._run_jsluice())
        self.bind(KEYBOARD_SHORTCUTS["run_shell"][1], lambda _: self._run_shell_command())

        self.bind(KEYBOARD_SHORTCUTS["tab_ioc"][1], lambda _: self._notebook.select(0))
        self.bind(KEYBOARD_SHORTCUTS["tab_vt"][1], lambda _: self._notebook.select(1))
        self.bind(KEYBOARD_SHORTCUTS["tab_jsluice"][1], lambda _: self._notebook.select(2))
        self.bind(KEYBOARD_SHORTCUTS["tab_shell"][1], lambda _: self._notebook.select(3))
        self.bind(KEYBOARD_SHORTCUTS["tab_nmap"][1], lambda _: self._notebook.select(4))
        self.bind(KEYBOARD_SHORTCUTS["run_nmap"][1], lambda _: self._run_nmap())

        self.bind("<Control-o>", lambda _: self._open_file())

    def _open_file(self):
        """Open a file and load its contents into the input area."""
        path = filedialog.askopenfilename(
            title="Open File",
            filetypes=[
                ("Text Files", "*.txt *.log *.csv *.json *.js *.html *.xml *.yaml *.yml"),
                ("All Files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            self._article_input.delete("1.0", tk.END)
            self._article_input.insert("1.0", content)
            self._article_input.config(fg=COLORS["fg_primary"])
            self._set_status(f"Loaded: {os.path.basename(path)} ({len(content):,} chars)")
        except Exception as exc:
            messagebox.showerror("File Error", f"Failed to read file:\n{exc}")

    def _populate_initial_text(self):
        """Fill tabs with help / placeholder text on startup."""
        inp = self._input["text"]
        inp.insert(tk.END, INPUT_PLACEHOLDER)
        inp.config(fg=COLORS["fg_placeholder"])

        self._output["review_text"].insert(tk.END, IOC_REVIEW_HELP)
        self._render_review_tree_placeholder()
        self._output["vt_text"].insert(tk.END, VT_HELP)

        jsluice_text = self._output["jsluice_text"]
        jsluice_text.insert(tk.END, JSLUICE_HELP)
        if not self.jsluice.available:
            jsluice_text.insert(
                tk.END,
                "\n\nWARNING: jsluice command not found in PATH.\n"
                "Click 'Install jsluice' in the toolbar to install automatically.",
                "error",
            )
        if self.jsluice.init_warning:
            messagebox.showwarning("Jsluice Warning", self.jsluice.init_warning)

        self._output["shell_output"].insert(tk.END, SHELL_HELP)

        self._nmap_output.insert(tk.END, NMAP_HELP)
        if not self.nmap.available:
            self._nmap_output.insert(
                tk.END,
                "\n\nWARNING: nmap command not found in PATH.\n"
                "Click 'Install Nmap' in the toolbar to install automatically.",
                "error",
            )

        self._render_history_placeholder()
        self.after(80, self._refresh_history_tab)
        if self._history_db_error:
            self._output["history_details_text"].configure(state="normal")
            self._output["history_details_text"].delete("1.0", tk.END)
            self._output["history_details_text"].insert(
                tk.END,
                "IOC History database unavailable.\n\n"
                f"{self._history_db_error}",
                "error",
            )
            self._set_status("IOC History unavailable")

    def _on_close(self):
        """Cleanup and exit."""
        try:
            self._stop_rest_api(silent=True)
        except Exception:
            pass
        self.jsluice.cleanup()
        self.destroy()

    # ==================================================================
    # Find/Replace toggle
    # ==================================================================

    def _toggle_find_replace(self):
        """Show or hide the Find/Replace bar."""
        if self._find_replace_visible:
            self._fr["frame"].pack_forget()
            self._fr["separator"].pack_forget()
            self._find_replace_visible = False
        else:
            self._fr["separator"].pack(side=tk.TOP, fill="x",
                                       before=self.main_pane)
            self._fr["frame"].pack(side=tk.TOP, fill="x",
                                   before=self.main_pane)
            self._fr["find_entry"].focus_set()
            self._find_replace_visible = True

    # ==================================================================
    # Settings / UI prefs
    # ==================================================================

    def _apply_ui_density_scale(self):
        """Apply a coarse Tk scaling factor from persisted density prefs."""
        scale_map = {
            "compact": 0.95,
            "normal": 1.00,
            "comfortable": 1.08,
        }
        factor = scale_map.get(getattr(self.settings, "ui_density", "normal"), 1.0)
        try:
            self.tk.call("tk", "scaling", factor)
        except Exception:
            pass

    def _apply_runtime_settings(self):
        """Apply settings that can be updated without rebuilding the UI."""
        try:
            self.jsluice.set_temp_max_age(self.settings.jsluice_temp_max_age_seconds)
        except Exception:
            pass

    def _apply_default_parse_groups(self):
        """Apply persisted default parse groups to pattern checkboxes."""
        groups = [
            g for g in self.settings.default_parse_groups
            if g in IOC_PATTERN_GROUPS
        ]
        if not groups:
            return
        for var in self._selected_patterns.values():
            var.set(False)
        for group_name in groups:
            for pat_name in IOC_PATTERN_GROUPS.get(group_name, []):
                var = self._selected_patterns.get(pat_name)
                if var is not None:
                    var.set(True)

    def _notify(
        self,
        message: str,
        level: str = "info",
        title: str | None = None,
        duration_ms: int = 2600,
    ):
        """Show a lightweight in-app toast message."""
        try:
            self._toasts.show(message, level=level, title=title, duration_ms=duration_ms)
        except Exception:
            pass

    # ==================================================================
    # REST API runtime controls (GUI-managed)
    # ==================================================================

    def _rest_api_status_text(self) -> str:
        if self._api_running:
            return f"Running ({self._api_runtime_url or 'active'})"
        if self._api_starting:
            return "Starting..."
        if self._api_last_error:
            return f"Stopped (last error: {self._api_last_error})"
        return "Stopped"

    def _refresh_rest_api_menu_state(self):
        """Enable/disable REST API menu actions based on runtime state."""
        try:
            tm = self._menus["tools_menu"]
            tm.entryconfigure("Start REST API", state=(tk.DISABLED if self._api_running or self._api_starting else tk.NORMAL))
            tm.entryconfigure("Stop REST API", state=(tk.NORMAL if self._api_running or self._api_starting else tk.DISABLED))
            token_available = bool(getattr(self.settings, "api_bearer_token", "").strip())
            tm.entryconfigure("Copy REST API Token", state=(tk.NORMAL if token_available else tk.DISABLED))
            tm.entryconfigure("Open REST API Docs", state=tk.NORMAL)
        except Exception:
            pass

    def _persist_api_token_if_needed(self, token: str) -> None:
        token = str(token or "").strip()
        if not token:
            return
        if getattr(self.settings, "api_bearer_token", "").strip() == token:
            return
        self.settings.api_bearer_token = token
        try:
            settings_store.save_settings(self.settings)
        except Exception:
            pass
        self._refresh_rest_api_menu_state()

    def _start_rest_api(self, silent: bool = False):
        """Start the embedded REST API server in a background thread."""
        if self._api_running or self._api_starting:
            if not silent:
                messagebox.showinfo("REST API", "REST API is already running or starting.")
            return

        host = str(getattr(self.settings, "api_host", "127.0.0.1") or "127.0.0.1").strip()
        try:
            port = int(getattr(self.settings, "api_port", 8765))
        except Exception:
            port = 8765
        require_auth = bool(getattr(self.settings, "api_require_auth", True))
        token = str(getattr(self.settings, "api_bearer_token", "") or "").strip()
        allow_shell = bool(getattr(self.settings, "api_allow_shell_endpoint", False))
        history_db_path = None
        try:
            if self.history_db is not None:
                history_db_path = str(self.history_db.db_path)
        except Exception:
            history_db_path = None

        try:
            import uvicorn  # type: ignore
            from ..api import AppService, create_api_app
        except Exception as exc:
            self._api_last_error = f"Missing dependency ({type(exc).__name__})"
            self._refresh_rest_api_menu_state()
            if not silent:
                messagebox.showerror(
                    "REST API Unavailable",
                    "FastAPI/Uvicorn dependencies are not installed.\n\n"
                    "Install with:\n"
                    "  pip install -r requirements.txt\n\n"
                    f"Details: {exc}",
                )
            return

        try:
            service = AppService(
                allow_shell_api=allow_shell,
                auth_token=(token or None),
                require_auth=require_auth,
                history_db_path=history_db_path,
            )
            app = create_api_app(service)
            # Persist generated token so external clients like OpenClaw can reuse it.
            if service.require_auth and service.auth_token_generated:
                self._persist_api_token_if_needed(service.auth_token)

            config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)
            try:
                server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
            except Exception:
                pass
        except Exception as exc:
            self._api_last_error = f"{type(exc).__name__}: {exc}"
            self._refresh_rest_api_menu_state()
            if not silent:
                messagebox.showerror("REST API Error", f"Failed to initialize REST API:\n{exc}")
            return

        def _run_server():
            err: str | None = None
            try:
                server.run()
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
            finally:
                def _finish():
                    if err:
                        self._api_last_error = err
                    # If server exits unexpectedly after having started, clear runtime state.
                    if not self._api_starting and self._api_running:
                        self._api_running = False
                        self._api_runtime_url = ""
                        self._api_server = None
                        self._api_server_thread = None
                        self._api_service = None
                        self._refresh_rest_api_menu_state()
                        self._set_status("REST API stopped")
                        self._notify("REST API stopped", level="warning")
                    elif self._api_starting:
                        # Poller will handle startup failure path.
                        pass
                try:
                    self.after(0, _finish)
                except Exception:
                    pass

        thread = threading.Thread(target=_run_server, daemon=True)
        self._api_server = server
        self._api_server_thread = thread
        self._api_service = service
        self._api_running = False
        self._api_starting = True
        self._api_last_error = None
        self._api_runtime_url = ""
        self._api_start_attempt_started = time.time()
        self._refresh_rest_api_menu_state()
        thread.start()
        self._set_status(f"Starting REST API on {host}:{port}...")
        self._notify(f"Starting REST API on {host}:{port}", level="info")
        self.after(150, self._poll_rest_api_startup)

    def _poll_rest_api_startup(self):
        """Poll uvicorn startup state and finalize GUI status."""
        if not self._api_starting:
            return
        server = self._api_server
        thread = self._api_server_thread
        host = str(getattr(self.settings, "api_host", "127.0.0.1") or "127.0.0.1").strip()
        port = int(getattr(self.settings, "api_port", 8765) or 8765)
        started = bool(getattr(server, "started", False)) if server is not None else False

        if started:
            self._api_starting = False
            self._api_running = True
            display_host = host if host not in ("0.0.0.0", "") else "127.0.0.1"
            self._api_runtime_url = f"http://{display_host}:{port}"
            self._refresh_rest_api_menu_state()
            self._set_status(f"REST API running at {self._api_runtime_url}")
            self._notify(f"REST API running at {self._api_runtime_url}", level="success")
            return

        if thread is None or not thread.is_alive():
            self._api_starting = False
            self._api_running = False
            self._api_runtime_url = ""
            self._api_server = None
            self._api_server_thread = None
            self._api_service = None
            if not self._api_last_error:
                self._api_last_error = "Server exited before startup (port in use or dependency issue)"
            self._refresh_rest_api_menu_state()
            self._set_status("REST API failed to start")
            self._notify("REST API failed to start", level="error")
            return

        if time.time() - self._api_start_attempt_started > 10.0:
            # Timed out waiting for startup. Request shutdown and show error.
            try:
                if self._api_server is not None:
                    self._api_server.should_exit = True
            except Exception:
                pass
            self._api_starting = False
            self._api_running = False
            self._api_runtime_url = ""
            self._api_last_error = self._api_last_error or "Startup timeout"
            self._refresh_rest_api_menu_state()
            self._set_status("REST API startup timed out")
            self._notify("REST API startup timed out", level="error")
            return

        self.after(150, self._poll_rest_api_startup)

    def _stop_rest_api(self, silent: bool = False):
        """Stop the embedded REST API server if running."""
        if not self._api_running and not self._api_starting:
            self._refresh_rest_api_menu_state()
            if not silent:
                self._set_status("REST API is not running")
            return

        server = self._api_server
        thread = self._api_server_thread
        self._set_status("Stopping REST API...")

        try:
            if server is not None:
                server.should_exit = True
        except Exception:
            pass

        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
            if thread.is_alive():
                try:
                    if server is not None:
                        server.force_exit = True
                except Exception:
                    pass
                thread.join(timeout=1.0)

        still_alive = bool(thread and thread.is_alive())
        if still_alive:
            self._api_last_error = "Server thread did not stop cleanly"
            if not silent:
                messagebox.showwarning(
                    "REST API",
                    "REST API shutdown is still in progress in the background.",
                )
            return

        self._api_running = False
        self._api_starting = False
        self._api_runtime_url = ""
        self._api_server = None
        self._api_server_thread = None
        self._api_service = None
        self._refresh_rest_api_menu_state()
        if not silent:
            self._notify("REST API stopped", level="success")
            self._set_status("REST API stopped")

    def _copy_rest_api_token(self):
        token = str(getattr(self.settings, "api_bearer_token", "") or "").strip()
        if not token:
            messagebox.showwarning(
                "REST API Token",
                "No API bearer token is configured yet.\n"
                "Start the REST API once (with auth enabled) or set a token in Settings.",
            )
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(token)
            self._notify("REST API token copied", level="success")
            self._set_status("REST API token copied to clipboard")
        except Exception as exc:
            messagebox.showerror("Clipboard Error", f"Failed to copy token:\n{exc}")

    def _open_rest_api_docs(self):
        host = str(getattr(self.settings, "api_host", "127.0.0.1") or "127.0.0.1").strip()
        port = int(getattr(self.settings, "api_port", 8765) or 8765)
        if self._api_runtime_url:
            url = self._api_runtime_url + "/docs"
        else:
            display_host = host if host not in ("0.0.0.0", "") else "127.0.0.1"
            url = f"http://{display_host}:{port}/docs"
        try:
            webbrowser.open(url)
            self._set_status(f"Opened REST API docs: {url}")
        except Exception as exc:
            messagebox.showerror("REST API Docs", f"Failed to open browser:\n{exc}")

    def _show_settings_dialog(self):
        """Open a persisted settings dialog for timeouts/UI defaults."""
        dlg = tk.Toplevel(self)
        dlg.title("Settings")
        dlg.transient(self)
        dlg.configure(bg=COLORS["bg_primary"])
        dlg.resizable(True, True)
        dlg.grab_set()
        dlg.geometry("760x760")

        outer = tk.Frame(dlg, bg=COLORS["bg_primary"], padx=12, pady=12)
        outer.pack(expand=True, fill="both")

        row = 0
        tk.Label(
            outer,
            text="Runtime Preferences",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_heading"],
            font=FONTS["button"],
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(0, 8))
        row += 1

        def _lbl(text):
            return tk.Label(
                outer, text=text, bg=COLORS["bg_primary"],
                fg=COLORS["fg_secondary"], font=FONTS["label"], anchor="w"
            )

        shell_timeout_var = tk.StringVar(value=str(self.settings.shell_timeout_seconds))
        nmap_timeout_var = tk.StringVar(value=str(self.settings.nmap_timeout_seconds))
        jsluice_age_var = tk.StringVar(value=str(self.settings.jsluice_temp_max_age_seconds))
        density_var = tk.StringVar(value=self.settings.ui_density)
        api_host_var = tk.StringVar(value=str(getattr(self.settings, "api_host", "127.0.0.1")))
        api_port_var = tk.StringVar(value=str(getattr(self.settings, "api_port", 8765)))
        api_require_auth_var = tk.IntVar(
            value=1 if bool(getattr(self.settings, "api_require_auth", True)) else 0
        )
        api_token_var = tk.StringVar(value=str(getattr(self.settings, "api_bearer_token", "")))
        api_allow_shell_var = tk.IntVar(
            value=1 if bool(getattr(self.settings, "api_allow_shell_endpoint", False)) else 0
        )

        _lbl("Shell timeout (seconds)").grid(row=row, column=0, sticky="w", pady=3)
        tk.Entry(
            outer, textvariable=shell_timeout_var, width=10,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["body"],
        ).grid(row=row, column=1, sticky="w", padx=(8, 14), ipady=3)

        _lbl("Nmap timeout (seconds)").grid(row=row, column=2, sticky="w", pady=3)
        tk.Entry(
            outer, textvariable=nmap_timeout_var, width=10,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["body"],
        ).grid(row=row, column=3, sticky="w", padx=(8, 0), ipady=3)
        row += 1

        _lbl("Jsluice temp max age (sec)").grid(row=row, column=0, sticky="w", pady=3)
        tk.Entry(
            outer, textvariable=jsluice_age_var, width=10,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["body"],
        ).grid(row=row, column=1, sticky="w", padx=(8, 14), ipady=3)

        _lbl("UI density").grid(row=row, column=2, sticky="w", pady=3)
        density_combo = ttk.Combobox(
            outer,
            textvariable=density_var,
            values=["compact", "normal", "comfortable"],
            state="readonly",
            width=14,
            font=FONTS["body"],
        )
        density_combo.grid(row=row, column=3, sticky="w", padx=(8, 0))
        row += 1

        tk.Label(
            outer,
            text="UI density applies best after restart (scaling is also applied immediately where possible).",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            font=FONTS["label"],
            justify="left",
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(2, 10))
        row += 1

        tk.Frame(outer, bg=COLORS["separator"], height=1).grid(
            row=row, column=0, columnspan=4, sticky="ew", pady=(0, 10)
        )
        row += 1

        tk.Label(
            outer,
            text="Default Parse Groups",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_heading"],
            font=FONTS["button"],
        ).grid(row=row, column=0, columnspan=4, sticky="w")
        row += 1

        tk.Label(
            outer,
            text="These groups are preselected in the Parse dropdown at startup. Leave empty to keep no boxes checked (Parse button still parses all).",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            font=FONTS["label"],
            justify="left",
            wraplength=640,
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(2, 6))
        row += 1

        groups_frame_row = row
        groups_frame = tk.Frame(outer, bg=COLORS["bg_primary"])
        groups_frame.grid(row=groups_frame_row, column=0, columnspan=4, sticky="nsew")

        groups_list = tk.Listbox(
            groups_frame,
            selectmode=tk.MULTIPLE,
            bg=COLORS["bg_output"],
            fg=COLORS["fg_primary"],
            selectbackground=COLORS["blue_dim"],
            selectforeground=COLORS["fg_heading"],
            relief="flat",
            bd=0,
            height=10,
            exportselection=False,
            font=FONTS["body"],
        )
        groups_scroll = tk.Scrollbar(groups_frame, command=groups_list.yview)
        groups_list.configure(yscrollcommand=groups_scroll.set)
        groups_list.grid(row=0, column=0, sticky="nsew")
        groups_scroll.grid(row=0, column=1, sticky="ns")
        groups_frame.grid_columnconfigure(0, weight=1)
        groups_frame.grid_rowconfigure(0, weight=1)

        group_names = list(IOC_PATTERN_GROUPS.keys())
        for group_name in group_names:
            groups_list.insert(tk.END, group_name)
        for idx, group_name in enumerate(group_names):
            if group_name in self.settings.default_parse_groups:
                groups_list.selection_set(idx)
        row += 1

        group_btns = tk.Frame(outer, bg=COLORS["bg_primary"])
        group_btns.grid(row=row, column=0, columnspan=4, sticky="ew", pady=(6, 10))
        tk.Button(
            group_btns, text="Select All Groups",
            command=lambda: groups_list.selection_set(0, tk.END),
            relief="flat", bd=0,
            bg=COLORS["slate"], fg=COLORS["btn_fg"],
            activebackground=COLORS["slate_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=4,
        ).pack(side="left")
        tk.Button(
            group_btns, text="Clear Group Selection",
            command=lambda: groups_list.selection_clear(0, tk.END),
            relief="flat", bd=0,
            bg=COLORS["slate"], fg=COLORS["btn_fg"],
            activebackground=COLORS["slate_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=4,
        ).pack(side="left", padx=(8, 0))

        tk.Frame(outer, bg=COLORS["separator"], height=1).grid(
            row=row + 1, column=0, columnspan=4, sticky="ew", pady=(0, 10)
        )
        row += 2

        # ------------------------------------------------------------------
        # REST API controls (for external integrations like OpenClaw)
        # ------------------------------------------------------------------
        tk.Label(
            outer,
            text="REST API",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_heading"],
            font=FONTS["button"],
        ).grid(row=row, column=0, columnspan=4, sticky="w")
        row += 1

        tk.Label(
            outer,
            text=(
                "Run a local REST API so other programs can push/pull IOC data, "
                "trigger parsing, query history, and run jobs (VT/jsluice/nmap)."
            ),
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            font=FONTS["label"],
            justify="left",
            wraplength=720,
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(2, 6))
        row += 1

        _lbl("Host").grid(row=row, column=0, sticky="w", pady=3)
        tk.Entry(
            outer, textvariable=api_host_var, width=18,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["body"],
        ).grid(row=row, column=1, sticky="w", padx=(8, 14), ipady=3)

        _lbl("Port").grid(row=row, column=2, sticky="w", pady=3)
        tk.Entry(
            outer, textvariable=api_port_var, width=10,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["body"],
        ).grid(row=row, column=3, sticky="w", padx=(8, 0), ipady=3)
        row += 1

        api_opts = tk.Frame(outer, bg=COLORS["bg_primary"])
        api_opts.grid(row=row, column=0, columnspan=4, sticky="ew", pady=(2, 4))
        tk.Checkbutton(
            api_opts,
            text="Require bearer auth",
            variable=api_require_auth_var,
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            selectcolor=COLORS["bg_entry"],
            activebackground=COLORS["bg_primary"],
            activeforeground=COLORS["fg_primary"],
            font=FONTS["label"],
        ).pack(side="left")
        tk.Checkbutton(
            api_opts,
            text="Allow shell endpoint (dangerous)",
            variable=api_allow_shell_var,
            bg=COLORS["bg_primary"],
            fg=COLORS["orange"],
            selectcolor=COLORS["bg_entry"],
            activebackground=COLORS["bg_primary"],
            activeforeground=COLORS["orange"],
            font=FONTS["label"],
        ).pack(side="left", padx=(12, 0))
        row += 1

        _lbl("Bearer token").grid(row=row, column=0, sticky="w", pady=3)
        api_token_entry = tk.Entry(
            outer, textvariable=api_token_var,
            bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"], relief="flat", bd=0,
            font=FONTS["mono_small"],
        )
        api_token_entry.grid(row=row, column=1, columnspan=3, sticky="ew", padx=(8, 0), ipady=3)
        row += 1

        api_token_btns = tk.Frame(outer, bg=COLORS["bg_primary"])
        api_token_btns.grid(row=row, column=0, columnspan=4, sticky="ew", pady=(4, 8))

        def _generate_api_token():
            api_token_var.set(secrets.token_urlsafe(32))

        def _copy_api_token_from_dialog():
            token = api_token_var.get().strip()
            if not token:
                messagebox.showwarning("REST API Token", "No token to copy.", parent=dlg)
                return
            try:
                self.clipboard_clear()
                self.clipboard_append(token)
                self._notify("REST API token copied", level="success")
            except Exception as exc:
                messagebox.showerror("Clipboard Error", f"Failed to copy token:\n{exc}", parent=dlg)

        tk.Button(
            api_token_btns, text="Generate Token",
            command=_generate_api_token,
            relief="flat", bd=0,
            bg=COLORS["teal"], fg=COLORS["btn_fg"],
            activebackground=COLORS["teal_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=4,
        ).pack(side="left")
        tk.Button(
            api_token_btns, text="Copy Token",
            command=_copy_api_token_from_dialog,
            relief="flat", bd=0,
            bg=COLORS["blue"], fg=COLORS["btn_fg"],
            activebackground=COLORS["blue_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=4,
        ).pack(side="left", padx=(8, 0))
        row += 1

        api_status_var = tk.StringVar(value=self._rest_api_status_text())
        tk.Label(
            outer,
            textvariable=api_status_var,
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            font=FONTS["label"],
            justify="left",
            wraplength=720,
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(0, 6))
        row += 1

        api_btns = tk.Frame(outer, bg=COLORS["bg_primary"])
        api_btns.grid(row=row, column=0, columnspan=4, sticky="ew", pady=(0, 10))

        def _refresh_api_status_in_dlg():
            try:
                api_status_var.set(self._rest_api_status_text())
            except Exception:
                return
            try:
                if self._api_running or self._api_starting:
                    start_api_btn.configure(state="disabled")
                    stop_api_btn.configure(state="normal")
                else:
                    start_api_btn.configure(state="normal")
                    stop_api_btn.configure(state="disabled")
            except Exception:
                pass
            if dlg.winfo_exists():
                dlg.after(300, _refresh_api_status_in_dlg)

        def _sync_api_vars_to_settings_in_memory():
            self.settings.api_host = api_host_var.get().strip() or "127.0.0.1"
            try:
                self.settings.api_port = int(api_port_var.get().strip())
            except Exception:
                self.settings.api_port = 8765
            self.settings.api_require_auth = bool(api_require_auth_var.get())
            self.settings.api_bearer_token = api_token_var.get().strip()
            self.settings.api_allow_shell_endpoint = bool(api_allow_shell_var.get())
            self.settings = self.settings.normalized()

        def _start_api_from_dialog():
            _sync_api_vars_to_settings_in_memory()
            try:
                settings_store.save_settings(self.settings)
            except Exception:
                pass
            self._start_rest_api()

        def _stop_api_from_dialog():
            self._stop_rest_api()

        start_api_btn = tk.Button(
            api_btns, text="Start API",
            command=_start_api_from_dialog,
            relief="flat", bd=0,
            bg=COLORS["green"], fg=COLORS["btn_fg"],
            activebackground=COLORS["green_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["button"], padx=12, pady=5,
        )
        start_api_btn.pack(side="left")
        stop_api_btn = tk.Button(
            api_btns, text="Stop API",
            command=_stop_api_from_dialog,
            relief="flat", bd=0,
            bg=COLORS["red"], fg=COLORS["btn_fg"],
            activebackground=COLORS["red_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["button"], padx=12, pady=5,
        )
        stop_api_btn.pack(side="left", padx=(8, 0))
        tk.Button(
            api_btns, text="Open Docs",
            command=self._open_rest_api_docs,
            relief="flat", bd=0,
            bg=COLORS["blue"], fg=COLORS["btn_fg"],
            activebackground=COLORS["blue_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=5,
        ).pack(side="left", padx=(8, 0))

        _refresh_api_status_in_dlg()

        tk.Frame(outer, bg=COLORS["separator"], height=1).grid(
            row=row, column=0, columnspan=4, sticky="ew", pady=(2, 10)
        )
        row += 1

        actions = tk.Frame(outer, bg=COLORS["bg_primary"])
        actions.grid(row=row, column=0, columnspan=4, sticky="ew")

        def _clear_vt_from_settings():
            keychain.delete_api_key()
            self.vt_api_key = None
            self._set_status("VT API key cleared from keychain")
            self._notify("VirusTotal API key cleared", level="success")

        tk.Button(
            actions, text="Clear Stored VT API Key",
            command=_clear_vt_from_settings,
            relief="flat", bd=0,
            bg=COLORS["red"], fg=COLORS["btn_fg"],
            activebackground=COLORS["red_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=10, pady=5,
        ).pack(side="left")

        def _save():
            try:
                old_api_tuple = (
                    getattr(self.settings, "api_host", "127.0.0.1"),
                    int(getattr(self.settings, "api_port", 8765)),
                    bool(getattr(self.settings, "api_require_auth", True)),
                    str(getattr(self.settings, "api_bearer_token", "") or ""),
                    bool(getattr(self.settings, "api_allow_shell_endpoint", False)),
                )
                new_settings = settings_store.AppSettings(
                    shell_timeout_seconds=int(shell_timeout_var.get().strip()),
                    nmap_timeout_seconds=int(nmap_timeout_var.get().strip()),
                    jsluice_temp_max_age_seconds=int(jsluice_age_var.get().strip()),
                    ui_density=density_var.get().strip(),
                    default_parse_groups=[
                        group_names[i] for i in groups_list.curselection()
                    ],
                    api_host=api_host_var.get().strip() or "127.0.0.1",
                    api_port=int(api_port_var.get().strip()),
                    api_require_auth=bool(api_require_auth_var.get()),
                    api_bearer_token=api_token_var.get().strip(),
                    api_allow_shell_endpoint=bool(api_allow_shell_var.get()),
                ).normalized()
            except ValueError:
                messagebox.showerror(
                    "Settings Error",
                    "Timeout and API port fields must be integers.",
                )
                return

            density_changed = new_settings.ui_density != self.settings.ui_density
            api_settings_changed = old_api_tuple != (
                new_settings.api_host,
                new_settings.api_port,
                new_settings.api_require_auth,
                new_settings.api_bearer_token,
                new_settings.api_allow_shell_endpoint,
            )
            self.settings = new_settings
            self._apply_runtime_settings()
            self._apply_ui_density_scale()
            self._apply_default_parse_groups()
            try:
                settings_store.save_settings(self.settings)
            except Exception as exc:
                messagebox.showerror("Settings Error", f"Failed to save settings:\n{exc}")
                return

            self._set_status("Settings saved")
            self._notify("Settings saved", level="success")
            self._refresh_rest_api_menu_state()
            if density_changed:
                self._notify(
                    "UI density updated. Restart the app for a full layout refresh.",
                    level="info",
                    duration_ms=3400,
                )
            if api_settings_changed and (self._api_running or self._api_starting):
                self._notify(
                    "REST API settings changed. Stop/start the API to apply host/auth/token changes.",
                    level="warning",
                    duration_ms=4200,
                )
            dlg.destroy()

        tk.Button(
            actions, text="Cancel",
            command=dlg.destroy,
            relief="flat", bd=0,
            bg=COLORS["slate"], fg=COLORS["btn_fg"],
            activebackground=COLORS["slate_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=12, pady=5,
        ).pack(side="right")
        tk.Button(
            actions, text="Save Settings",
            command=_save,
            relief="flat", bd=0,
            bg=COLORS["blue"], fg=COLORS["btn_fg"],
            activebackground=COLORS["blue_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["button"], padx=12, pady=5,
        ).pack(side="right", padx=(0, 8))

        outer.grid_columnconfigure(0, weight=1)
        outer.grid_columnconfigure(1, weight=0)
        outer.grid_columnconfigure(2, weight=1)
        outer.grid_columnconfigure(3, weight=0)
        outer.grid_rowconfigure(groups_frame_row, weight=1)

        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.wait_visibility()
        dlg.focus_set()

    # ==================================================================
    # Status bar helpers
    # ==================================================================

    def _set_status(self, text: str):
        self._status["progress_var"].set(text)
        self.update_idletasks()

    def _set_summary(self, text: str):
        self._status["summary_var"].set(text)
        self.update_idletasks()

    def _set_progress(self, current: int, total: int, label: str = ""):
        """Update the status-bar determinate progress indicator."""
        try:
            bar = self._status.get("progress_bar")
            if bar is None:
                return
            total = max(1, int(total))
            current = max(0, min(int(current), total))
            bar.stop()
            bar.configure(mode="determinate", maximum=total, value=current)
            self._status["progress_detail_var"].set(
                label or f"{current}/{total}"
            )
            self.update_idletasks()
        except Exception:
            pass

    def _set_busy_progress(self, label: str = "Working..."):
        """Show an indeterminate spinner-like progress bar in the status bar."""
        try:
            bar = self._status.get("progress_bar")
            if bar is None:
                return
            if str(bar.cget("mode")) != "indeterminate":
                bar.configure(mode="indeterminate")
            bar.start(12)
            self._status["progress_detail_var"].set(label)
            self.update_idletasks()
        except Exception:
            pass

    def _clear_progress(self):
        """Reset the status-bar progress indicator."""
        try:
            bar = self._status.get("progress_bar")
            if bar is None:
                return
            bar.stop()
            bar.configure(mode="determinate", maximum=100, value=0)
            self._status["progress_detail_var"].set("")
            self.update_idletasks()
        except Exception:
            pass

    # ==================================================================
    # Convenience accessors
    # ==================================================================

    @property
    def _article_input(self) -> scrolledtext.ScrolledText:
        return self._input["text"]

    @property
    def _review_output(self) -> scrolledtext.ScrolledText:
        return self._output["review_text"]

    @property
    def _review_tree(self):
        return self._output["review_tree"]

    @property
    def _vt_output(self) -> scrolledtext.ScrolledText:
        return self._output["vt_text"]

    @property
    def _jsluice_output(self) -> scrolledtext.ScrolledText:
        return self._output["jsluice_text"]

    @property
    def _shell_output(self) -> scrolledtext.ScrolledText:
        return self._output["shell_output"]

    @property
    def _nmap_output(self) -> scrolledtext.ScrolledText:
        return self._output["nmap_output"]

    @property
    def _nmap_structured(self) -> scrolledtext.ScrolledText:
        return self._output["nmap_structured"]

    @property
    def _notebook(self):
        return self._output["notebook"]

    # ==================================================================
    # Placeholder behaviour
    # ==================================================================

    def _on_input_focus_in(self, _event):
        if self._article_input.get("1.0", "end-1c") == INPUT_PLACEHOLDER:
            self._article_input.delete("1.0", tk.END)
            self._article_input.config(fg=COLORS["fg_primary"])

    def _on_input_focus_out(self, _event):
        if not self._article_input.get("1.0", "end-1c"):
            self._article_input.insert(tk.END, INPUT_PLACEHOLDER)
            self._article_input.config(fg=COLORS["fg_placeholder"])

    def _get_input_text(self) -> str | None:
        """Return input text, or None if empty / placeholder."""
        text = self._article_input.get("1.0", tk.END)
        if not text or text.strip() == INPUT_PLACEHOLDER:
            return None
        return text

    # ==================================================================
    # Find / Replace / Highlight
    # ==================================================================

    def _clear_highlight(self):
        self._article_input.tag_remove("highlight", "1.0", tk.END)

    def _highlight_text(self):
        self._clear_highlight()
        find_text = self._fr["find_entry"].get()
        if not find_text.strip():
            return
        use_regex = bool(self._fr["regex_var"].get())
        count = 0
        try:
            pattern = find_text if use_regex else re.escape(find_text)
            start = "1.0"
            while True:
                pos = self._article_input.search(
                    pattern, start, stopindex=tk.END,
                    regexp=use_regex, nocase=not use_regex,
                )
                if not pos:
                    break
                if use_regex:
                    segment = self._article_input.get(pos, f"{pos} + 200 chars")
                    m = re.search(find_text, segment)
                    length = max(1, len(m.group(0))) if m else 1
                    end = f"{pos}+{length}c"
                else:
                    end = f"{pos}+{len(find_text)}c"
                self._article_input.tag_add("highlight", pos, end)
                start = end
                count += 1
        except re.error as exc:
            messagebox.showerror("Invalid Regex", f"Error in Find pattern: {exc}")
        except tk.TclError:
            pass
        if count:
            self._set_status(f"Found {count} match{'es' if count != 1 else ''}")

    def _find_and_replace(self):
        find_str = self._fr["find_entry"].get()
        replace_str = self._fr["replace_entry"].get()
        use_regex = self._fr["regex_var"].get() == 1
        if not find_str:
            messagebox.showwarning("Missing Input", "Please enter text to find.")
            return
        count = 0
        try:
            if use_regex:
                content = self._article_input.get("1.0", tk.END)
                new_content, count = re.subn(find_str, replace_str, content)
                if count > 0:
                    self._article_input.delete("1.0", tk.END)
                    self._article_input.insert("1.0", new_content)
                    self._clear_highlight()
                    self._article_input.tag_remove("ioc_highlight", "1.0", tk.END)
            else:
                start = "1.0"
                while True:
                    pos = self._article_input.search(
                        find_str, start, stopindex=tk.END, nocase=True,
                    )
                    if not pos:
                        break
                    end_pos = f"{pos}+{len(find_str)}c"
                    self._article_input.delete(pos, end_pos)
                    self._article_input.insert(pos, replace_str)
                    count += 1
                    start = f"{pos}+{len(replace_str)}c"
            if count > 0:
                self._set_status(f"Replaced {count} occurrence{'s' if count != 1 else ''}")
                messagebox.showinfo("Replace Complete", f"Made {count} replacements.")
            else:
                messagebox.showinfo("Replace Complete", "No occurrences found.")
        except re.error as exc:
            messagebox.showerror("Regex Error", f"Invalid Regex:\n{exc}")
        except tk.TclError as exc:
            messagebox.showerror("Replace Error", f"Tkinter error: {exc}")
        except Exception as exc:
            messagebox.showerror("Error", f"Unexpected error: {exc}")

    # ==================================================================
    # IOC Parsing
    # ==================================================================

    def _parse_iocs(self):
        text = self._get_input_text()
        if text is None:
            messagebox.showwarning(
                "Input Missing", "Please provide text in the input box first."
            )
            return

        if self._parsing_iocs:
            messagebox.showwarning(
                "Parser Busy",
                "IOC parsing is already in progress.\n"
                "Please wait for it to complete.",
            )
            return

        # Snapshot selected patterns before entering bg thread.
        # If none are checked → run ALL patterns (the "Parse All" path).
        selected = {
            name for name, var in self._selected_patterns.items()
            if var.get()
        } or None  # None = run all patterns

        self._parsing_iocs = True
        self._set_status("Parsing IOCs...")
        self._set_busy_progress("Parsing")
        self._loading.show("Parsing IOCs...",
                           f"{len(text):,} characters to analyze")
        self._review_output.configure(state="normal")
        self._review_output.delete("1.0", tk.END)
        self._review_output.insert(tk.END, "Parsing IOCs...\n")
        self._notebook.select(0)

        def _work():
            """Extract IOCs and pre-build all output on the bg thread."""
            found, spans = ioc_parser.extract_iocs(
                text, selected_patterns=selected,
            )

            # Pre-compute Tkinter line.col indices for input highlights
            tk_spans = IOCExtractorApp._charoffsets_to_linecol(text, spans)

            # Build the entire review output as a single string +
            # tag ranges, so the main thread just does one insert.
            output_text, tag_ranges, total = (
                IOCExtractorApp._build_review_output(found)
            )

            self.after(0, _apply, found, output_text, tag_ranges,
                       tk_spans, total)

        def _apply(found, output_text, tag_ranges, tk_spans, total):
            """Single fast update on the main thread."""
            self.found_iocs = {
                k: v for k, v in found.items()
                if not k.startswith("__error__")
            }
            self._review_tree_source_label = "Parser"
            self._history_loaded_collection_id = None
            self._review_tree_status.clear()

            # Hide overlay so the user sees the result immediately
            self._loading.hide()

            # --- Review output: one bulk insert ---
            out = self._review_output
            out.configure(state="normal")
            out.delete("1.0", tk.END)

            if not output_text:
                out.insert(tk.END,
                           "No IOCs found matching the defined patterns.")
                self._render_review_tree_placeholder("No parsed IOC rows")
                self._set_status("No IOCs found")
                self._set_summary("")
                self._clear_progress()
                self._parsing_iocs = False
                return

            out.insert(tk.END, output_text)
            self._render_review_tree_from_found_iocs()

            # Apply tags (bold headings, errors, links) — all pre-computed
            for tag, start_idx, end_idx in tag_ranges:
                try:
                    out.tag_add(tag, start_idx, end_idx)
                except tk.TclError:
                    pass

            # --- Input highlights (chunked — can be many) ---
            inp = self._article_input
            inp.tag_remove("ioc_highlight", "1.0", tk.END)

            if tk_spans:
                self._highlight_state = {"spans": tk_spans, "idx": 0}
                self.after(1, _highlight_chunk)
            else:
                self._clear_progress()
                self._parsing_iocs = False

            # Status / summary
            summary = file_operations.format_ioc_summary(self.found_iocs)
            self._set_status(
                f"Parsed {total} IOCs across "
                f"{len(self.found_iocs)} categories"
            )
            self._set_summary(summary)

        def _highlight_chunk():
            """Apply input highlights in batches — keeps UI responsive."""
            st = self._highlight_state
            if st is None:
                return
            spans = st["spans"]
            inp = self._article_input
            CHUNK = 2000  # tag_add with line.col is O(1), safe to do many
            i = st["idx"]
            end = min(i + CHUNK, len(spans))
            while i < end:
                s_idx, e_idx = spans[i]
                try:
                    inp.tag_add("ioc_highlight", s_idx, e_idx)
                except tk.TclError:
                    pass
                i += 1
            st["idx"] = i
            if i >= len(spans):
                self._highlight_state = None
                self._clear_progress()
                self._parsing_iocs = False
            else:
                self.after(1, _highlight_chunk)

        threading.Thread(target=_work, daemon=True).start()

    # ------------------------------------------------------------------
    # Static helpers for background pre-computation
    # ------------------------------------------------------------------

    @staticmethod
    def _build_review_output(found):
        """Build review text + tag ranges entirely off the main thread.

        Returns (output_text, tag_ranges, total_iocs) where
        tag_ranges is a list of (tag_name, "line.col", "line.col").
        """
        import re as _re
        url_pat = _re.compile(r'https?://[^\s<>"\')\]]+')

        parts: list[str] = []
        tag_ranges: list[tuple] = []
        line = 1  # current line in the output (1-based)
        total = 0

        for name, matches in found.items():
            if name.startswith("__error__"):
                real_name = name.replace("__error__", "")
                heading = f"--- Error in pattern {real_name}: {matches[0]} ---\n\n"
                tag_ranges.append(("error", f"{line}.0", f"{line}.{len(heading) - 1}"))
                parts.append(heading)
                line += heading.count("\n")
                continue

            # Category heading
            heading = f"--- {name} ---\n"
            tag_ranges.append(("bold", f"{line}.0", f"{line}.{len(heading) - 1}"))
            parts.append(heading)
            line += 1

            for ioc in matches:
                ioc_line = ioc + "\n"
                # Detect URLs for link tagging
                for m in url_pat.finditer(ioc_line):
                    tag_ranges.append((
                        "link",
                        f"{line}.{m.start()}",
                        f"{line}.{m.end()}",
                    ))
                parts.append(ioc_line)
                line += 1

            parts.append("\n")
            line += 1
            total += len(matches)

        return "".join(parts), tag_ranges, total

    @staticmethod
    def _charoffsets_to_linecol(text, spans):
        """Convert character offsets to Tkinter 'line.col' indices.

        Runs on the background thread.  Building the index is O(N) once,
        then each span lookup is O(1).
        """
        if not spans:
            return []

        # Collect all unique offsets we need
        offsets_needed: set = set()
        for s, e, _cat in spans:
            offsets_needed.add(s)
            offsets_needed.add(e)
        sorted_offsets = sorted(offsets_needed)
        offset_map: dict = {}

        line = 1
        col = 0
        oi = 0
        length = len(text)
        for idx in range(length + 1):
            while oi < len(sorted_offsets) and sorted_offsets[oi] == idx:
                offset_map[idx] = f"{line}.{col}"
                oi += 1
            if oi >= len(sorted_offsets):
                break
            if idx < length and text[idx] == "\n":
                line += 1
                col = 0
            else:
                col += 1

        result = []
        for s, e, _cat in spans:
            s_str = offset_map.get(s)
            e_str = offset_map.get(e)
            if s_str and e_str:
                result.append((s_str, e_str))
        return result

    def _render_review_tree_placeholder(self, message: str = "Parse text to populate IOC rows"):
        """Show a simple placeholder row in the IOC Review tree."""
        tree = self._review_tree
        tree.delete(*tree.get_children())
        self._review_tree_nodes_by_ioc.clear()
        self._review_tree_status.clear()
        tree.insert(
            "",
            "end",
            text="Ready",
            values=(message, "", "", "", ""),
            tags=("muted",),
            open=True,
        )
        self._output["review_tree_sel_var"].set("0 selected")

    def _render_review_tree_from_found_iocs(self):
        """Render the structured IOC Treeview from ``self.found_iocs``."""
        tree = self._review_tree
        tree.delete(*tree.get_children())
        self._review_tree_nodes_by_ioc.clear()

        if not self.found_iocs:
            self._render_review_tree_placeholder()
            return

        for category, items in self.found_iocs.items():
            parent_id = tree.insert(
                "",
                "end",
                text=category,
                values=("", len(items), "", "", self._review_tree_source_label),
                tags=("category",),
                open=True,
            )
            for ioc in items:
                status = self._review_tree_status.get(ioc, "")
                row_id = tree.insert(
                    parent_id,
                    "end",
                    text=category,
                    values=(ioc, 1, "", status, self._review_tree_source_label),
                    tags=("ioc_row",),
                )
                self._review_tree_nodes_by_ioc.setdefault(ioc, []).append(row_id)

        self._refresh_review_tree_selection_markers()

    def _refresh_review_tree_selection_markers(self):
        """Refresh the Treeview 'Selected' column and selection count label."""
        tree = self._review_tree
        selected_iids = set(tree.selection())
        selected_ioc_rows = 0
        for parent in tree.get_children(""):
            for child in tree.get_children(parent):
                is_selected = child in selected_iids
                if is_selected:
                    selected_ioc_rows += 1
                try:
                    tree.set(child, "selected", "Yes" if is_selected else "")
                except tk.TclError:
                    pass
        self._output["review_tree_sel_var"].set(f"{selected_ioc_rows} selected")

    def _review_tree_get_selected_iocs(self) -> list[str]:
        """Return unique IOC values from selected Treeview rows."""
        tree = self._review_tree
        selected_iids = tree.selection()
        if not selected_iids:
            return []

        values: list[str] = []
        seen: set[str] = set()
        for iid in selected_iids:
            # Category row: include all children.
            if tree.parent(iid) == "":
                for child in tree.get_children(iid):
                    ioc_val = str(tree.set(child, "ioc")).strip()
                    if ioc_val and ioc_val not in seen:
                        seen.add(ioc_val)
                        values.append(ioc_val)
                continue

            ioc_val = str(tree.set(iid, "ioc")).strip()
            if ioc_val and ioc_val not in seen:
                seen.add(ioc_val)
                values.append(ioc_val)
        return values

    def _review_tree_set_status_for_iocs(self, iocs: list[str], status: str):
        """Update the review tree Status column for matching IOC rows."""
        if not iocs:
            return
        for ioc in iocs:
            self._review_tree_status[ioc] = status
            for iid in self._review_tree_nodes_by_ioc.get(ioc, []):
                try:
                    self._review_tree.set(iid, "status", status)
                except tk.TclError:
                    pass

    def _on_review_tree_select(self, _event=None):
        self._refresh_review_tree_selection_markers()

    def _on_review_tree_double_click(self, _event=None):
        tree = self._review_tree
        focused = tree.focus()
        if not focused:
            return
        if tree.parent(focused) == "":
            tree.item(focused, open=not bool(tree.item(focused, "open")))
            return
        ioc_val = str(tree.set(focused, "ioc")).strip()
        if not ioc_val:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(ioc_val)
            self._notify("IOC copied to clipboard", level="success")
        except Exception:
            pass

    def _review_tree_select_all_iocs(self):
        tree = self._review_tree
        iids: list[str] = []
        for parent in tree.get_children(""):
            iids.extend(tree.get_children(parent))
        if iids:
            tree.selection_set(iids)
            self._refresh_review_tree_selection_markers()

    def _review_tree_clear_selection(self):
        self._review_tree.selection_remove(self._review_tree.selection())
        self._refresh_review_tree_selection_markers()

    def _copy_selected_review_iocs(self):
        iocs = self._review_tree_get_selected_iocs()
        if not iocs:
            messagebox.showwarning("Selection Error", "No IOC rows selected.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(iocs))
            self._set_status(f"Copied {len(iocs)} IOC rows")
            self._notify(
                f"Copied {len(iocs)} IOC row{'s' if len(iocs) != 1 else ''}",
                level="success",
            )
        except Exception as exc:
            messagebox.showerror("Clipboard Error", f"Failed to copy:\n{exc}")

    # ==================================================================
    # IOC History (SQLite)
    # ==================================================================

    def _open_history_tab(self):
        """Select the IOC History tab and refresh its query results."""
        try:
            for tab_id in self._notebook.tabs():
                text = str(self._notebook.tab(tab_id, "text"))
                if "History" in text:
                    self._notebook.select(tab_id)
                    break
        except Exception:
            pass
        self._refresh_history_tab()

    def _toggle_history_bottom_pane(self, pane: str):
        """
        Toggle maximize/restore for the IOC History lower split panes.

        pane: "entries" or "details"
        """
        bottom = self._output.get("history_bottom_split")
        entries_frame = self._output.get("history_entries_frame")
        details_frame = self._output.get("history_detail_frame")
        entries_btn = self._output.get("history_toggle_entries_btn")
        details_btn = self._output.get("history_toggle_details_btn")
        if not all((bottom, entries_frame, details_frame, entries_btn, details_btn)):
            return

        if self._history_bottom_maximized_pane == pane:
            # Restore both lower panes
            self._history_bottom_maximized_pane = None
            try:
                bottom.forget(entries_frame)
            except tk.TclError:
                pass
            try:
                bottom.forget(details_frame)
            except tk.TclError:
                pass
            bottom.add(entries_frame, stretch="always")
            bottom.add(details_frame, stretch="always")
            entries_btn.configure(text="Maximize")
            details_btn.configure(text="Maximize")
            return

        self._history_bottom_maximized_pane = pane
        if pane == "entries":
            try:
                bottom.forget(details_frame)
            except tk.TclError:
                pass
            entries_btn.configure(text="Restore")
            details_btn.configure(text="Maximize")
        else:
            try:
                bottom.forget(entries_frame)
            except tk.TclError:
                pass
            details_btn.configure(text="Restore")
            entries_btn.configure(text="Maximize")

    def _render_history_placeholder(self, message: str = "Search or save parsed IOCs to build history"):
        col_tree = self._output.get("history_collections_tree")
        entry_tree = self._output.get("history_entries_tree")
        details = self._output.get("history_details_text")
        if col_tree is None or entry_tree is None or details is None:
            return

        try:
            col_tree.delete(*col_tree.get_children())
            entry_tree.delete(*entry_tree.get_children())
        except Exception:
            return

        self._history_collection_nodes.clear()
        col_tree.insert(
            "",
            "end",
            text="History",
            values=(message, "", "", "", ""),
            tags=("muted",),
        )
        details.configure(state="normal")
        details.delete("1.0", tk.END)
        details.insert(
            tk.END,
            "IOC History\n\n"
            "Use 'Save to History' from the IOC Review Save menu (or button) to store "
            "parsed IOC sets with a collection name. Click a collection above to see "
            "all saved IOCs for that collection below.",
        )
        details.configure(state="disabled")
        self._output["history_count_var"].set("History: 0 collections")

    @staticmethod
    def _format_history_timestamp(ts: str) -> str:
        raw = str(ts or "").strip()
        if not raw:
            return ""
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                continue
        return raw.replace("T", " ")[:16]

    def _clear_history_search(self):
        try:
            self._output["history_search_entry"].delete(0, tk.END)
        except Exception:
            pass
        self._refresh_history_tab("")

    def _search_history(self):
        try:
            query = self._output["history_search_entry"].get().strip()
        except Exception:
            query = ""
        self._refresh_history_tab(query)

    def _refresh_history_tab(self, query: str | None = None):
        """Refresh the IOC History collection list from SQLite."""
        tree = self._output.get("history_collections_tree")
        if tree is None:
            return

        if self.history_db is None:
            self._render_history_placeholder("Database unavailable")
            if self._history_db_error:
                self._set_status("IOC History unavailable")
            return

        if query is None:
            try:
                query = self._output["history_search_entry"].get().strip()
            except Exception:
                query = ""
        query = str(query or "").strip()
        self._history_last_query = query

        try:
            rows = self.history_db.search_collections(query=query, limit=500)
        except Exception as exc:
            messagebox.showerror("History Error", f"Failed to query IOC history:\n{exc}")
            return

        tree.delete(*tree.get_children())
        self._history_collection_nodes.clear()

        if not rows:
            msg = "No history matches" if query else "No saved IOC history yet"
            tree.insert(
                "",
                "end",
                text="History",
                values=(msg, "", "", "", ""),
                tags=("muted",),
            )
            self._output["history_count_var"].set("History: 0 collections")
            entry_tree = self._output.get("history_entries_tree")
            if entry_tree is not None:
                entry_tree.delete(*entry_tree.get_children())
            details = self._output.get("history_details_text")
            if details is not None:
                details.configure(state="normal")
                details.delete("1.0", tk.END)
                details.insert(
                    tk.END,
                    "No matching IOC history collections.\n\n"
                    "Search by collection name (and also malware/group name, notes, "
                    "IOC value, or category). Click a collection result to see all "
                    "IOCs saved under it below.",
                )
                details.configure(state="disabled")
            return

        for row in rows:
            threat_context = str(row.get("threat_context") or "")
            iid = tree.insert(
                "",
                "end",
                text=str(row.get("collection_name") or "(unnamed)"),
                values=(
                    threat_context,
                    row.get("total_iocs", 0),
                    row.get("category_count", 0),
                    self._format_history_timestamp(str(row.get("created_at") or "")),
                    str(row.get("source_label") or "Parser"),
                ),
            )
            self._history_collection_nodes[iid] = int(row["id"])

        label = "matches" if query else "collections"
        self._output["history_count_var"].set(f"History: {len(rows)} {label}")
        self._set_status(
            f"IOC History: {len(rows)} {'match' if len(rows) == 1 else 'matches'}"
            if query else
            f"IOC History: loaded {len(rows)} collection{'s' if len(rows) != 1 else ''}"
        )

        first = tree.get_children("")
        if first:
            tree.selection_set(first[0])
            tree.focus(first[0])
            self._on_history_collection_select()

    def _history_selected_collection_id(self) -> int | None:
        tree = self._output.get("history_collections_tree")
        if tree is None:
            return None
        sel = tree.selection()
        if not sel:
            return None
        return self._history_collection_nodes.get(sel[0])

    def _on_history_collection_select(self, _event=None):
        cid = self._history_selected_collection_id()
        entries_tree = self._output.get("history_entries_tree")
        details = self._output.get("history_details_text")
        if entries_tree is None or details is None:
            return

        entries_tree.delete(*entries_tree.get_children())
        details.configure(state="normal")
        details.delete("1.0", tk.END)

        if cid is None or self.history_db is None:
            details.insert(tk.END, "Select a saved IOC collection to view details.")
            details.configure(state="disabled")
            return

        try:
            data = self.history_db.get_collection(cid)
        except Exception as exc:
            details.insert(tk.END, f"Failed to load collection details:\n{exc}", "error")
            details.configure(state="disabled")
            return

        if not data:
            details.insert(tk.END, "Selected collection was not found.", "error")
            details.configure(state="disabled")
            return

        category_nodes: dict[str, str] = {}
        category_counts: dict[str, int] = {}
        for entry in data.get("entries", []):
            category = str(entry.get("category") or "").strip() or "Uncategorized"
            value = str(entry.get("value") or "")
            normalized = str(entry.get("normalized_value") or "")
            source = str(entry.get("source") or "")

            parent_iid = category_nodes.get(category)
            if parent_iid is None:
                parent_iid = entries_tree.insert(
                    "",
                    "end",
                    text=category,
                    values=("", "", ""),
                    open=True,
                    tags=("category",),
                )
                category_nodes[category] = parent_iid
                category_counts[category] = 0

            entries_tree.insert(
                parent_iid,
                "end",
                text="",
                values=(value, normalized, source),
            )
            category_counts[category] = category_counts.get(category, 0) + 1

        for category, parent_iid in category_nodes.items():
            count = category_counts.get(category, 0)
            try:
                entries_tree.set(parent_iid, "ioc", f"{count} IOC{'s' if count != 1 else ''}")
            except tk.TclError:
                pass

        details_lines = [
            f"Collection: {data.get('collection_name', '')}",
            f"Threat/Malware/Group: {data.get('threat_context', '') or '-'}",
            f"Saved: {self._format_history_timestamp(str(data.get('created_at') or ''))}",
            f"Source: {data.get('source_label', 'Parser')}",
            f"IOCs: {data.get('total_iocs', 0)}",
            f"Categories: {data.get('category_count', 0)}",
            "",
            "Notes:",
            str(data.get("notes") or "(none)"),
        ]
        details.insert(tk.END, "\n".join(details_lines))
        details.configure(state="disabled")
        self._set_status(
            f"IOC History: showing {len(data.get('entries', []))} IOC"
            f"{'s' if len(data.get('entries', [])) != 1 else ''} for "
            f"{data.get('collection_name', '')}"
        )

    def _copy_selected_history_iocs(self):
        entries_tree = self._output.get("history_entries_tree")
        if entries_tree is None:
            return
        selected = entries_tree.selection()
        values: list[str] = []
        if selected:
            for iid in selected:
                if entries_tree.parent(iid) == "":
                    for child in entries_tree.get_children(iid):
                        val = str(entries_tree.set(child, "ioc")).strip()
                        if val:
                            values.append(val)
                    continue
                val = str(entries_tree.set(iid, "ioc")).strip()
                if val:
                    values.append(val)
        else:
            for parent_iid in entries_tree.get_children(""):
                for child in entries_tree.get_children(parent_iid):
                    val = str(entries_tree.set(child, "ioc")).strip()
                    if val:
                        values.append(val)

        # de-duplicate while preserving order
        deduped: list[str] = []
        seen: set[str] = set()
        for v in values:
            if v in seen:
                continue
            seen.add(v)
            deduped.append(v)

        if not deduped:
            messagebox.showwarning("History", "No IOC rows available to copy.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(deduped))
            self._set_status(f"Copied {len(deduped)} history IOC rows")
            self._notify(
                f"Copied {len(deduped)} IOC{'s' if len(deduped) != 1 else ''} from history",
                level="success",
            )
        except Exception as exc:
            messagebox.showerror("Clipboard Error", f"Failed to copy:\n{exc}")

    def _load_selected_history_collection_into_review(self):
        cid = self._history_selected_collection_id()
        if cid is None:
            messagebox.showwarning("History", "Select a saved IOC collection first.")
            return
        if self.history_db is None:
            messagebox.showerror(
                "History Error",
                "IOC History database is unavailable in this session.",
            )
            return
        try:
            data = self.history_db.get_collection(cid)
        except Exception as exc:
            messagebox.showerror("History Error", f"Failed to load collection:\n{exc}")
            return
        if not data:
            messagebox.showwarning("History", "Selected collection not found.")
            return

        ioc_map = data.get("ioc_map")
        if not isinstance(ioc_map, dict) or not ioc_map:
            messagebox.showwarning("History", "Selected collection has no IOC rows.")
            return

        self.found_iocs = {
            str(k): list(v)
            for k, v in ioc_map.items()
            if isinstance(k, str) and isinstance(v, list)
        }
        self._review_tree_status.clear()
        self._review_tree_source_label = "History"
        self._history_loaded_collection_id = cid
        total = self._render_review_from_found_iocs()
        self._set_status(
            f"Loaded history collection '{data.get('collection_name', '')}' "
            f"({total} IOCs)"
        )
        self._notify(
            f"Loaded history collection: {data.get('collection_name', '')}",
            level="success",
        )
        self._notebook.select(0)

    def _suggest_history_collection_name(self) -> str:
        """Generate a default collection name from input text + timestamp."""
        try:
            raw_text = self._get_input_text() or ""
        except Exception:
            raw_text = ""
        first_line = ""
        for line in raw_text.splitlines():
            line = line.strip()
            if line:
                first_line = line
                break
        first_line = re.sub(r"\s+", " ", first_line)[:48].strip()
        stamp = datetime.now().strftime("%Y-%m-%d %H%M")
        if first_line:
            return f"{first_line} ({stamp})"
        return f"Parsed IOC Set ({stamp})"

    def _prompt_ioc_history_save_metadata(self, auto_prompt: bool = False) -> dict | None:
        """Prompt for the collection name/metadata required before DB save."""
        dlg = tk.Toplevel(self)
        dlg.title("Save Parsed IOCs to History")
        dlg.transient(self)
        dlg.configure(bg=COLORS["bg_primary"])
        dlg.resizable(True, False)
        dlg.grab_set()
        dlg.geometry("620x360")

        outer = tk.Frame(dlg, bg=COLORS["bg_primary"], padx=12, pady=12)
        outer.pack(expand=True, fill="both")

        tk.Label(
            outer,
            text="Name this IOC collection before saving",
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_heading"],
            font=FONTS["button"],
        ).grid(row=0, column=0, columnspan=2, sticky="w")

        tk.Label(
            outer,
            text=(
                "Use a label you can search later (malware family, threat group, "
                "campaign, incident ticket, or sample name)."
            ),
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            font=FONTS["label"],
            justify="left",
            wraplength=580,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 10))

        name_var = tk.StringVar(value=self._suggest_history_collection_name())
        threat_var = tk.StringVar()

        def _entry(parent, textvariable, width=44):
            return tk.Entry(
                parent,
                textvariable=textvariable,
                width=width,
                bg=COLORS["bg_entry"],
                fg=COLORS["fg_primary"],
                insertbackground=COLORS["fg_primary"],
                relief="flat",
                bd=0,
                font=FONTS["body"],
            )

        tk.Label(
            outer, text="Collection Name *",
            bg=COLORS["bg_primary"], fg=COLORS["fg_secondary"], font=FONTS["label"]
        ).grid(row=2, column=0, sticky="w", pady=(0, 4))
        name_entry = _entry(outer, name_var)
        name_entry.grid(row=3, column=0, columnspan=2, sticky="ew", ipady=4)

        tk.Label(
            outer, text="Threat / Malware / Group (optional)",
            bg=COLORS["bg_primary"], fg=COLORS["fg_secondary"], font=FONTS["label"]
        ).grid(row=4, column=0, sticky="w", pady=(10, 4))
        threat_entry = _entry(outer, threat_var)
        threat_entry.grid(row=5, column=0, columnspan=2, sticky="ew", ipady=4)

        tk.Label(
            outer, text="Notes (optional)",
            bg=COLORS["bg_primary"], fg=COLORS["fg_secondary"], font=FONTS["label"]
        ).grid(row=6, column=0, sticky="w", pady=(10, 4))
        notes_text = tk.Text(
            outer,
            height=5,
            wrap=tk.WORD,
            bg=COLORS["bg_output"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            relief="flat",
            bd=0,
            font=FONTS["body"],
            padx=8,
            pady=6,
        )
        notes_text.grid(row=7, column=0, columnspan=2, sticky="nsew")

        btns = tk.Frame(outer, bg=COLORS["bg_primary"])
        btns.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        result: dict | None = None

        def _cancel():
            dlg.destroy()

        def _save():
            nonlocal result
            name = name_var.get().strip()
            threat_context = threat_var.get().strip()
            notes = notes_text.get("1.0", "end-1c").strip()
            if not name:
                messagebox.showwarning(
                    "History Save",
                    "Collection name is required before saving to the history database.",
                    parent=dlg,
                )
                name_entry.focus_set()
                return
            result = {
                "collection_name": name,
                "threat_context": threat_context,
                "notes": notes,
            }
            dlg.destroy()

        cancel_label = "Skip" if auto_prompt else "Cancel"
        tk.Button(
            btns, text=cancel_label,
            command=_cancel,
            relief="flat", bd=0,
            bg=COLORS["slate"], fg=COLORS["btn_fg"],
            activebackground=COLORS["slate_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["label"], padx=12, pady=5,
        ).pack(side="right")
        tk.Button(
            btns, text="Save to History",
            command=_save,
            relief="flat", bd=0,
            bg=COLORS["teal"], fg=COLORS["btn_fg"],
            activebackground=COLORS["teal_hover"], activeforeground=COLORS["btn_fg"],
            font=FONTS["button"], padx=12, pady=5,
        ).pack(side="right", padx=(0, 8))

        outer.grid_columnconfigure(0, weight=1)
        outer.grid_columnconfigure(1, weight=1)
        outer.grid_rowconfigure(7, weight=1)

        dlg.bind("<Escape>", lambda _e: _cancel())
        dlg.bind("<Return>", lambda _e: _save())
        dlg.wait_visibility()
        name_entry.focus_set()
        name_entry.selection_range(0, tk.END)
        dlg.wait_window()
        return result

    def _save_current_iocs_to_history(self):
        """Save current parsed IOC state to the SQLite history database."""
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No parsed IOCs to save. Parse first.")
            return
        if self.history_db is None:
            messagebox.showerror(
                "History Error",
                "IOC History database is unavailable.\n"
                f"{self._history_db_error or ''}".strip(),
            )
            return

        meta = self._prompt_ioc_history_save_metadata(auto_prompt=False)
        if not meta:
            return

        try:
            saved = self.history_db.save_collection(
                collection_name=meta["collection_name"],
                threat_context=meta.get("threat_context", ""),
                notes=meta.get("notes", ""),
                ioc_map=self.found_iocs,
                source_label=self._review_tree_source_label,
            )
        except Exception as exc:
            messagebox.showerror("History Save Error", f"Failed to save IOC history:\n{exc}")
            return

        self._set_status(
            f"History saved: {saved.collection_name} ({saved.total_iocs} IOCs)"
        )
        self._notify(
            f"Saved to IOC History: {saved.collection_name}",
            level="success",
            duration_ms=3000,
        )
        self._refresh_history_tab(self._history_last_query if self._history_last_query else "")

    def _maybe_prompt_save_parsed_iocs_to_history(self, total_iocs: int):
        """After parsing, offer to save the parsed IOC set with a searchable name."""
        if total_iocs <= 0 or not self.found_iocs or self.history_db is None:
            return

        try:
            should_save = messagebox.askyesno(
                "Save Parsed IOCs to History?",
                "Parsed IOC results are ready.\n\n"
                "Would you like to save this IOC set to the local SQLite history "
                "database so you can search it later by malware/threat-group name?",
                default=messagebox.YES,
            )
        except Exception:
            should_save = False

        if not should_save:
            return

        meta = self._prompt_ioc_history_save_metadata(auto_prompt=True)
        if not meta:
            self._set_status("History save skipped")
            return

        try:
            saved = self.history_db.save_collection(
                collection_name=meta["collection_name"],
                threat_context=meta.get("threat_context", ""),
                notes=meta.get("notes", ""),
                ioc_map=self.found_iocs,
                source_label="Parser",
            )
        except Exception as exc:
            messagebox.showerror("History Save Error", f"Failed to save IOC history:\n{exc}")
            return

        self._set_status(
            f"Parsed IOCs saved to history: {saved.collection_name} ({saved.total_iocs})"
        )
        self._notify(
            f"Saved parsed IOCs to history: {saved.collection_name}",
            level="success",
            duration_ms=3000,
        )
        self._refresh_history_tab(self._history_last_query if self._history_last_query else "")

    def _render_review_from_found_iocs(self) -> int:
        """
        Rebuild the IOC Review pane from ``self.found_iocs`` state.

        Returns the total IOC count rendered.
        """
        out = self._review_output
        out.configure(state="normal")
        out.delete("1.0", tk.END)

        if not self.found_iocs:
            out.insert(tk.END, IOC_REVIEW_HELP)
            self._render_review_tree_placeholder()
            self._set_summary("")
            return 0

        self._render_review_tree_from_found_iocs()

        output_text, tag_ranges, total = IOCExtractorApp._build_review_output(
            self.found_iocs
        )
        if not output_text:
            out.insert(tk.END, "No IOCs found matching the defined patterns.")
            self._set_summary("")
            return 0

        out.insert(tk.END, output_text)
        for tag, start_idx, end_idx in tag_ranges:
            try:
                out.tag_add(tag, start_idx, end_idx)
            except tk.TclError:
                pass

        self._set_summary(file_operations.format_ioc_summary(self.found_iocs))
        return total

    def _defang_iocs(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No IOCs to defang. Parse first.")
            return
        self.found_iocs = ioc_parser.defang_ioc_map(self.found_iocs)
        self._review_tree_status.clear()
        total = self._render_review_from_found_iocs()
        self._set_status(f"IOCs defanged ({total} total)")

    def _refang_iocs(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No IOCs to refang. Parse first.")
            return
        self.found_iocs = ioc_parser.refang_ioc_map(self.found_iocs)
        self._review_tree_status.clear()
        total = self._render_review_from_found_iocs()
        self._set_status(f"IOCs refanged ({total} total)")

    # ==================================================================
    # VirusTotal (threaded)
    # ==================================================================

    def _get_vt_api_key(self) -> str | None:
        # 1. Already loaded this session
        if self.vt_api_key:
            return self.vt_api_key

        # 2. Try loading from secure storage (macOS Keychain / keyring)
        stored = keychain.load_api_key()
        if stored:
            self.vt_api_key = stored
            return self.vt_api_key

        # 3. Prompt user
        key = simpledialog.askstring(
            "API Key Required",
            "Enter your VirusTotal API Key:\n"
            "(will be stored securely in your system keychain)",
            show="*",
        )
        if key:
            self.vt_api_key = key.strip()
            if not self.vt_api_key:
                messagebox.showerror("API Key Missing", "Key was empty.")
                self.vt_api_key = None
                return None
            # Store in keychain for persistence
            if keychain.store_api_key(self.vt_api_key):
                self._set_status("API key saved to system keychain")
            else:
                self._set_status("API key loaded (secure storage unavailable)")
        else:
            messagebox.showerror("API Key Missing", "VT API Key is required.")
            return None
        return self.vt_api_key

    def _clear_vt_api_key(self):
        """Remove the stored VT API key from keychain and memory."""
        keychain.delete_api_key()
        self.vt_api_key = None
        self._set_status("VT API key cleared from keychain")
        self._notify("VirusTotal API key removed from keychain and memory.", level="success")

    def _get_selection_from_active_tab(self) -> tuple:
        """Return (selected_text, source_tab_name) or (None, error_msg)."""
        try:
            sel = self._notebook.select()
            if not sel:
                return None, "No tab selected."
            idx = self._notebook.index(sel)

            widget_map = {
                0: (self._review_output, "IOC Review"),
                2: (self._jsluice_output, "Jsluice Analysis"),
            }
            if idx not in widget_map:
                return (
                    None,
                    "Please select text in the 'IOC Review' or 'Jsluice' tab.",
                )

            widget, name = widget_map[idx]
            if idx == 0:
                selected_iocs = self._review_tree_get_selected_iocs()
                if selected_iocs:
                    return "\n".join(selected_iocs), name
            try:
                text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                return text, name
            except tk.TclError:
                if idx == 0:
                    return None, (
                        "Select IOC rows in the table (top pane) or highlight text "
                        "in the review text pane."
                    )
                return None, "Please select text in the active tab first."

        except Exception as exc:
            return None, f"Error getting selection: {exc}"

    def _prepare_vt_iocs_for_submission(
        self,
        iocs: list[str],
        action_label: str = "VirusTotal",
    ) -> list[tuple[str, str]]:
        """
        Auto-refang IOC values for VT actions while preserving display values.

        Returns ``[(original_value, vt_value), ...]`` so callers can display the
        original selection while sending refanged values to VirusTotal.
        """
        if not iocs:
            return []

        prepared: list[tuple[str, str]] = []
        changed_originals: list[str] = []
        for original in iocs:
            vt_value = ioc_parser.refang_text(original)
            prepared.append((original, vt_value))
            if vt_value != original:
                changed_originals.append(original)

        if changed_originals:
            try:
                if self._notebook.index(self._notebook.select()) == 0:
                    self._review_tree_set_status_for_iocs(changed_originals, "Auto-refanged")
            except Exception:
                pass
            self._set_status(
                f"{action_label}: auto-refanged {len(changed_originals)} IOC"
                f"{'s' if len(changed_originals) != 1 else ''}"
            )
            self._notify(
                f"Auto-refanged {len(changed_originals)} selected IOC"
                f"{'s' if len(changed_originals) != 1 else ''} for {action_label}.",
                level="info",
                duration_ms=3200,
            )

        return prepared

    def _vt_guard(self) -> bool:
        if self._vt_running:
            messagebox.showwarning(
                "VT Busy",
                "A VirusTotal operation is already in progress.\n"
                "Please wait for it to complete."
            )
            return False
        return True

    def _run_vt_threaded(self, target, label="VirusTotal"):
        if not self._vt_guard():
            return
        self._vt_running = True
        self._set_status(f"{label}: starting...")
        if not self._status["progress_detail_var"].get():
            self._set_busy_progress(label)

        def _wrapper():
            error_msg = None
            try:
                target()
            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}"
            finally:
                self._vt_running = False
                self.after(0, self._clear_progress)
                if error_msg is not None:
                    self.after(0, lambda: self._set_status(f"{label} failed"))
                    self.after(
                        0,
                        lambda: messagebox.showerror(
                            f"{label} Error",
                            f"Unexpected error while running {label}:\n{error_msg}",
                        ),
                    )

        threading.Thread(target=_wrapper, daemon=True).start()

    def _on_vt_check(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        iocs = [line.strip() for line in selected.splitlines() if line.strip()]
        if not iocs:
            messagebox.showwarning("Selection Error", "No valid IOCs selected.")
            return
        prepared_iocs = self._prepare_vt_iocs_for_submission(iocs, "VT Check")
        try:
            from_review_tab = self._notebook.index(self._notebook.select()) == 0
        except Exception:
            from_review_tab = False
        if from_review_tab:
            self._review_tree_set_status_for_iocs(
                [orig for orig, _vt_val in prepared_iocs], "Queued"
            )

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ VT Check — 0/{len(iocs)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._set_progress(0, len(prepared_iocs), f"VT Check 0/{len(prepared_iocs)}")
        self._notebook.select(1)

        def _work():
            total = len(prepared_iocs)
            for i, (ioc_display, ioc_query) in enumerate(prepared_iocs, 1):
                # Update status bar and progress header
                def _update_progress(idx=i, ioc_val=ioc_display):
                    self._set_status(f"VT Check: {idx}/{total} — {ioc_val}")
                    self._set_progress(idx - 1, total, f"VT Check {idx - 1}/{total}")
                    if from_review_tab:
                        self._review_tree_set_status_for_iocs([ioc_val], "Checking")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ VT Check — {idx - 1}/{total} complete  |  checking: {ioc_val}",
                        "bold",
                    )
                self.after(0, _update_progress)

                def _progress_cb(msg, ioc_val=ioc_display):
                    def _inner():
                        self._set_status(msg)
                        self._vt_output.delete("1.0", "1.end")
                        self._vt_output.insert(
                            "1.0",
                            f"⏳ VT Check — rate limited, waiting...  |  next: {ioc_val}",
                            "bold",
                        )
                    self.after(0, _inner)

                result = vt.query_ioc(api_key, ioc_query, progress_callback=_progress_cb)

                def _update(ioc_val=ioc_display, result_val=result, idx=i, tot=total):
                    self._vt_output.insert(tk.END, ioc_val + ":\n", "bold")
                    insert_with_links(self._vt_output, result_val + "\n\n")
                    if from_review_tab:
                        self._review_tree_set_status_for_iocs([ioc_val], "Done")
                    self._set_progress(idx, tot, f"VT Check {idx}/{tot}")
                    # Update progress header
                    self._vt_output.delete("1.0", "1.end")
                    if idx < tot:
                        self._vt_output.insert(
                            "1.0",
                            f"⏳ VT Check — {idx}/{tot} complete",
                            "bold",
                        )
                    else:
                        self._vt_output.insert(
                            "1.0",
                            f"✅ VT Check — {tot}/{tot} complete",
                            "bold",
                        )
                    self._vt_output.see(tk.END)

                self.after(0, _update)

            self.after(0, lambda: self._set_status(
                f"VT Check complete — {len(iocs)} IOC{'s' if len(iocs) != 1 else ''} checked"
            ))

        self._run_vt_threaded(_work, "VT Check")

    def _submit_url_for_analysis(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        urls = [u.strip() for u in selected.splitlines() if u.strip()]
        if not urls:
            messagebox.showwarning("Selection Error", "No valid URLs selected.")
            return
        prepared_urls = self._prepare_vt_iocs_for_submission(urls, "VT Submit")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ VT Submit — 0/{len(urls)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        def _work():
            total = len(prepared_urls)
            for i, (url_display, url_query) in enumerate(prepared_urls, 1):
                def _update_progress(idx=i, url_val=url_display):
                    self._set_status(f"VT Submit: {idx}/{total} — {url_val}")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ VT Submit — {idx - 1}/{total} complete  |  submitting: {url_val}",
                        "bold",
                    )
                self.after(0, _update_progress)

                if vt.is_url(url_query):
                    result = vt.submit_url(api_key, url_query)

                    def _update_result(r=result, url_val=url_display, idx=i, tot=total):
                        self._vt_output.insert(tk.END, f"URL {url_val}:\n", "bold")
                        if r["success"]:
                            insert_with_links(
                                self._vt_output,
                                f"{r['message']}\nCheck Report: {r.get('report_link', 'N/A')}\n\n",
                            )
                        else:
                            self._vt_output.insert(
                                tk.END, f"{r['message']}\n\n", "error"
                            )
                        # Update progress header
                        self._vt_output.delete("1.0", "1.end")
                        if idx < tot:
                            self._vt_output.insert(
                                "1.0",
                                f"⏳ VT Submit — {idx}/{tot} complete",
                                "bold",
                            )
                        else:
                            self._vt_output.insert(
                                "1.0",
                                f"✅ VT Submit — {tot}/{tot} complete",
                                "bold",
                            )
                        self._vt_output.see(tk.END)
                    self.after(0, _update_result)
                else:
                    def _update_skip(u=url_display, idx=i, tot=total):
                        self._vt_output.insert(
                            tk.END, f"Skipping non-URL: {u}\n\n", "error"
                        )
                        self._vt_output.delete("1.0", "1.end")
                        if idx < tot:
                            self._vt_output.insert(
                                "1.0",
                                f"⏳ VT Submit — {idx}/{tot} complete",
                                "bold",
                            )
                        else:
                            self._vt_output.insert(
                                "1.0",
                                f"✅ VT Submit — {tot}/{tot} complete",
                                "bold",
                            )
                        self._vt_output.see(tk.END)
                    self.after(0, _update_skip)

            self.after(0, lambda: self._set_status(f"VT Submit complete — {len(urls)} URLs"))

        self._run_vt_threaded(_work, "VT Submit")

    def _get_all_hash_details(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        hashes = [h.strip() for h in selected.splitlines() if h.strip()]
        if not hashes:
            messagebox.showwarning("Selection Error", "No valid hashes selected.")
            return
        prepared_hashes = self._prepare_vt_iocs_for_submission(hashes, "Hash Details")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ Hash Details — 0/{len(hashes)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        def _work():
            total = len(prepared_hashes)
            for i, (hash_display, hash_query) in enumerate(prepared_hashes, 1):
                def _update_progress(idx=i, hash_val=hash_display):
                    self._set_status(f"Hash Details: {idx}/{total} — {hash_val[:16]}...")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ Hash Details — {idx - 1}/{total} complete  |  checking: {hash_val[:24]}...",
                        "bold",
                    )
                self.after(0, _update_progress)

                if vt.is_hash(hash_query):
                    details = vt.get_hash_details(api_key, hash_query)

                    def _update(hash_val=hash_display, d=details, idx=i, tot=total):
                        self._vt_output.insert(tk.END, f"Input Hash: {hash_val}\n", "bold")
                        if "error" not in d:
                            self._vt_output.insert(
                                tk.END,
                                f"  MD5:    {d.get('md5', 'N/A')}\n"
                                f"  SHA-1:  {d.get('sha1', 'N/A')}\n"
                                f"  SHA-256:{d.get('sha256', 'N/A')}\n\n",
                            )
                        else:
                            self._vt_output.insert(
                                tk.END, f"  Error: {d['error']}\n\n", "error"
                            )
                        # Update progress header
                        self._vt_output.delete("1.0", "1.end")
                        if idx < tot:
                            self._vt_output.insert(
                                "1.0",
                                f"⏳ Hash Details — {idx}/{tot} complete",
                                "bold",
                            )
                        else:
                            self._vt_output.insert(
                                "1.0",
                                f"✅ Hash Details — {tot}/{tot} complete",
                                "bold",
                            )
                        self._vt_output.see(tk.END)
                    self.after(0, _update)
                elif hash_display:
                    def _skip(hash_val=hash_display, idx=i, tot=total):
                        self._vt_output.insert(
                            tk.END, f"Skipping invalid hash: {hash_val}\n\n", "error"
                        )
                        self._vt_output.delete("1.0", "1.end")
                        self._vt_output.insert(
                            "1.0",
                            f"⏳ Hash Details — {idx}/{tot} complete",
                            "bold",
                        )
                        self._vt_output.see(tk.END)
                    self.after(0, _skip)

            self.after(0, lambda: self._set_status(f"Hash Details complete — {len(hashes)} hashes"))

        self._run_vt_threaded(_work, "Hash Details")

    def _submit_for_mitre_ttps(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        hashes = [h.strip() for h in selected.splitlines() if h.strip()]
        if not hashes:
            messagebox.showwarning("Selection Error", "No valid hashes selected.")
            return
        prepared_hashes = self._prepare_vt_iocs_for_submission(hashes, "MITRE TTPs")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ MITRE TTPs — 0/{len(hashes)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        def _work():
            total = len(prepared_hashes)
            for i, (hash_display, hash_query) in enumerate(prepared_hashes, 1):
                def _update_progress(idx=i, hash_val=hash_display):
                    self._set_status(f"MITRE TTPs: {idx}/{total} — {hash_val[:16]}...")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ MITRE TTPs — {idx - 1}/{total} complete  |  checking: {hash_val[:24]}...",
                        "bold",
                    )
                self.after(0, _update_progress)

                if vt.is_hash(hash_query):
                    ttps = vt.get_mitre_ttps(api_key, hash_query)

                    def _update(hash_val=hash_display, ttps_val=ttps, idx=i, tot=total):
                        self._vt_output.insert(tk.END, f"Hash: {hash_val}\n", "bold")
                        if isinstance(ttps_val, list):
                            for ttp in ttps_val:
                                insert_with_links(
                                    self._vt_output,
                                    f"  {ttp['id']}: {ttp['name']}\n"
                                )
                                self._vt_output.insert(
                                    tk.END,
                                    f"    Tactics: {', '.join(ttp['tactics'])}\n",
                                )
                                insert_with_links(
                                    self._vt_output,
                                    f"    Link: {ttp['link']}\n"
                                )
                            self._vt_output.insert(tk.END, "\n")
                        elif isinstance(ttps_val, dict) and "error" in ttps_val:
                            self._vt_output.insert(
                                tk.END, f"  Error: {ttps_val['error']}\n\n", "error"
                            )
                        else:
                            self._vt_output.insert(
                                tk.END, "  Unexpected error.\n\n", "error"
                            )
                        # Update progress header
                        self._vt_output.delete("1.0", "1.end")
                        if idx < tot:
                            self._vt_output.insert(
                                "1.0",
                                f"⏳ MITRE TTPs — {idx}/{tot} complete",
                                "bold",
                            )
                        else:
                            self._vt_output.insert(
                                "1.0",
                                f"✅ MITRE TTPs — {tot}/{tot} complete",
                                "bold",
                            )
                        self._vt_output.see(tk.END)
                    self.after(0, _update)
                elif hash_display:
                    def _skip(hash_val=hash_display, idx=i, tot=total):
                        self._vt_output.insert(
                            tk.END, f"Skipping invalid hash: {hash_val}\n\n", "error"
                        )
                        self._vt_output.delete("1.0", "1.end")
                        self._vt_output.insert(
                            "1.0",
                            f"⏳ MITRE TTPs — {idx}/{tot} complete",
                            "bold",
                        )
                        self._vt_output.see(tk.END)
                    self.after(0, _skip)

            self.after(0, lambda: self._set_status(f"MITRE TTPs complete — {len(hashes)} hashes"))

        self._run_vt_threaded(_work, "MITRE TTPs")

    def _get_file_behavior(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        hashes = [h.strip() for h in selected.splitlines() if h.strip()]
        if not hashes:
            messagebox.showwarning("Selection Error", "No valid hashes selected.")
            return
        prepared_hashes = self._prepare_vt_iocs_for_submission(hashes, "Behavior Analysis")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ Behavior Analysis — 0/{len(hashes)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        # Field display names
        _FIELD_LABELS = {
            "processes_created": "Processes Created",
            "command_executions": "Command Executions",
            "files_dropped": "Files Dropped",
            "files_opened": "Files Opened",
            "files_written": "Files Written",
            "registry_keys_set": "Registry Keys Set",
            "registry_keys_opened": "Registry Keys Opened",
            "mutexes_created": "Mutexes Created",
            "dns_lookups": "DNS Lookups",
            "http_conversations": "HTTP Conversations",
            "ip_traffic": "IP Traffic",
            "ja3_digests": "JA3 Digests",
            "services_started": "Services Started",
        }

        def _work():
            total = len(prepared_hashes)
            for i, (hash_display, hash_query) in enumerate(prepared_hashes, 1):
                def _update_progress(idx=i, hash_val=hash_display):
                    self._set_status(f"Behavior: {idx}/{total} — {hash_val[:16]}...")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ Behavior Analysis — {idx - 1}/{total} complete  |  analyzing: {hash_val[:24]}...",
                        "bold",
                    )
                self.after(0, _update_progress)

                if vt.is_hash(hash_query):
                    behavior = vt.get_file_behavior(api_key, hash_query)

                    def _update(hash_val=hash_display, data=behavior, idx=i, tot=total):
                        self._vt_output.insert(tk.END, f"Hash: {hash_val}\n", "bold")
                        if "error" in data:
                            self._vt_output.insert(
                                tk.END, f"  Error: {data['error']}\n\n", "error"
                            )
                        else:
                            for field, label in _FIELD_LABELS.items():
                                items = data.get(field, [])
                                if items:
                                    self._vt_output.insert(
                                        tk.END, f"  {label} ({len(items)}):\n", "bold"
                                    )
                                    for item in items:
                                        if isinstance(item, dict):
                                            # DNS lookups, HTTP convos, IP traffic
                                            parts = []
                                            for k, v in item.items():
                                                parts.append(f"{k}={v}")
                                            self._vt_output.insert(
                                                tk.END, f"    {', '.join(parts)}\n"
                                            )
                                        else:
                                            self._vt_output.insert(
                                                tk.END, f"    {item}\n"
                                            )
                            self._vt_output.insert(tk.END, "\n")
                        # Update progress header
                        self._vt_output.delete("1.0", "1.end")
                        done_label = "⏳" if idx < tot else "✅"
                        self._vt_output.insert(
                            "1.0",
                            f"{done_label} Behavior Analysis — {idx}/{tot} complete",
                            "bold",
                        )
                        self._vt_output.see(tk.END)
                    self.after(0, _update)
                elif hash_display:
                    def _skip(hash_val=hash_display):
                        self._vt_output.insert(
                            tk.END, f"Skipping invalid hash: {hash_val}\n\n", "error"
                        )
                    self.after(0, _skip)

            self.after(0, lambda: self._set_status(f"Behavior complete — {len(hashes)} hashes"))

        self._run_vt_threaded(_work, "Behavior Analysis")

    def _get_resolutions(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        iocs = [line.strip() for line in selected.splitlines() if line.strip()]
        if not iocs:
            messagebox.showwarning("Selection Error", "No valid IOCs selected.")
            return
        prepared_iocs = self._prepare_vt_iocs_for_submission(iocs, "DNS Resolutions")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ DNS Resolutions — 0/{len(iocs)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        def _work():
            total = len(prepared_iocs)
            for i, (ioc_display, ioc_query) in enumerate(prepared_iocs, 1):
                def _update_progress(idx=i, ioc_val=ioc_display):
                    self._set_status(f"Resolutions: {idx}/{total} — {ioc_val}")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ DNS Resolutions — {idx - 1}/{total} complete  |  querying: {ioc_val}",
                        "bold",
                    )
                self.after(0, _update_progress)

                resolutions = vt.get_resolutions(api_key, ioc_query)

                def _update(ioc_val=ioc_display, data=resolutions, idx=i, tot=total):
                    self._vt_output.insert(tk.END, f"{ioc_val}:\n", "bold")
                    if isinstance(data, dict) and "error" in data:
                        self._vt_output.insert(
                            tk.END, f"  {data['error']}\n\n", "error"
                        )
                    elif isinstance(data, list):
                        for entry in data:
                            host = entry.get("host", "")
                            ip = entry.get("ip", "")
                            date = entry.get("date", "")
                            resolver = entry.get("resolver", "")
                            parts = []
                            if host:
                                parts.append(f"Host: {host}")
                            if ip:
                                parts.append(f"IP: {ip}")
                            if date:
                                parts.append(f"Date: {date}")
                            if resolver:
                                parts.append(f"Resolver: {resolver}")
                            self._vt_output.insert(
                                tk.END, f"  {' | '.join(parts)}\n"
                            )
                        self._vt_output.insert(tk.END, "\n")
                    # Update progress header
                    self._vt_output.delete("1.0", "1.end")
                    done_label = "⏳" if idx < tot else "✅"
                    self._vt_output.insert(
                        "1.0",
                        f"{done_label} DNS Resolutions — {idx}/{tot} complete",
                        "bold",
                    )
                    self._vt_output.see(tk.END)
                self.after(0, _update)

            self.after(0, lambda: self._set_status(f"Resolutions complete — {len(iocs)} IOCs"))

        self._run_vt_threaded(_work, "DNS Resolutions")

    def _get_communicating_files(self):
        api_key = self._get_vt_api_key()
        if not api_key:
            return
        selected, err = self._get_selection_from_active_tab()
        if selected is None:
            messagebox.showwarning("Selection Error", err)
            return
        iocs = [line.strip() for line in selected.splitlines() if line.strip()]
        if not iocs:
            messagebox.showwarning("Selection Error", "No valid IOCs selected.")
            return
        prepared_iocs = self._prepare_vt_iocs_for_submission(iocs, "Communicating Files")

        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(
            tk.END,
            f"⏳ Communicating Files — 0/{len(iocs)} complete\n{'─' * 50}\n\n",
            "bold",
        )
        self._notebook.select(1)

        def _work():
            total = len(prepared_iocs)
            for i, (ioc_display, ioc_query) in enumerate(prepared_iocs, 1):
                def _update_progress(idx=i, ioc_val=ioc_display):
                    self._set_status(f"Comms Files: {idx}/{total} — {ioc_val}")
                    self._vt_output.delete("1.0", "1.end")
                    self._vt_output.insert(
                        "1.0",
                        f"⏳ Communicating Files — {idx - 1}/{total} complete  |  querying: {ioc_val}",
                        "bold",
                    )
                self.after(0, _update_progress)

                files = vt.get_communicating_files(api_key, ioc_query)

                def _update(ioc_val=ioc_display, data=files, idx=i, tot=total):
                    self._vt_output.insert(tk.END, f"{ioc_val}:\n", "bold")
                    if isinstance(data, dict) and "error" in data:
                        self._vt_output.insert(
                            tk.END, f"  {data['error']}\n\n", "error"
                        )
                    elif isinstance(data, list):
                        for entry in data:
                            name = entry.get("name", "")
                            sha256 = entry.get("sha256", "")
                            score = entry.get("score", "")
                            label = entry.get("threat_label", "")
                            line = f"  {score}"
                            if label:
                                line += f" [{label}]"
                            if name:
                                line += f" — {name}"
                            self._vt_output.insert(tk.END, line + "\n")
                            if sha256:
                                self._vt_output.insert(
                                    tk.END, f"    SHA-256: {sha256}\n"
                                )
                        self._vt_output.insert(tk.END, "\n")
                    # Update progress header
                    self._vt_output.delete("1.0", "1.end")
                    done_label = "⏳" if idx < tot else "✅"
                    self._vt_output.insert(
                        "1.0",
                        f"{done_label} Communicating Files — {idx}/{tot} complete",
                        "bold",
                    )
                    self._vt_output.see(tk.END)
                self.after(0, _update)

            self.after(0, lambda: self._set_status(f"Comms Files complete — {len(iocs)} IOCs"))

        self._run_vt_threaded(_work, "Communicating Files")

    # ==================================================================
    # Jsluice
    # ==================================================================

    def _run_jsluice(self):
        text = self._get_input_text()
        if text is None:
            messagebox.showwarning("Input Missing", "Provide text for jsluice.")
            return

        if self._jsluice_running:
            messagebox.showwarning(
                "Jsluice Busy",
                "Jsluice is already running.\n"
                "Please wait for it to complete.",
            )
            return

        mode = self._toolbar["mode_combo"].get()
        if not mode:
            messagebox.showerror("Jsluice Error", "Please select a mode.")
            return

        options = self._output["options_entry"].get().strip()
        raw = bool(self._output["raw_var"].get())

        self._jsluice_running = True
        self._set_status(f"Running jsluice ({mode} mode)...")
        self._set_busy_progress(f"Jsluice ({mode})")
        self._loading.show(f"Running jsluice ({mode})...",
                           f"{len(text):,} characters of JavaScript")
        self._jsluice_output.configure(state="normal")
        self._jsluice_output.delete("1.0", tk.END)
        self._jsluice_output.insert(tk.END, f"Running jsluice ({mode})...\n\n")
        self._notebook.select(2)

        def _work():
            result = self.jsluice.run(text, mode, options, raw)
            self.after(0, _begin_jsluice_render, result)

        def _begin_jsluice_render(result):
            # Hide overlay first so widgets can repaint during chunked rendering
            self._loading.hide()

            out = self._jsluice_output
            out.configure(state="normal")
            out.delete("1.0", tk.END)

            if "temp_file" in result:
                out.insert(
                    tk.END,
                    f"--- Input saved to: {result['temp_file']} ---\n\n",
                    "bold",
                )

            if not result["success"]:
                out.insert(
                    tk.END,
                    f"--- Jsluice Error ---\n{result['error']}\n",
                    "error",
                )
                self._clear_progress()
                self._set_status("Jsluice error")
                self._jsluice_running = False
                return

            out.insert(
                tk.END,
                f"--- Jsluice Results ({mode} mode) ---\n\n",
                "bold",
            )

            # Split output into lines for chunked rendering
            lines = result["output"].splitlines(keepends=True)
            if not lines:
                self._clear_progress()
                self._set_status(f"Jsluice ({mode}) complete")
                self._jsluice_running = False
                return

            self._set_status(f"Rendering jsluice results...")
            self._jsluice_render = {"lines": lines, "idx": 0}
            self.after(1, _jsluice_render_chunk)

        def _jsluice_render_chunk():
            st = self._jsluice_render
            if st is None:
                return
            lines = st["lines"]
            out = self._jsluice_output
            CHUNK = 100
            i = st["idx"]
            end = min(i + CHUNK, len(lines))
            out.configure(state="normal")
            while i < end:
                insert_with_links(out, lines[i])
                i += 1
            st["idx"] = i

            if i >= len(lines):
                self._jsluice_render = None
                self._clear_progress()
                self._set_status(f"Jsluice ({mode}) complete")
                self._jsluice_running = False
            else:
                self.after(1, _jsluice_render_chunk)

        threading.Thread(target=_work, daemon=True).start()

    def _install_jsluice(self):
        """Auto-install jsluice (and Go if needed) with live progress."""
        if not messagebox.askyesno(
            "Install jsluice",
            "This will install jsluice (a JavaScript analysis tool) "
            "from source.\n\n"
            "Requirements:\n"
            "  • Go compiler (will be installed via Homebrew if missing)\n"
            "  • Internet connection\n\n"
            "This may take a few minutes. Proceed?",
        ):
            return

        # Switch to Jsluice tab and prepare output
        self._notebook.select(2)
        out = self._jsluice_output
        out.configure(state="normal")
        out.delete("1.0", tk.END)
        out.insert(tk.END, "--- Installing jsluice ---\n\n", "bold")
        self.update_idletasks()

        # Disable install button to prevent double-clicks
        tb = self._toolbar
        install_btn = tb.get("install_jsluice_btn")
        if install_btn:
            install_btn.configure(state="disabled")

        self._set_status("Installing jsluice...")

        def _progress(msg: str):
            """Thread-safe progress callback — appends to output widget."""
            self.after(0, self._append_install_line, msg)

        def _work():
            installer = JsluiceInstaller()
            result = installer.full_install(_progress)
            self.after(0, _done, result)

        def _done(result: dict):
            if result["success"]:
                # Re-detect jsluice
                self.jsluice.reinitialize()

                out.insert(
                    tk.END,
                    f"\n✓ {result['message']}\n",
                    "bold",
                )

                # Enable Run button
                tb["run_jsluice_btn"].configure(state="normal")

                # Remove Install button from toolbar
                if install_btn:
                    tb["flow"].remove(install_btn)
                    tb.pop("install_jsluice_btn", None)

                self._set_status("jsluice installed successfully")
            else:
                out.insert(
                    tk.END,
                    f"\n✗ Installation failed:\n{result['message']}\n",
                    "error",
                )
                # Re-enable install button for retry
                if install_btn:
                    install_btn.configure(state="normal")
                self._set_status("jsluice installation failed")

            out.configure(state="disabled")

        threading.Thread(target=_work, daemon=True).start()

    def _append_install_line(self, msg: str):
        """Append a progress line to the jsluice output (main thread)."""
        out = self._jsluice_output
        out.configure(state="normal")
        out.insert(tk.END, f"  {msg}\n")
        out.see(tk.END)
        out.configure(state="disabled")

    # ==================================================================
    # Nmap installation
    # ==================================================================

    def _install_nmap(self):
        """Auto-install nmap with live progress."""
        if not messagebox.askyesno(
            "Install Nmap",
            "This will install nmap (a network scanning tool).\n\n"
            "Installation method:\n"
            "  • macOS: Homebrew or MacPorts\n"
            "  • Linux: apt, dnf, pacman, or other package managers\n"
            "  • Windows: Chocolatey, Scoop, Winget, or direct download\n\n"
            "This may take a few minutes. Proceed?",
        ):
            return

        # Switch to Nmap tab and prepare output
        self._notebook.select(4)
        out = self._nmap_output
        out.configure(state="normal")
        out.delete("1.0", tk.END)
        out.insert(tk.END, "--- Installing nmap ---\n\n", "bold")
        self.update_idletasks()

        # Disable install button to prevent double-clicks
        tb = self._toolbar
        install_btn = tb.get("install_nmap_btn")
        if install_btn:
            install_btn.configure(state="disabled")

        self._set_status("Installing nmap...")

        def _progress(msg: str):
            """Thread-safe progress callback — appends to nmap output widget."""
            self.after(0, self._append_nmap_install_line, msg)

        def _work():
            installer = NmapInstaller()
            result = installer.full_install(_progress)
            self.after(0, _done, result)

        def _done(result: dict):
            if result["success"]:
                # Re-detect nmap
                self.nmap = NmapHandler()

                out.insert(
                    tk.END,
                    f"\n✓ {result['message']}\n",
                    "bold",
                )

                # Enable Run button
                tb["run_nmap_btn"].configure(state="normal")

                # Remove Install button from toolbar
                if install_btn:
                    tb["flow"].remove(install_btn)
                    tb.pop("install_nmap_btn", None)

                self._set_status("nmap installed successfully")
            else:
                out.insert(
                    tk.END,
                    f"\n✗ Installation failed:\n{result['message']}\n",
                    "error",
                )
                # Re-enable install button for retry
                if install_btn:
                    install_btn.configure(state="normal")
                self._set_status("nmap installation failed")

            out.configure(state="disabled")

        threading.Thread(target=_work, daemon=True).start()

    def _append_nmap_install_line(self, msg: str):
        """Append a progress line to the nmap output (main thread)."""
        out = self._nmap_output
        out.configure(state="normal")
        out.insert(tk.END, f"  {msg}\n")
        out.see(tk.END)
        out.configure(state="disabled")

    # ==================================================================
    # Shell command
    # ==================================================================

    def _run_shell_command(self):
        cmd = self._output["shell_entry"].get().strip()
        if not cmd:
            messagebox.showwarning("Input Missing", "Please enter a shell command.")
            return

        if self._shell_running:
            messagebox.showwarning(
                "Shell Busy",
                "A shell command is already running.\n"
                "Please wait for it to complete.",
            )
            return

        self._shell_running = True
        self._set_status(f"Running: {cmd[:50]}...")
        self._set_busy_progress("Shell")
        self._loading.show(f"Running command...", cmd[:80])
        out = self._shell_output
        out.configure(state="normal")
        out.delete("1.0", tk.END)
        out.insert(tk.END, f"$ {cmd}\n\n", "bold")
        out.insert(tk.END, "Running...\n")
        self._notebook.select(3)

        def _work():
            # Use raw mode to preserve ANSI escape codes
            result = shell_runner.run_command_raw(
                cmd, timeout=self.settings.shell_timeout_seconds
            )

            def _update():
                self._shell_running = False
                self._clear_progress()
                self._loading.hide()
                out.configure(state="normal")
                out.delete("1.0", tk.END)
                out.insert(tk.END, f"$ {cmd}\n\n", "bold")

                if result["timed_out"]:
                    out.insert(
                        tk.END, "--- Command Timed Out ---\n", ("error", "bold")
                    )

                if result["stdout"]:
                    insert_ansi_text(out, result["stdout"])
                    out.insert(tk.END, "\n")
                if result["stderr"]:
                    out.insert(tk.END, "--- stderr ---\n", ("bold", "error"))
                    out.insert(tk.END, result["stderr"] + "\n", "error")

                rc = result["return_code"]
                tag = ("error",) if rc != 0 else ("success",)
                out.insert(tk.END, f"\n[Exit Code: {rc}]\n", ("bold",) + tag)
                self._set_status(f"Shell command exited ({rc})")

            self.after(0, _update)

        threading.Thread(target=_work, daemon=True).start()

    # ==================================================================
    # Nmap
    # ==================================================================

    def _run_nmap(self):
        """Execute an nmap scan using the config from the Nmap tab."""
        if not self.nmap.available:
            messagebox.showerror(
                "Nmap Not Found",
                "nmap is not installed or not found in PATH.\n"
                "Click 'Install Nmap' in the toolbar to install automatically."
            )
            return

        if self._nmap_running:
            messagebox.showwarning(
                "Nmap Busy",
                "An nmap scan is already in progress.\n"
                "Please wait for it to complete."
            )
            return

        target = self._output["nmap_target"].get().strip()
        if not target:
            messagebox.showwarning("Target Missing", "Enter a target IP or hostname.")
            return

        # Get scan type flag from combo selection
        scan_label = self._output["nmap_scan_combo"].get()
        scan_flag = ""
        for label, flag in NMAP_SCAN_TYPES:
            if label == scan_label:
                scan_flag = flag
                break

        # Get checked flags
        flags = []
        for flag, var in self._output["nmap_flag_vars"]:
            if var.get():
                flags.append(flag)

        # Get timing template
        timing_label = self._output["nmap_timing_combo"].get()
        timing_flag = ""
        for label, flag in NMAP_TIMING_TEMPLATES:
            if label == timing_label:
                timing_flag = flag
                break
        if timing_flag:
            flags.append(timing_flag)

        # Get ports specification
        ports_str = self._output["nmap_ports_entry"].get().strip()
        if ports_str:
            flags.append(f"-p {ports_str}")

        extra = self._output["nmap_extra_entry"].get().strip()
        use_sudo = bool(self._output["nmap_sudo_var"].get())

        # Check if the scan type requires sudo and warn if not checked
        needs_sudo = scan_flag in NMAP_SUDO_SCAN_FLAGS
        if needs_sudo and not use_sudo:
            answer = messagebox.askyesnocancel(
                "Sudo Required",
                f"The scan type '{scan_label}' typically requires root privileges.\n\n"
                "Run with sudo? (You will be prompted for your password.)\n\n"
                "Yes = Run with sudo\n"
                "No = Run without sudo (may fail)\n"
                "Cancel = Abort",
            )
            if answer is None:
                return  # Cancel
            if answer:
                use_sudo = True
                self._output["nmap_sudo_var"].set(1)

        # If using sudo, acquire credentials before running the scan
        if use_sudo:
            if not self.nmap.check_sudo_cached():
                self._set_status("Acquiring sudo credentials...")
                self.update_idletasks()
                if not self.nmap.acquire_sudo():
                    messagebox.showerror(
                        "Sudo Failed",
                        "Could not acquire sudo credentials.\n"
                        "The password prompt was cancelled or failed.\n\n"
                        "Try running without sudo, or run the app from a terminal\n"
                        "with 'sudo -v' first to cache your credentials."
                    )
                    self._set_status("Sudo authentication failed")
                    return

        # Build command for display
        cmd = self.nmap.build_command(
            target, scan_flag, flags, extra, use_sudo=use_sudo, xml_output=None
        )
        display_cmd = cmd

        self._set_status(f"Nmap scanning {target}...")
        self._set_busy_progress(f"Nmap: {target}")
        self._nmap_running = True
        self._loading.show(f"Scanning {target}...", scan_label)

        # Clear output
        self._nmap_output.configure(state="normal")
        self._nmap_output.delete("1.0", tk.END)
        self._nmap_output.insert(tk.END, f"$ {display_cmd}\n\n", "bold")

        self._nmap_structured.configure(state="normal")
        self._nmap_structured.delete("1.0", tk.END)
        self._nmap_structured.insert(tk.END, "Scanning...\n")
        self._last_nmap_structured = None

        self._notebook.select(4)
        self.update_idletasks()

        def _work():
            result = self.nmap.run(
                target, scan_flag, flags, extra, use_sudo=use_sudo,
                timeout=self.settings.nmap_timeout_seconds,
            )

            def _update():
                self._nmap_running = False
                self._clear_progress()
                self._loading.hide()

                self._nmap_output.configure(state="normal")

                if result["timed_out"]:
                    self._nmap_output.insert(
                        tk.END, "--- Scan Timed Out ---\n", ("error", "bold")
                    )
                    self._nmap_output.insert(
                        tk.END,
                        "Tip: The scan exceeded the 5-minute timeout.\n"
                        "Try using -F (Quick) scan, limiting ports with -p,\n"
                        "or using -T4 / -T5 timing for faster results.\n\n",
                        "error",
                    )

                if result["stdout"]:
                    insert_nmap_highlighted(self._nmap_output, result["stdout"])
                    self._nmap_output.insert(tk.END, "\n")

                if result["stderr"]:
                    self._nmap_output.insert(
                        tk.END, "--- stderr ---\n", ("bold", "error")
                    )
                    self._nmap_output.insert(
                        tk.END, result["stderr"] + "\n", "error"
                    )

                rc = result["return_code"]
                tag = ("error",) if rc != 0 else ("success",)
                self._nmap_output.insert(
                    tk.END, f"\n[Exit Code: {rc}]\n", ("bold",) + tag
                )

                # Structured data
                self._nmap_structured.configure(state="normal")
                self._nmap_structured.delete("1.0", tk.END)

                structured = result.get("structured")
                if structured:
                    self._last_nmap_structured = structured
                    formatted = self.nmap.format_structured(structured)
                    insert_nmap_structured_highlighted(
                        self._nmap_structured, formatted
                    )

                    # Count open ports
                    total_ports = sum(
                        len([p for p in h.get("ports", []) if p.get("state") == "open"])
                        for h in structured.get("hosts", [])
                    )
                    total_hosts = len(structured.get("hosts", []))
                    self._set_status(
                        f"Nmap complete — {total_hosts} host(s), "
                        f"{total_ports} open port(s)"
                    )
                else:
                    self._nmap_structured.insert(
                        tk.END, "No structured data available.\n"
                    )
                    if result["success"]:
                        self._set_status("Nmap scan complete")
                    else:
                        self._set_status("Nmap scan failed")

            self.after(0, _update)

        threading.Thread(target=_work, daemon=True).start()

    def _on_nmap_scan_type_changed(self, _event=None):
        """Auto-check sudo when a privileged scan type is selected."""
        scan_label = self._output["nmap_scan_combo"].get()
        scan_flag = ""
        for label, flag in NMAP_SCAN_TYPES:
            if label == scan_label:
                scan_flag = flag
                break
        if scan_flag in NMAP_SUDO_SCAN_FLAGS:
            self._output["nmap_sudo_var"].set(1)

    def _stop_nmap(self):
        """Stop the currently running nmap scan."""
        if not self._nmap_running:
            return
        self.nmap.stop()
        self._nmap_running = False
        self._clear_progress()
        self._loading.hide()
        self._nmap_output.configure(state="normal")
        self._nmap_output.insert(
            tk.END, "\n--- Scan Stopped by User ---\n", ("error", "bold")
        )
        self._set_status("Nmap scan stopped")

    def _toggle_nmap_pane(self, pane: str):
        """
        Toggle maximize/restore for a nmap results pane.

        pane: "raw" or "struct"
        """
        nmap_pane = self._output["nmap_pane"]
        raw_frame = self._output["nmap_output_frame"]
        struct_frame = self._output["nmap_struct_frame"]
        raw_btn = self._output["nmap_toggle_raw_btn"]
        struct_btn = self._output["nmap_toggle_struct_btn"]

        if self._nmap_maximized_pane == pane:
            # Restore both panes
            self._nmap_maximized_pane = None
            if pane == "raw":
                nmap_pane.add(struct_frame, stretch="always")
            else:
                nmap_pane.forget(raw_frame)
                nmap_pane.forget(struct_frame)
                nmap_pane.add(raw_frame, stretch="always")
                nmap_pane.add(struct_frame, stretch="always")

            raw_btn.configure(text="Maximize")
            struct_btn.configure(text="Maximize")
        else:
            # Maximize this pane, hide the other
            self._nmap_maximized_pane = pane
            if pane == "raw":
                try:
                    nmap_pane.forget(struct_frame)
                except tk.TclError:
                    pass
                raw_btn.configure(text="Restore")
                struct_btn.configure(text="Maximize")
            else:
                try:
                    nmap_pane.forget(raw_frame)
                except tk.TclError:
                    pass
                struct_btn.configure(text="Restore")
                raw_btn.configure(text="Maximize")

    def _clear_nmap_output(self):
        """Clear nmap output and structured data."""
        self._nmap_output.configure(state="normal")
        self._nmap_output.delete("1.0", tk.END)
        self._nmap_output.insert(tk.END, NMAP_HELP)
        if not self.nmap.available:
            self._nmap_output.insert(
                tk.END,
                "\n\nWARNING: nmap command not found in PATH.\n"
                "Click 'Install Nmap' in the toolbar to install automatically.",
                "error",
            )
        self._nmap_structured.configure(state="normal")
        self._nmap_structured.delete("1.0", tk.END)
        self._last_nmap_structured = None
        self._set_status("Nmap output cleared")

    def _save_nmap_raw(self):
        """Save raw nmap output to a text file."""
        text = strip_ansi(self._nmap_output.get("1.0", "end-1c"))
        if not text.strip() or text.strip().startswith("Nmap scan results"):
            messagebox.showwarning("No Nmap Results", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Nmap Output As",
        )
        if path:
            try:
                file_operations.save_text_to_file(text, path)
                self._set_status(f"Nmap output saved to {os.path.basename(path)}")
                self._notify(f"Nmap output saved: {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed:\n{exc}")

    def _save_nmap_json(self):
        """Save structured nmap data as JSON."""
        if not self._last_nmap_structured:
            messagebox.showwarning(
                "No Structured Data", "No structured scan data to export."
            )
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export Nmap Structured Data As JSON",
        )
        if path:
            try:
                json_str = self.nmap.structured_to_json(self._last_nmap_structured)
                file_operations.save_text_to_file(json_str, path)
                self._set_status(f"Nmap JSON exported to {os.path.basename(path)}")
                self._notify(f"Nmap JSON exported: {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Export Error", f"Failed:\n{exc}")

    # ==================================================================
    # Save / Export
    # ==================================================================

    def _save_input_text(self):
        text = self._get_input_text()
        if text is None:
            messagebox.showwarning("Empty Input", "No input text to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Input Text As",
        )
        if path:
            try:
                file_operations.save_text_to_file(text, path)
                self._set_status(f"Input saved to {os.path.basename(path)}")
                self._notify(f"Input saved: {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed:\n{exc}")

    def _save_iocs_grouped(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No IOCs to save. Parse first.")
            return
        text, _tag_ranges, _total = IOCExtractorApp._build_review_output(self.found_iocs)
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Extracted IOCs As Group",
        )
        if path:
            try:
                file_operations.save_text_to_file(text, path)
                self._set_status(f"IOCs saved to {os.path.basename(path)}")
                self._notify(f"IOCs saved: {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed:\n{exc}")

    def _save_iocs_individually(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No parsed IOCs. Parse first.")
            return
        folder = filedialog.askdirectory(title="Select Folder for IOC Categories")
        if not folder:
            return
        saved, errors = file_operations.save_iocs_by_category(
            self.found_iocs, folder
        )
        if errors:
            messagebox.showerror(
                "Save Errors",
                f"Saved {saved} categories.\nErrors:\n" + "\n".join(errors),
            )
        elif saved:
            self._set_status(f"Saved {saved} IOC categories")
            self._notify(
                f"Saved {saved} IOC categor{'y' if saved == 1 else 'ies'}",
                level="success",
            )
        else:
            messagebox.showwarning("No Data", "No valid IOC data to save.")

    def _save_iocs_json(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No parsed IOCs. Parse first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export IOCs as JSON",
        )
        if path:
            try:
                file_operations.export_iocs_as_json(self.found_iocs, path)
                self._set_status(f"IOCs exported to {os.path.basename(path)}")
                self._notify(f"IOCs exported (JSON): {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Export Error", f"Failed:\n{exc}")

    def _save_iocs_csv(self):
        if not self.found_iocs:
            messagebox.showwarning("No IOCs", "No parsed IOCs. Parse first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Export IOCs as CSV",
        )
        if path:
            try:
                file_operations.export_iocs_as_csv(self.found_iocs, path)
                self._set_status(f"IOCs exported to {os.path.basename(path)}")
                self._notify(f"IOCs exported (CSV): {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Export Error", f"Failed:\n{exc}")

    def _save_vt_output(self):
        text = self._vt_output.get("1.0", "end-1c")
        if not text.strip() or text.strip().startswith("VirusTotal results"):
            messagebox.showwarning("No VT Results", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("TXT", "*.txt"), ("All", "*.*")],
            title="Save VT Output As",
        )
        if path:
            try:
                file_operations.save_text_to_file(text, path)
                self._set_status(f"VT output saved to {os.path.basename(path)}")
                self._notify(f"VT output saved: {os.path.basename(path)}", level="success")
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed:\n{exc}")

    def _save_jsluice_output(self):
        text = self._jsluice_output.get("1.0", "end-1c").strip()
        if (not text or text.startswith("Jsluice analysis results")
                or text.startswith("Usage:")):
            messagebox.showwarning("No Jsluice Results", "No results to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text Files", "*.txt"), ("JSON Lines", "*.jsonl"),
                ("All Files", "*.*"),
            ],
            title="Save Jsluice Output As",
        )
        if path:
            try:
                if not text.endswith("\n"):
                    text += "\n"
                file_operations.save_text_to_file(text, path)
                self._set_status(f"Jsluice output saved to {os.path.basename(path)}")
                self._notify(
                    f"Jsluice output saved: {os.path.basename(path)}",
                    level="success",
                )
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed:\n{exc}")

    # ==================================================================
    # Clear operations
    # ==================================================================

    def _clear_input_text(self):
        if messagebox.askyesno("Confirm Clear", "Clear the input text?"):
            self._article_input.delete("1.0", tk.END)
            self._article_input.insert(tk.END, INPUT_PLACEHOLDER)
            self._article_input.config(fg=COLORS["fg_placeholder"])
            self._clear_highlight()
            self._article_input.tag_remove("ioc_highlight", "1.0", tk.END)
            self._set_status("Input cleared")
            self._set_summary("")

    def _clear_review_output(self):
        self._review_output.configure(state="normal")
        self._review_output.delete("1.0", tk.END)
        self._review_output.insert(tk.END, IOC_REVIEW_HELP)
        self.found_iocs.clear()
        self._review_tree_source_label = "Parser"
        self._history_loaded_collection_id = None
        self._review_tree_status.clear()
        self._render_review_tree_placeholder()
        self._set_summary("")
        self._set_status("IOC Review cleared")

    def _clear_vt_output(self):
        self._vt_output.configure(state="normal")
        self._vt_output.delete("1.0", tk.END)
        self._vt_output.insert(tk.END, VT_HELP)
        self._set_status("VT output cleared")

    def _clear_jsluice_output(self):
        self._jsluice_output.configure(state="normal")
        self._jsluice_output.delete("1.0", tk.END)
        self._jsluice_output.insert(tk.END, JSLUICE_HELP)
        if not self.jsluice.available:
            self._jsluice_output.insert(
                tk.END,
                "\n\nWARNING: jsluice command not found in PATH.",
                "error",
            )
        self._set_status("Jsluice output cleared")

    # ==================================================================
    # Help dialogs
    # ==================================================================

    def _show_jsluice_help(self):
        messagebox.showinfo("Jsluice Options Help", JSLUICE_OPTIONS_HELP)

    def _show_shortcuts(self):
        lines = ["Keyboard Shortcuts:\n"]
        for name, (display, _binding) in KEYBOARD_SHORTCUTS.items():
            label = name.replace("_", " ").title()
            lines.append(f"  {display:<20s}  {label}")
        messagebox.showinfo("Keyboard Shortcuts", "\n".join(lines))

    def _show_about(self):
        messagebox.showinfo(
            "About IOC Citadel",
            "IOC Citadel 2.0\n"
            "by Bulwark Black LLC\n\n"
            "A professional tool for extracting Indicators of Compromise\n"
            "from text, with VirusTotal integration, Jsluice analysis,\n"
            "and shell command execution.\n\n"
            "Supports 25+ IOC types including IPs, domains, URLs,\n"
            "hashes, CVEs, MITRE ATT&CK IDs, and more.",
        )


if __name__ == "__main__":
    app = IOCExtractorApp()
    app.mainloop()
