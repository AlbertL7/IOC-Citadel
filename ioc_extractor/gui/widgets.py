"""
widgets.py - Professional dark-themed GUI widget builders.

Layout philosophy: **Toolbar is the action hub, tabs are for results.**

  - FlowFrame toolbar wraps buttons responsively (no clipping on resize)
  - Toolbar groups: File | Parse | VirusTotal | Jsluice
  - Each output tab has only Save + Clear (minimal controls)
  - Find/Replace bar is toggleable (Ctrl+H)
  - Menu bar provides full access to every action

Color coding:
  Green  = IOC parsing / extraction
  Blue   = VirusTotal operations
  Orange = Jsluice analysis
  Purple = Shell / terminal commands

Platform handling:
  - macOS Aqua theme ignores bg/fg on tk.Button, so we use a custom
    Frame+Label "ColorButton" widget with manual hover/click bindings.
  - Linux and Windows render tk.Button colors natively.
"""

import platform
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import webbrowser

from ioc_extractor.constants import (
    COLORS, FONTS, JSLUICE_MODES, KEYBOARD_SHORTCUTS,
    NMAP_SCAN_TYPES, NMAP_COMMON_FLAGS, NMAP_TIMING_TEMPLATES,
)

# Detect platform once at import time
_IS_MACOS = platform.system() == "Darwin"
_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"


# =====================================================================
# FlowFrame — responsive wrapping layout
# =====================================================================

class FlowFrame(tk.Frame):
    """
    A frame that wraps its children like CSS flexbox-wrap.

    Children are laid out left-to-right; when the next widget would
    exceed the frame width, it wraps to a new row. The frame auto-
    adjusts its height to fit all rows.
    """

    def __init__(self, parent, padx=4, pady=3, **kw):
        super().__init__(parent, **kw)
        self._items = []      # list of (widget, padx, pady)
        self._pad_x = padx
        self._pad_y = pady
        self.bind("<Configure>", self._reflow)

    def add(self, widget, padx=None, pady=None):
        """Register a child widget for flow layout."""
        px = padx if padx is not None else self._pad_x
        py = pady if pady is not None else self._pad_y
        self._items.append((widget, px, py))
        # Do initial placement
        self.after_idle(self._reflow)

    def add_separator(self):
        """Add a thin vertical separator to the flow."""
        sep = tk.Frame(self, bg=COLORS["separator"], width=1)
        self._items.append((sep, 8, 4))
        self.after_idle(self._reflow)

    def add_label(self, text, fg=None):
        """Add a colored group label to the flow."""
        lbl = tk.Label(
            self, text=text, font=FONTS["label"],
            bg=self["bg"], fg=fg or COLORS["fg_secondary"],
        )
        self._items.append((lbl, 4, 4))
        self.after_idle(self._reflow)
        return lbl

    def remove(self, widget):
        """Remove a widget from the flow layout and destroy it."""
        self._items = [(w, px, py) for w, px, py in self._items if w is not widget]
        widget.destroy()
        self.after_idle(self._reflow)

    def _reflow(self, event=None):
        """Reposition children in a wrapping flow layout."""
        if not self._items:
            return

        max_w = self.winfo_width()
        if max_w <= 1:
            max_w = 9999  # Not yet mapped — lay out wide

        x = 0
        y = 0
        row_h = 0

        for widget, px, py in self._items:
            widget.update_idletasks()
            w = widget.winfo_reqwidth() + 2 * px
            h = widget.winfo_reqheight() + 2 * py

            if x + w > max_w and x > 0:
                x = 0
                y += row_h
                row_h = 0

            widget.place(x=x + px, y=y + py)
            x += w
            row_h = max(row_h, h)

        total_h = y + row_h
        if total_h > 0:
            self.configure(height=total_h)


# =====================================================================
# Loading overlay — non-blocking progress indicator
# =====================================================================

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class LoadingOverlay(tk.Frame):
    """
    A dark overlay with animated spinner and status text.

    Placed over the entire application window to signal that a
    background task is running.  Call :meth:`show` to display and
    :meth:`hide` to dismiss.  The overlay does **not** block the
    Tkinter event loop — the spinner animates via ``after()``.

    Usage::

        overlay = LoadingOverlay(root)
        overlay.show("Parsing IOCs...")
        # ... later, from main thread ...
        overlay.hide()
    """

    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.configure(bg="#0d1117")

        self._frame_idx = 0
        self._after_id: str | None = None

        # --- Inner card ---
        card = tk.Frame(self, bg="#16213e", bd=0, highlightthickness=1,
                        highlightbackground="#2d3748")
        card.place(relx=0.5, rely=0.5, anchor="center")
        self._card = card

        # Spinner character
        self._spinner_lbl = tk.Label(
            card, text=_SPINNER_FRAMES[0],
            font=("Menlo", 28), fg="#3b82f6", bg="#16213e",
        )
        self._spinner_lbl.pack(padx=30, pady=(24, 8))

        # Status message
        self._msg_lbl = tk.Label(
            card, text="Loading...",
            font=(FONTS["body"][0], 13), fg="#e2e8f0", bg="#16213e",
        )
        self._msg_lbl.pack(padx=30, pady=(0, 6))

        # Sub-message / detail
        self._detail_lbl = tk.Label(
            card, text="",
            font=(FONTS["body"][0], 10), fg="#94a3b8", bg="#16213e",
        )
        self._detail_lbl.pack(padx=30, pady=(0, 20))

    # --- Public API ---

    def show(self, message: str = "Processing...", detail: str = ""):
        """Display the overlay with *message* text."""
        self._msg_lbl.configure(text=message)
        self._detail_lbl.configure(text=detail)
        self._frame_idx = 0
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.lift()
        self._animate()

    def update_message(self, message: str, detail: str = ""):
        """Change the text while the overlay is visible."""
        self._msg_lbl.configure(text=message)
        self._detail_lbl.configure(text=detail)

    def hide(self):
        """Dismiss the overlay."""
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.place_forget()

    # --- Internal ---

    def _animate(self):
        """Cycle through braille spinner frames."""
        self._spinner_lbl.configure(text=_SPINNER_FRAMES[self._frame_idx])
        self._frame_idx = (self._frame_idx + 1) % len(_SPINNER_FRAMES)
        self._after_id = self.after(100, self._animate)


# =====================================================================
# Toast notifications
# =====================================================================

class ToastManager(tk.Frame):
    """Simple in-window toast stack for non-blocking notifications."""

    def __init__(self, parent, **kw):
        host_bg = parent.cget("bg") if "bg" in parent.keys() else COLORS["bg_primary"]
        super().__init__(parent, bg=host_bg, bd=0, highlightthickness=0, **kw)
        self._stack = tk.Frame(self, bg=host_bg, bd=0, highlightthickness=0)
        self._stack.pack(anchor="ne")
        self.place(relx=1.0, x=-12, y=10, anchor="ne")
        self.lift()

    def show(
        self,
        message: str,
        level: str = "info",
        title: str | None = None,
        duration_ms: int = 2600,
    ):
        palette = {
            "info": (COLORS["bg_secondary"], COLORS["blue"], COLORS["fg_heading"]),
            "success": (COLORS["bg_secondary"], COLORS["green"], COLORS["fg_heading"]),
            "warning": (COLORS["bg_secondary"], COLORS["yellow"], COLORS["fg_heading"]),
            "error": (COLORS["bg_secondary"], COLORS["red"], COLORS["fg_heading"]),
        }
        card_bg, accent, fg = palette.get(level, palette["info"])

        card = tk.Frame(
            self._stack,
            bg=card_bg,
            bd=0,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            padx=10,
            pady=8,
        )
        card.pack(anchor="ne", pady=4, fill="x")

        bar = tk.Frame(card, bg=accent, width=4)
        bar.pack(side="left", fill="y", padx=(0, 8))

        body = tk.Frame(card, bg=card_bg)
        body.pack(side="left", fill="both", expand=True)

        if title:
            tk.Label(
                body,
                text=title,
                bg=card_bg,
                fg=fg,
                font=FONTS["button"],
                anchor="w",
            ).pack(anchor="w")

        tk.Label(
            body,
            text=message,
            bg=card_bg,
            fg=COLORS["fg_primary"],
            font=FONTS["body"],
            justify="left",
            wraplength=420,
            anchor="w",
        ).pack(anchor="w")

        def _dismiss():
            try:
                card.destroy()
            except Exception:
                pass

        card.after(max(800, int(duration_ms)), _dismiss)
        self.lift()
        return card


# =====================================================================
# Button helpers
# =====================================================================

class ColorButton(tk.Frame):
    """
    A custom colored button that works on macOS.

    macOS Aqua ignores bg/fg on tk.Button. This uses a Frame+Label
    combination that renders colored backgrounds reliably everywhere.
    """

    def __init__(self, parent, text, bg_color, hover_color=None,
                 fg_color=None, font=None, width=None, padx=10, pady=4,
                 state=tk.NORMAL, command=None, **kw):
        super().__init__(parent, bg=bg_color, cursor="hand2", **kw)

        self._bg = bg_color
        self._hover = hover_color or bg_color
        self._command = command
        self._state = state

        label_cfg = dict(
            text=text,
            bg=bg_color,
            fg=fg_color or COLORS["btn_fg"],
            font=font or FONTS["button"],
            padx=padx,
            pady=pady,
            cursor="hand2",
        )
        if width:
            label_cfg["width"] = width

        self._label = tk.Label(self, **label_cfg)
        self._label.pack(expand=True, fill="both")

        for widget in (self, self._label):
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
            widget.bind("<Button-1>", self._on_click)

        if state == tk.DISABLED:
            self._set_disabled()

    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        if "command" in kw:
            self._command = kw.pop("command")
        if "text" in kw:
            self._label.configure(text=kw.pop("text"))
        if "state" in kw:
            self._state = kw.pop("state")
            if self._state == tk.DISABLED:
                self._set_disabled()
            else:
                self._set_enabled()
        if kw:
            super().configure(**kw)

    config = configure

    def _on_enter(self, _event):
        if self._state != tk.DISABLED:
            self["bg"] = self._hover
            self._label["bg"] = self._hover

    def _on_leave(self, _event):
        if self._state != tk.DISABLED:
            self["bg"] = self._bg
            self._label["bg"] = self._bg

    def _on_click(self, _event):
        if self._state != tk.DISABLED and self._command:
            self._command()

    def _set_disabled(self):
        self._state = tk.DISABLED
        dim = COLORS["bg_secondary"]
        self["bg"] = dim
        self._label["bg"] = dim
        self._label["fg"] = COLORS["fg_secondary"]
        for widget in (self, self._label):
            widget["cursor"] = ""

    def _set_enabled(self):
        self._state = tk.NORMAL
        self["bg"] = self._bg
        self._label["bg"] = self._bg
        self._label["fg"] = COLORS["btn_fg"]
        for widget in (self, self._label):
            widget["cursor"] = "hand2"


class NativeColorButton(tk.Button):
    """Native tk.Button with hover effects for Linux / Windows."""

    def __init__(self, parent, bg_color, hover_color=None, **kw):
        self._bg = bg_color
        self._hover = hover_color or bg_color
        kw.setdefault("bg", bg_color)
        kw.setdefault("activebackground", self._hover)
        kw.setdefault("relief", "flat")
        kw.setdefault("bd", 0)
        kw.setdefault("cursor", "hand2")
        super().__init__(parent, **kw)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event):
        if str(self["state"]) != "disabled":
            self["bg"] = self._hover

    def _on_leave(self, _event):
        if str(self["state"]) != "disabled":
            self["bg"] = self._bg


class SplitButton(tk.Frame):
    """
    A button with a dropdown arrow — click the main area to execute
    the command, click the ``▾`` arrow to open a menu.

    Works on macOS (Aqua ignores bg on tk.Button) by using Frame+Label
    like :class:`ColorButton`.
    """

    def __init__(self, parent, text, bg_color, hover_color=None,
                 fg_color=None, font=None, padx=10, pady=4,
                 command=None, **kw):
        super().__init__(parent, bg=bg_color, cursor="hand2", **kw)

        self._bg = bg_color
        self._hover = hover_color or bg_color
        self._command = command
        self._state = tk.NORMAL

        fg = fg_color or COLORS["btn_fg"]
        fnt = font or FONTS["button"]

        # --- Main label (left) ---
        self._label = tk.Label(
            self, text=text, bg=bg_color, fg=fg,
            font=fnt, padx=padx, pady=pady, cursor="hand2",
        )
        self._label.pack(side="left", fill="both", expand=True)

        # --- Thin separator ---
        self._sep = tk.Frame(self, bg=fg, width=1)
        self._sep.pack(side="left", fill="y", pady=3)

        # --- Arrow label (right) ---
        self._arrow = tk.Label(
            self, text="▾", bg=bg_color, fg=fg,
            font=fnt, padx=5, pady=pady, cursor="hand2",
        )
        self._arrow.pack(side="left", fill="both")

        # --- Dropdown menu (populated externally) ---
        self.menu = tk.Menu(
            self, tearoff=False,
            bg=COLORS["bg_secondary"], fg=COLORS["fg_primary"],
            activebackground=COLORS["blue_dim"],
            activeforeground=COLORS["fg_heading"],
            font=FONTS["body"],
        )

        # --- Bindings ---
        for w in (self, self._label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click_main)

        for w in (self._arrow,):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click_arrow)

    # --- Public API ---

    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        if "command" in kw:
            self._command = kw.pop("command")
        if "text" in kw:
            self._label.configure(text=kw.pop("text"))
        if "state" in kw:
            self._state = kw.pop("state")
            if self._state == tk.DISABLED:
                self._set_disabled()
            else:
                self._set_enabled()
        if kw:
            super().configure(**kw)

    config = configure

    # --- Event handlers ---

    def _on_enter(self, _event):
        if self._state != tk.DISABLED:
            for w in (self, self._label, self._arrow):
                w["bg"] = self._hover

    def _on_leave(self, _event):
        if self._state != tk.DISABLED:
            for w in (self, self._label, self._arrow):
                w["bg"] = self._bg

    def _on_click_main(self, _event):
        if self._state != tk.DISABLED and self._command:
            self._command()

    def _on_click_arrow(self, event):
        if self._state == tk.DISABLED:
            return
        # Post menu directly below the button
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height()
        self.menu.post(x, y)

    def _set_disabled(self):
        self._state = tk.DISABLED
        dim = COLORS["bg_secondary"]
        fg = COLORS["fg_secondary"]
        for w in (self, self._label, self._arrow):
            w["bg"] = dim
            w["cursor"] = ""
        self._label["fg"] = fg
        self._arrow["fg"] = fg

    def _set_enabled(self):
        self._state = tk.NORMAL
        fg = COLORS["btn_fg"]
        for w in (self, self._label, self._arrow):
            w["bg"] = self._bg
            w["cursor"] = "hand2"
        self._label["fg"] = fg
        self._arrow["fg"] = fg


def _make_button(parent, text, color_key, width=None, state=tk.NORMAL, **kw):
    """Create a consistently styled colored button (platform-aware)."""
    bg = COLORS[color_key]
    hover = COLORS.get(f"{color_key}_hover", bg)

    if _IS_MACOS:
        return ColorButton(
            parent, text=text, bg_color=bg, hover_color=hover,
            fg_color=COLORS["btn_fg"], font=FONTS["button"],
            width=width, state=state, **kw,
        )
    else:
        cfg = dict(
            text=text, fg=COLORS["btn_fg"], activeforeground=COLORS["btn_fg"],
            font=FONTS["button"], padx=10, pady=4, state=state,
        )
        if width:
            cfg["width"] = width
        cfg.update(kw)
        return NativeColorButton(parent, bg_color=bg, hover_color=hover, **cfg)


def _make_menubutton(parent, text, color_key, menu_items):
    """
    Create a styled Menubutton with a dropdown menu.

    menu_items: list of (label, key) tuples. Commands wired later by app.py.
    Returns (menubutton, menu, {key: index}) so app.py can wire commands.
    """
    bg = COLORS[color_key]
    hover = COLORS.get(f"{color_key}_hover", bg)

    mb = tk.Menubutton(
        parent, text=text, font=FONTS["button"],
        bg=bg, fg=COLORS["btn_fg"], activebackground=hover,
        activeforeground=COLORS["btn_fg"], relief="flat", bd=0,
        padx=10, pady=4, cursor="hand2", indicatoron=False,
    )

    menu = tk.Menu(
        mb, tearoff=0,
        bg=COLORS["bg_secondary"], fg=COLORS["fg_primary"],
        activebackground=COLORS["blue_dim"], activeforeground=COLORS["fg_heading"],
        font=FONTS["menu"],
    )
    mb["menu"] = menu

    indices = {}
    for label, key in menu_items:
        menu.add_command(label=label)
        indices[key] = menu.index(tk.END)

    return mb, menu, indices


def _make_label(parent, text, fg=None, font=None, **kw):
    """Create a styled label on a dark background."""
    return tk.Label(
        parent, text=text,
        bg=kw.pop("bg", COLORS["bg_toolbar"]),
        fg=fg or COLORS["fg_secondary"],
        font=font or FONTS["label"], **kw,
    )


def _make_separator(parent, orient="horizontal"):
    """Thin colored separator line."""
    return tk.Frame(
        parent, bg=COLORS["separator"],
        height=1 if orient == "horizontal" else None,
        width=1 if orient == "vertical" else None,
    )


# =====================================================================
# Right-click context menu
# =====================================================================

def _add_context_menu(widget, readonly=False):
    """Attach a richer right-click context menu to text/entry-like widgets."""
    menu = tk.Menu(widget, tearoff=0,
                   bg=COLORS["bg_secondary"], fg=COLORS["fg_primary"],
                   activebackground=COLORS["blue_dim"],
                   activeforeground=COLORS["fg_heading"],
                   font=FONTS["body"])

    def _is_text_widget():
        return hasattr(widget, "tag_add") and hasattr(widget, "mark_set")

    def _is_entry_like():
        return hasattr(widget, "selection_range") and hasattr(widget, "icursor")

    def _get_text(selection_only=False):
        try:
            if _is_text_widget():
                if selection_only:
                    return widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                return widget.get("1.0", "end-1c")
            if _is_entry_like():
                if selection_only:
                    try:
                        start = widget.index("sel.first")
                        end = widget.index("sel.last")
                    except tk.TclError:
                        return ""
                    return widget.get()[start:end]
                return widget.get()
        except tk.TclError:
            return ""
        except Exception:
            return ""
        return ""

    def _has_selection():
        try:
            if _is_text_widget():
                return bool(widget.tag_ranges(tk.SEL))
            if _is_entry_like():
                try:
                    widget.index("sel.first")
                    widget.index("sel.last")
                    return True
                except tk.TclError:
                    return False
        except Exception:
            return False
        return False

    def _delete_selection():
        if readonly:
            return
        try:
            if _is_text_widget():
                if widget.tag_ranges(tk.SEL):
                    widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
                return
            if _is_entry_like():
                try:
                    start = widget.index("sel.first")
                    end = widget.index("sel.last")
                    widget.delete(start, end)
                except tk.TclError:
                    pass
        except tk.TclError:
            pass

    def _save_text(content: str, path: str):
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)

    def _save_as(selection_only=False):
        content = _get_text(selection_only=selection_only)
        if not content:
            messagebox.showwarning(
                "Nothing to Save",
                "No text available to save." if not selection_only else "No selected text to save.",
                parent=widget.winfo_toplevel(),
            )
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save As" if not selection_only else "Save Selection As",
            parent=widget.winfo_toplevel(),
        )
        if not path:
            return
        try:
            _save_text(content, path)
            if not selection_only:
                try:
                    setattr(widget, "_context_last_save_path", path)
                except Exception:
                    pass
        except Exception as exc:
            messagebox.showerror(
                "Save Error",
                f"Failed to save text:\n{exc}",
                parent=widget.winfo_toplevel(),
            )

    def _save():
        content = _get_text(selection_only=False)
        if not content:
            messagebox.showwarning(
                "Nothing to Save",
                "No text available to save.",
                parent=widget.winfo_toplevel(),
            )
            return
        path = getattr(widget, "_context_last_save_path", None)
        if not path:
            _save_as(selection_only=False)
            return
        try:
            _save_text(content, path)
        except Exception:
            _save_as(selection_only=False)

    def _copy():
        try: widget.event_generate("<<Copy>>")
        except tk.TclError: pass

    def _paste():
        try: widget.event_generate("<<Paste>>")
        except tk.TclError: pass

    def _cut():
        try: widget.event_generate("<<Cut>>")
        except tk.TclError: pass

    def _select_all():
        try:
            if _is_text_widget():
                widget.tag_add(tk.SEL, "1.0", tk.END)
                widget.mark_set(tk.INSERT, tk.END)
                widget.see(tk.INSERT)
            elif _is_entry_like():
                widget.selection_range(0, tk.END)
                widget.icursor(tk.END)
        except tk.TclError:
            pass

    if not readonly:
        menu.add_command(label="Cut", command=_cut, accelerator="Ctrl+X")
    menu.add_command(label="Copy", command=_copy, accelerator="Ctrl+C")
    if not readonly:
        menu.add_command(label="Paste", command=_paste, accelerator="Ctrl+V")
        menu.add_command(label="Delete", command=_delete_selection)
    menu.add_separator()
    menu.add_command(label="Save", command=_save)
    menu.add_command(label="Save As...", command=lambda: _save_as(selection_only=False))
    menu.add_command(label="Save Selection As...", command=lambda: _save_as(selection_only=True))
    menu.add_separator()
    menu.add_command(label="Select All", command=_select_all, accelerator="Ctrl+A")

    def _show_menu(event):
        try:
            try:
                widget.focus_set()
            except Exception:
                pass
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    # Bind all common secondary-click gestures. macOS Tk can emit Button-2
    # or Button-3 depending on device/settings; control-click is also common.
    for seq in ("<Button-3>", "<Button-2>", "<Control-Button-1>"):
        try:
            widget.bind(seq, _show_menu, add="+")
        except TypeError:
            # Some Tk wrappers may not accept add="+" (older bindings); fallback.
            widget.bind(seq, _show_menu)

    return menu


def _add_tree_context_menu(tree: ttk.Treeview):
    """Attach a right-click context menu to a Treeview."""
    menu = tk.Menu(
        tree,
        tearoff=0,
        bg=COLORS["bg_secondary"],
        fg=COLORS["fg_primary"],
        activebackground=COLORS["blue_dim"],
        activeforeground=COLORS["fg_heading"],
        font=FONTS["body"],
    )

    def _copy_selected_rows():
        rows = tree.selection()
        if not rows:
            rows = tree.get_children("")
        lines = []
        for iid in rows:
            item = tree.item(iid)
            row_text = str(item.get("text") or "")
            values = [str(v) for v in item.get("values", ())]
            if values:
                lines.append("\t".join([row_text] + values))
            elif row_text:
                lines.append(row_text)
            for child in tree.get_children(iid):
                citem = tree.item(child)
                ctext = str(citem.get("text") or "")
                cvals = [str(v) for v in citem.get("values", ())]
                if cvals:
                    lines.append("\t".join([ctext] + cvals))
                elif ctext:
                    lines.append(ctext)
        if not lines:
            return
        try:
            tree.clipboard_clear()
            tree.clipboard_append("\n".join(lines))
        except tk.TclError:
            pass

    def _select_all():
        iids: list[str] = []
        for parent in tree.get_children(""):
            iids.append(parent)
            iids.extend(tree.get_children(parent))
        if iids:
            tree.selection_set(iids)

    def _expand_all():
        for parent in tree.get_children(""):
            tree.item(parent, open=True)

    def _collapse_all():
        for parent in tree.get_children(""):
            tree.item(parent, open=False)

    menu.add_command(label="Copy Selected Row(s)", command=_copy_selected_rows)
    menu.add_separator()
    menu.add_command(label="Select All Rows", command=_select_all)
    menu.add_command(label="Expand All", command=_expand_all)
    menu.add_command(label="Collapse All", command=_collapse_all)

    def _show_menu(event):
        try:
            row = tree.identify_row(event.y)
            if row:
                try:
                    tree.selection_set((row,))
                    tree.focus(row)
                except tk.TclError:
                    pass
            tree.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    for seq in ("<Button-3>", "<Button-2>", "<Control-Button-1>"):
        try:
            tree.bind(seq, _show_menu, add="+")
        except TypeError:
            tree.bind(seq, _show_menu)
    return menu


# =====================================================================
# Clickable hyperlinks in text widgets
# =====================================================================

def _setup_hyperlink_tags(widget):
    """Configure the 'link' tag on a text widget to make URLs clickable."""
    widget.tag_configure(
        "link", foreground=COLORS["link"], underline=True,
        font=FONTS["link"] if "link" in FONTS else FONTS["mono"],
    )

    def _on_link_enter(event):
        widget.config(cursor="hand2")

    def _on_link_leave(event):
        widget.config(cursor="")

    def _on_link_click(event):
        idx = widget.index(f"@{event.x},{event.y}")
        tag_ranges = widget.tag_ranges("link")
        for i in range(0, len(tag_ranges), 2):
            start, end = tag_ranges[i], tag_ranges[i + 1]
            if widget.compare(start, "<=", idx) and widget.compare(idx, "<", end):
                url = widget.get(start, end).strip()
                if url.startswith("http://") or url.startswith("https://"):
                    webbrowser.open(url)
                break

    widget.tag_bind("link", "<Enter>", _on_link_enter)
    widget.tag_bind("link", "<Leave>", _on_link_leave)
    widget.tag_bind("link", "<Button-1>", _on_link_click)


def insert_with_links(widget, text, base_tag=None):
    """Insert text, auto-detecting and tagging URLs as clickable links."""
    url_pattern = re.compile(r'https?://[^\s<>"\')\]]+')
    pos = 0
    for match in url_pattern.finditer(text):
        before = text[pos:match.start()]
        if before:
            if base_tag: widget.insert(tk.END, before, base_tag)
            else: widget.insert(tk.END, before)
        url = match.group(0)
        tags = (base_tag, "link") if base_tag else ("link",)
        widget.insert(tk.END, url, tags)
        pos = match.end()
    remaining = text[pos:]
    if remaining:
        if base_tag: widget.insert(tk.END, remaining, base_tag)
        else: widget.insert(tk.END, remaining)


# =====================================================================
# Scrolled text with all enhancements
# =====================================================================

def _make_scrolled_text(parent, readonly=False, **overrides):
    """Create a dark-themed scrolled text widget with context menu and link support."""
    cfg = dict(
        wrap=tk.WORD, bg=COLORS["bg_output"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"],
        selectbackground=COLORS["blue_dim"],
        selectforeground=COLORS["fg_heading"],
        font=FONTS["mono"], relief="flat", bd=0, padx=8, pady=6,
    )
    cfg.update(overrides)
    widget = scrolledtext.ScrolledText(parent, **cfg)

    widget.tag_configure("bold", font=FONTS["category_header"],
                         foreground=COLORS["fg_heading"])
    widget.tag_configure("error", foreground=COLORS["red"])
    widget.tag_configure("success", foreground=COLORS["green"])

    _add_context_menu(widget, readonly=readonly)
    _setup_hyperlink_tags(widget)
    return widget


# =====================================================================
# Tab-local action bar helper
# =====================================================================

def _make_tab_action_bar(parent, bg=None):
    """Create a styled action bar frame for inside a tab."""
    return tk.Frame(parent, bg=bg or COLORS["bg_tab_actionbar"], padx=8, pady=6)


# =====================================================================
# Status bar
# =====================================================================

def create_status_bar(parent) -> dict:
    """Build the status bar (packed BOTTOM first so always visible)."""
    frame = tk.Frame(parent, bg=COLORS["bg_statusbar"], padx=8, pady=3)
    frame.pack(side=tk.BOTTOM, fill="x")

    sep = tk.Frame(parent, bg=COLORS["separator"], height=1)
    sep.pack(side=tk.BOTTOM, fill="x")

    progress_var = tk.StringVar(value="Ready")
    status_label = tk.Label(
        frame, textvariable=progress_var,
        bg=COLORS["bg_statusbar"], fg=COLORS["fg_secondary"],
        font=FONTS["statusbar"], anchor="w",
    )
    status_label.pack(side=tk.LEFT, fill="x", expand=True)

    right_frame = tk.Frame(frame, bg=COLORS["bg_statusbar"])
    right_frame.pack(side=tk.RIGHT)

    progress_detail_var = tk.StringVar(value="")
    progress_detail_label = tk.Label(
        right_frame, textvariable=progress_detail_var,
        bg=COLORS["bg_statusbar"], fg=COLORS["fg_secondary"],
        font=FONTS["statusbar"], anchor="e", width=18,
    )
    progress_detail_label.pack(side=tk.RIGHT)

    try:
        style = ttk.Style()
        style.configure(
            "Status.Horizontal.TProgressbar",
            troughcolor=COLORS["bg_entry"],
            background=COLORS["blue"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["blue"],
            darkcolor=COLORS["blue"],
        )
    except Exception:
        pass

    progress_bar = ttk.Progressbar(
        right_frame,
        orient="horizontal",
        mode="determinate",
        maximum=100,
        value=0,
        length=140,
        style="Status.Horizontal.TProgressbar",
    )
    progress_bar.pack(side=tk.RIGHT, padx=(0, 10))

    summary_var = tk.StringVar(value="")
    summary_label = tk.Label(
        right_frame, textvariable=summary_var,
        bg=COLORS["bg_statusbar"], fg=COLORS["green_fg"],
        font=FONTS["statusbar"], anchor="e",
    )
    summary_label.pack(side=tk.RIGHT, padx=(12, 10))

    return {
        "frame": frame, "status_label": status_label,
        "summary_label": summary_label,
        "progress_var": progress_var, "summary_var": summary_var,
        "progress_bar": progress_bar,
        "progress_detail_var": progress_detail_var,
        "progress_detail_label": progress_detail_label,
    }


# =====================================================================
# Menu bar
# =====================================================================

def create_menu_bar(parent) -> dict:
    """Build the application menu bar."""
    menu_style = dict(
        tearoff=0, bg=COLORS["bg_secondary"], fg=COLORS["fg_primary"],
        activebackground=COLORS["blue_dim"], activeforeground=COLORS["fg_heading"],
        font=FONTS["menu"],
    )

    menubar = tk.Menu(parent, **menu_style)

    # ---- File ----
    file_menu = tk.Menu(menubar, **menu_style)
    file_menu.add_command(label="Open File...", accelerator="Ctrl+O")
    file_menu.add_command(label="Save Input...", accelerator="Ctrl+S")
    file_menu.add_separator()
    save_iocs_menu = tk.Menu(file_menu, **menu_style)
    save_iocs_menu.add_command(label="As Group...")
    save_iocs_menu.add_command(label="Per Category...")
    save_iocs_menu.add_command(label="As JSON...")
    save_iocs_menu.add_command(label="As CSV...")
    file_menu.add_cascade(label="Export IOCs", menu=save_iocs_menu)
    file_menu.add_command(label="Save Parsed IOCs to History...")
    file_menu.add_command(label="Save VT Output...")
    file_menu.add_command(label="Save Jsluice Output...")
    file_menu.add_command(label="Save Nmap Output...")
    file_menu.add_command(label="Save Nmap Structured (JSON)...")
    file_menu.add_separator()
    file_menu.add_command(label="Exit")
    menubar.add_cascade(label="File", menu=file_menu)

    # ---- Edit ----
    edit_menu = tk.Menu(menubar, **menu_style)
    edit_menu.add_command(label="Find & Replace", accelerator="Ctrl+H")
    edit_menu.add_separator()
    edit_menu.add_command(label="Clear Input", accelerator="Ctrl+Shift+X")
    edit_menu.add_command(label="Clear IOC Review")
    edit_menu.add_command(label="Clear VT Results")
    edit_menu.add_command(label="Clear Jsluice Output")
    edit_menu.add_command(label="Clear Nmap Output")
    edit_menu.add_separator()
    edit_menu.add_command(label="Settings...")
    edit_menu.add_command(label="Clear VT API Key")
    menubar.add_cascade(label="Edit", menu=edit_menu)

    # ---- Tools ----
    tools_menu = tk.Menu(menubar, **menu_style)
    tools_menu.add_command(label="Parse IOCs", accelerator="Ctrl+P")
    tools_menu.add_command(label="Defang IOCs", accelerator="Ctrl+D")
    tools_menu.add_command(label="Refang IOCs")
    tools_menu.add_command(label="Open IOC History")
    tools_menu.add_separator()
    tools_menu.add_command(label="Run Jsluice", accelerator="Ctrl+J")
    tools_menu.add_separator()
    tools_menu.add_command(label="VT Check Selected")
    tools_menu.add_command(label="VT Submit URL(s)")
    tools_menu.add_command(label="VT Hash Check")
    tools_menu.add_command(label="VT Hash Details")
    tools_menu.add_command(label="VT MITRE TTPs")
    tools_menu.add_command(label="VT Behavior Analysis")
    tools_menu.add_command(label="VT DNS Resolutions")
    tools_menu.add_command(label="VT Communicating Files")
    tools_menu.add_separator()
    tools_menu.add_command(label="Run Nmap", accelerator="Ctrl+N")
    tools_menu.add_separator()
    tools_menu.add_command(label="Start REST API")
    tools_menu.add_command(label="Stop REST API")
    tools_menu.add_command(label="Copy REST API Token")
    tools_menu.add_command(label="Open REST API Docs")
    menubar.add_cascade(label="Tools", menu=tools_menu)

    # ---- Help ----
    help_menu = tk.Menu(menubar, **menu_style)
    help_menu.add_command(label="Keyboard Shortcuts")
    help_menu.add_command(label="Jsluice Options Help")
    help_menu.add_separator()
    help_menu.add_command(label="About IOC Citadel")
    menubar.add_cascade(label="Help", menu=help_menu)

    parent.config(menu=menubar)

    return {
        "menubar": menubar, "file_menu": file_menu,
        "save_iocs_menu": save_iocs_menu, "edit_menu": edit_menu,
        "tools_menu": tools_menu, "help_menu": help_menu,
    }


# =====================================================================
# Primary toolbar (FlowFrame — wraps responsively)
# =====================================================================

def create_primary_toolbar(
    parent,
    jsluice_available: bool = True,
    nmap_available: bool = True,
) -> dict:
    """
    Build the main action toolbar using FlowFrame for responsive wrapping.

    Groups: File | Parse | VirusTotal | Jsluice | Nmap
    All "do something" buttons live here. Tabs are for results only.
    """
    outer = tk.Frame(parent, bg=COLORS["bg_toolbar"])
    outer.pack(side=tk.TOP, fill="x")

    flow = FlowFrame(outer, bg=COLORS["bg_toolbar"], padx=4, pady=2)
    flow.pack(fill="x", padx=4, pady=2)

    _make_separator(parent).pack(side=tk.TOP, fill="x")

    widgets = {"frame": outer, "flow": flow}

    # --- File group ---
    open_btn = _make_button(flow, "Open File", "slate")
    flow.add(open_btn)
    widgets["open_btn"] = open_btn

    flow.add_separator()

    # --- Parse group ---
    flow.add_label("Parse", fg=COLORS["green"])

    parse_btn = SplitButton(
        flow, text="Parse IOCs",
        bg_color=COLORS["green"],
        hover_color=COLORS.get("green_hover", COLORS["green"]),
        fg_color=COLORS["btn_fg"],
        font=FONTS["button"],
    )
    flow.add(parse_btn)
    widgets["parse_btn"] = parse_btn
    widgets["parse_menu"] = parse_btn.menu

    defang_btn = _make_button(flow, "Defang", "slate")
    flow.add(defang_btn)
    widgets["defang_btn"] = defang_btn

    refang_btn = _make_button(flow, "Refang", "slate")
    flow.add(refang_btn)
    widgets["refang_btn"] = refang_btn

    flow.add_separator()

    # --- VirusTotal group ---
    flow.add_label("VirusTotal", fg=COLORS["blue"])

    vt_btn = SplitButton(
        flow, text="VirusTotal",
        bg_color=COLORS["blue"],
        hover_color=COLORS.get("blue_hover", COLORS["blue"]),
        fg_color=COLORS["btn_fg"],
        font=FONTS["button"],
    )
    flow.add(vt_btn)
    widgets["vt_btn"] = vt_btn
    widgets["vt_menu"] = vt_btn.menu

    flow.add_separator()

    # --- Jsluice group ---
    flow.add_label("Jsluice", fg=COLORS["orange"])

    mode_combo = ttk.Combobox(
        flow, values=JSLUICE_MODES, state="readonly", width=8,
        font=FONTS["body"],
    )
    mode_combo.set("urls")
    _add_context_menu(mode_combo, readonly=True)
    flow.add(mode_combo)
    widgets["mode_combo"] = mode_combo

    js_state = tk.NORMAL if jsluice_available else tk.DISABLED
    run_js_btn = _make_button(flow, "Run Jsluice", "orange", state=js_state)
    flow.add(run_js_btn)
    widgets["run_jsluice_btn"] = run_js_btn

    # Install button — shown only when jsluice is not available
    if not jsluice_available:
        install_js_btn = _make_button(flow, "Install jsluice", "orange")
        flow.add(install_js_btn)
        widgets["install_jsluice_btn"] = install_js_btn

    flow.add_separator()

    # --- Nmap group ---
    flow.add_label("Nmap", fg=COLORS["teal"])

    nmap_state = tk.NORMAL if nmap_available else tk.DISABLED
    run_nmap_btn = _make_button(flow, "Run Nmap", "teal", state=nmap_state)
    flow.add(run_nmap_btn)
    widgets["run_nmap_btn"] = run_nmap_btn

    # Install button — shown only when nmap is not available
    if not nmap_available:
        install_nmap_btn = _make_button(flow, "Install Nmap", "teal")
        flow.add(install_nmap_btn)
        widgets["install_nmap_btn"] = install_nmap_btn

    return widgets


# =====================================================================
# Find / Replace toolbar (toggleable)
# =====================================================================

def create_find_replace_frame(parent) -> dict:
    """Build a compact dark Find/Replace toolbar, initially hidden."""
    frame = tk.Frame(parent, bg=COLORS["bg_toolbar"], padx=8, pady=6)
    sep = _make_separator(parent)

    _make_label(frame, "Find:").grid(row=0, column=0, padx=(0, 6), pady=2, sticky="e")
    find_entry = tk.Entry(
        frame, width=40, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["body"],
        relief="flat", bd=0,
    )
    find_entry.grid(row=0, column=1, padx=4, pady=2, sticky="ew", ipady=3)
    _add_context_menu(find_entry, readonly=False)

    find_replace_btn = _make_button(frame, "Find & Replace", "blue", width=14)
    find_replace_btn.grid(row=0, column=2, padx=6, pady=2)

    _make_label(frame, "Replace:").grid(row=1, column=0, padx=(0, 6), pady=2, sticky="e")
    replace_entry = tk.Entry(
        frame, width=40, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["body"],
        relief="flat", bd=0,
    )
    replace_entry.grid(row=1, column=1, padx=4, pady=2, sticky="ew", ipady=3)
    _add_context_menu(replace_entry, readonly=False)

    regex_var = tk.IntVar()
    regex_cb = tk.Checkbutton(
        frame, text="Regex", variable=regex_var,
        bg=COLORS["bg_toolbar"], fg=COLORS["fg_secondary"],
        selectcolor=COLORS["bg_entry"], activebackground=COLORS["bg_toolbar"],
        activeforeground=COLORS["fg_primary"], font=FONTS["label"],
    )
    regex_cb.grid(row=1, column=2, padx=6, pady=2, sticky="w")

    close_btn = _make_button(frame, "Close", "red", width=6)
    close_btn.grid(row=0, column=3, rowspan=2, padx=(6, 0), pady=2)

    frame.grid_columnconfigure(1, weight=1)

    return {
        "frame": frame, "separator": sep,
        "find_entry": find_entry, "replace_entry": replace_entry,
        "find_replace_btn": find_replace_btn,
        "regex_var": regex_var, "regex_cb": regex_cb,
        "close_btn": close_btn,
    }


# =====================================================================
# Input area
# =====================================================================

def create_input_area(parent_pane) -> dict:
    """Build the main text input area with dark styling."""
    frame = tk.Frame(parent_pane, bg=COLORS["bg_primary"])

    text_widget = _make_scrolled_text(
        frame, readonly=False, height=15,
        bg=COLORS["bg_input"], fg=COLORS["fg_placeholder"],
    )
    text_widget.pack(expand=True, fill="both", padx=2, pady=2)

    text_widget.tag_configure(
        "highlight",
        background=COLORS["highlight_find"],
        foreground=COLORS["highlight_find_fg"],
    )
    text_widget.tag_configure(
        "ioc_highlight",
        background=COLORS["highlight_ioc"],
        foreground=COLORS["highlight_ioc_fg"],
    )

    drop_label = tk.Label(
        frame, text="Drop file here to load its contents",
        bg=COLORS["blue_dim"], fg=COLORS["blue_fg"],
        font=FONTS["heading"], padx=20, pady=20,
    )

    parent_pane.add(frame, stretch="always")
    return {"frame": frame, "text": text_widget, "drop_label": drop_label}


# =====================================================================
# Output notebook — lean tabs (Save + Clear only)
# =====================================================================

def create_output_notebook(parent_pane) -> dict:
    """
    Build tabbed output. Each tab is a results viewer with minimal
    Save + Clear controls. All "do" actions are in the toolbar.
    """
    notebook = ttk.Notebook(parent_pane)

    try:
        style = ttk.Style()
        if _IS_LINUX:
            style.theme_use("clam")
        elif _IS_WINDOWS:
            style.theme_use("winnative")
        else:
            style.theme_use("default")

        style.configure("TNotebook",
                        background=COLORS["bg_primary"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=COLORS["bg_secondary"],
                        foreground=COLORS["fg_secondary"],
                        font=FONTS["tab"], padding=[14, 6])
        style.map("TNotebook.Tab",
                   background=[("selected", COLORS["bg_primary"])],
                   foreground=[("selected", COLORS["fg_heading"])],
                   expand=[("selected", [0, 0, 0, 2])])
        style.configure(
            "Treeview",
            background=COLORS["bg_output"],
            fieldbackground=COLORS["bg_output"],
            foreground=COLORS["fg_primary"],
            rowheight=22,
            borderwidth=0,
            font=FONTS["mono_small"],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["bg_tab_actionbar"],
            foreground=COLORS["fg_heading"],
            font=FONTS["label"],
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["blue_dim"])],
            foreground=[("selected", COLORS["fg_heading"])],
        )
    except Exception:
        pass

    all_widgets = {"notebook": notebook}

    # ==================================================================
    # IOC Review tab
    # ==================================================================
    review_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(review_frame, bg=COLORS["green"], height=2).pack(fill="x")

    review_split = tk.PanedWindow(
        review_frame, orient=tk.VERTICAL, sashrelief=tk.FLAT,
        sashwidth=5, bg=COLORS["bg_sash"], bd=0,
    )
    review_split.pack(expand=True, fill="both", padx=2, pady=(0, 0))

    # Structured table (primary)
    review_tree_frame = tk.Frame(review_split, bg=COLORS["bg_primary"])
    review_tree_header = tk.Frame(
        review_tree_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=4
    )
    review_tree_header.pack(fill="x")

    tk.Label(
        review_tree_header, text="Structured IOC Table",
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["green_fg"],
        font=FONTS["label"],
    ).pack(side="left")

    review_tree_sel_var = tk.StringVar(value="0 selected")
    tk.Label(
        review_tree_header, textvariable=review_tree_sel_var,
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"],
        font=FONTS["label"],
    ).pack(side="right")

    tree_wrap = tk.Frame(review_tree_frame, bg=COLORS["bg_primary"])
    tree_wrap.pack(expand=True, fill="both")

    review_tree = ttk.Treeview(
        tree_wrap,
        columns=("ioc", "count", "selected", "status", "source"),
        show=("tree", "headings"),
        selectmode="extended",
    )
    review_tree.heading("#0", text="Type")
    review_tree.column("#0", width=170, minwidth=120, stretch=False)
    review_tree.heading("ioc", text="IOC")
    review_tree.column("ioc", width=520, minwidth=220, stretch=True)
    review_tree.heading("count", text="Count")
    review_tree.column("count", width=70, minwidth=60, anchor="center", stretch=False)
    review_tree.heading("selected", text="Selected")
    review_tree.column("selected", width=78, minwidth=70, anchor="center", stretch=False)
    review_tree.heading("status", text="Status")
    review_tree.column("status", width=100, minwidth=80, anchor="center", stretch=False)
    review_tree.heading("source", text="Source")
    review_tree.column("source", width=90, minwidth=80, anchor="center", stretch=False)
    review_tree.tag_configure("category", foreground=COLORS["green_fg"])
    review_tree.tag_configure("ioc_row", foreground=COLORS["fg_primary"])
    review_tree.tag_configure("muted", foreground=COLORS["fg_secondary"])
    _add_tree_context_menu(review_tree)

    review_tree_y = ttk.Scrollbar(tree_wrap, orient="vertical", command=review_tree.yview)
    review_tree_x = ttk.Scrollbar(tree_wrap, orient="horizontal", command=review_tree.xview)
    review_tree.configure(yscrollcommand=review_tree_y.set, xscrollcommand=review_tree_x.set)

    review_tree.grid(row=0, column=0, sticky="nsew")
    review_tree_y.grid(row=0, column=1, sticky="ns")
    review_tree_x.grid(row=1, column=0, sticky="ew")
    tree_wrap.grid_columnconfigure(0, weight=1)
    tree_wrap.grid_rowconfigure(0, weight=1)

    # Legacy text view (secondary)
    review_text_frame = tk.Frame(review_split, bg=COLORS["bg_primary"])
    review_text_header = tk.Frame(
        review_text_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=4
    )
    review_text_header.pack(fill="x")
    tk.Label(
        review_text_header,
        text="Review Text (Legacy / Copy-friendly)",
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["fg_secondary"],
        font=FONTS["label"],
    ).pack(side="left")

    review_text = _make_scrolled_text(review_text_frame, height=8)
    review_text.pack(expand=True, fill="both")

    review_split.add(review_tree_frame, stretch="always")
    review_split.add(review_text_frame, stretch="always")

    review_bar = _make_tab_action_bar(review_frame)
    review_bar.pack(fill="x")

    # Save dropdown (Group / Per Category / JSON / CSV)
    save_mb, save_menu, save_indices = _make_menubutton(
        review_bar, "Save / Export \u25be", "green",
        [
            ("Save as Group...", "save_group_btn"),
            ("Save to History (SQLite)...", "save_history_btn"),
            ("Save Per Category...", "save_individual_btn"),
            ("Export as JSON...", "save_json_btn"),
            ("Export as CSV...", "save_csv_btn"),
        ],
    )
    save_mb.grid(row=0, column=0, padx=2, pady=2)
    all_widgets["save_menubutton"] = save_mb
    all_widgets["save_menu"] = save_menu
    all_widgets["save_menu_indices"] = save_indices

    select_all_ioc_rows_btn = _make_button(review_bar, "Select All", "slate")
    select_all_ioc_rows_btn.grid(row=0, column=1, padx=(8, 2), pady=2)
    all_widgets["select_all_ioc_rows_btn"] = select_all_ioc_rows_btn

    clear_ioc_selection_btn = _make_button(review_bar, "Clear Sel", "slate")
    clear_ioc_selection_btn.grid(row=0, column=2, padx=2, pady=2)
    all_widgets["clear_ioc_selection_btn"] = clear_ioc_selection_btn

    copy_selected_ioc_btn = _make_button(review_bar, "Copy Selected", "slate")
    copy_selected_ioc_btn.grid(row=0, column=3, padx=2, pady=2)
    all_widgets["copy_selected_ioc_btn"] = copy_selected_ioc_btn

    review_vt_btn = _make_button(review_bar, "VT Check Selected", "blue")
    review_vt_btn.grid(row=0, column=4, padx=(8, 2), pady=2)
    all_widgets["review_vt_btn"] = review_vt_btn

    save_history_btn = _make_button(review_bar, "Save to History", "green")
    save_history_btn.grid(row=0, column=5, padx=(8, 2), pady=2)
    all_widgets["save_iocs_history_btn"] = save_history_btn

    open_history_tab_btn = _make_button(review_bar, "History", "blue")
    open_history_tab_btn.grid(row=0, column=6, padx=2, pady=2)
    all_widgets["open_history_tab_btn"] = open_history_tab_btn

    review_bar.grid_columnconfigure(7, weight=1)

    clear_ioc_btn = _make_button(review_bar, "Clear", "red")
    clear_ioc_btn.grid(row=0, column=8, padx=2, pady=2)
    all_widgets["clear_ioc_btn"] = clear_ioc_btn

    notebook.add(review_frame, text="  IOC Review  ")
    all_widgets["review_text"] = review_text
    all_widgets["review_tree"] = review_tree
    all_widgets["review_tree_split"] = review_split
    all_widgets["review_tree_sel_var"] = review_tree_sel_var

    # ==================================================================
    # VirusTotal tab
    # ==================================================================
    vt_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(vt_frame, bg=COLORS["blue"], height=2).pack(fill="x")

    vt_text = _make_scrolled_text(vt_frame, height=10)
    vt_text.pack(expand=True, fill="both", padx=2, pady=(0, 0))

    vt_bar = _make_tab_action_bar(vt_frame)
    vt_bar.pack(fill="x")

    save_vt_btn = _make_button(vt_bar, "Save", "green")
    save_vt_btn.grid(row=0, column=0, padx=2, pady=2)
    all_widgets["save_vt_btn"] = save_vt_btn

    vt_bar.grid_columnconfigure(1, weight=1)

    clear_vt_btn = _make_button(vt_bar, "Clear", "red")
    clear_vt_btn.grid(row=0, column=2, padx=2, pady=2)
    all_widgets["clear_vt_btn"] = clear_vt_btn

    notebook.add(vt_frame, text="  VirusTotal  ")
    all_widgets["vt_text"] = vt_text

    # ==================================================================
    # Jsluice tab
    # ==================================================================
    jsluice_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(jsluice_frame, bg=COLORS["orange"], height=2).pack(fill="x")

    jsluice_text = _make_scrolled_text(jsluice_frame, height=10)
    jsluice_text.pack(expand=True, fill="both", padx=2, pady=(0, 0))

    js_bar = _make_tab_action_bar(jsluice_frame)
    js_bar.pack(fill="x")

    # Secondary Jsluice config (options + raw) — rarely used, lives in tab
    col = 0
    tk.Label(js_bar, text="Options:", font=FONTS["label"],
             bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"]
             ).grid(row=0, column=col, padx=(0, 4))
    col += 1

    options_entry = tk.Entry(
        js_bar, width=20, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["body"],
        relief="flat", bd=0,
    )
    options_entry.grid(row=0, column=col, padx=2, ipady=3, sticky="ew")
    _add_context_menu(options_entry, readonly=False)
    all_widgets["options_entry"] = options_entry
    col += 1

    js_bar.grid_columnconfigure(col - 1, weight=1)

    help_btn = _make_button(js_bar, "?", "slate", width=2)
    help_btn.grid(row=0, column=col, padx=2)
    all_widgets["help_btn"] = help_btn
    col += 1

    raw_var = tk.IntVar()
    raw_cb = tk.Checkbutton(
        js_bar, text="Raw", variable=raw_var,
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"],
        selectcolor=COLORS["bg_entry"], activebackground=COLORS["bg_tab_actionbar"],
        activeforeground=COLORS["fg_primary"], font=FONTS["label"],
    )
    raw_cb.grid(row=0, column=col, padx=2)
    all_widgets["raw_var"] = raw_var
    col += 1

    save_js_btn = _make_button(js_bar, "Save", "green")
    save_js_btn.grid(row=0, column=col, padx=(8, 2))
    all_widgets["save_jsluice_btn"] = save_js_btn
    col += 1

    clear_js_btn = _make_button(js_bar, "Clear", "red")
    clear_js_btn.grid(row=0, column=col, padx=2)
    all_widgets["clear_jsluice_btn"] = clear_js_btn

    notebook.add(jsluice_frame, text="  Jsluice  ")
    all_widgets["jsluice_text"] = jsluice_text

    # ==================================================================
    # Shell Command tab
    # ==================================================================
    shell_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(shell_frame, bg=COLORS["purple"], height=2).pack(fill="x")

    shell_output = _make_scrolled_text(
        shell_frame, height=10, fg=COLORS["purple_fg"],
    )
    shell_output.pack(expand=True, fill="both", padx=2, pady=(0, 0))

    shell_bar = _make_tab_action_bar(shell_frame)
    shell_bar.pack(fill="x")

    _make_label(shell_bar, "Command:", fg=COLORS["purple_fg"],
                bg=COLORS["bg_tab_actionbar"]).grid(row=0, column=0, padx=(0, 6))

    shell_entry = tk.Entry(
        shell_bar, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["mono_small"],
        relief="flat", bd=0,
    )
    shell_entry.grid(row=0, column=1, padx=4, ipady=3, sticky="ew")
    _add_context_menu(shell_entry, readonly=False)
    shell_bar.grid_columnconfigure(1, weight=1)

    shell_run_btn = _make_button(shell_bar, "Run", "purple", width=8)
    shell_run_btn.grid(row=0, column=2, padx=(6, 0))

    notebook.add(shell_frame, text="  Shell  ")
    all_widgets["shell_output"] = shell_output
    all_widgets["shell_entry"] = shell_entry
    all_widgets["shell_run_btn"] = shell_run_btn

    # ==================================================================
    # Nmap tab
    # ==================================================================
    nmap_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(nmap_frame, bg=COLORS["teal"], height=2).pack(fill="x")

    # --- Config bar (target, scan type, flags, extra args) ---
    nmap_config = tk.Frame(nmap_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=6)
    nmap_config.pack(fill="x")

    # Row 0: Target + Scan Type + Timing
    tk.Label(
        nmap_config, text="Target:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["teal_fg"],
    ).grid(row=0, column=0, padx=(0, 4), pady=2, sticky="e")

    nmap_target = tk.Entry(
        nmap_config, width=30, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["mono_small"],
        relief="flat", bd=0,
    )
    nmap_target.grid(row=0, column=1, padx=4, pady=2, ipady=3, sticky="ew")
    _add_context_menu(nmap_target, readonly=False)
    all_widgets["nmap_target"] = nmap_target

    tk.Label(
        nmap_config, text="Scan:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["teal_fg"],
    ).grid(row=0, column=2, padx=(12, 4), pady=2, sticky="e")

    scan_labels = [label for label, _flag in NMAP_SCAN_TYPES]
    nmap_scan_combo = ttk.Combobox(
        nmap_config, values=scan_labels, state="readonly", width=22,
        font=FONTS["body"],
    )
    nmap_scan_combo.set(scan_labels[0])
    nmap_scan_combo.grid(row=0, column=3, padx=4, pady=2)
    _add_context_menu(nmap_scan_combo, readonly=True)
    all_widgets["nmap_scan_combo"] = nmap_scan_combo

    tk.Label(
        nmap_config, text="Timing:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["teal_fg"],
    ).grid(row=0, column=4, padx=(12, 4), pady=2, sticky="e")

    timing_labels = [label for label, _flag in NMAP_TIMING_TEMPLATES]
    nmap_timing_combo = ttk.Combobox(
        nmap_config, values=timing_labels, state="readonly", width=16,
        font=FONTS["body"],
    )
    nmap_timing_combo.set(timing_labels[0])
    nmap_timing_combo.grid(row=0, column=5, padx=4, pady=2)
    _add_context_menu(nmap_timing_combo, readonly=True)
    all_widgets["nmap_timing_combo"] = nmap_timing_combo

    nmap_config.grid_columnconfigure(1, weight=1)

    # Row 1: sudo + Ports + common flags (checkboxes) — scrollable
    flag_frame = tk.Frame(nmap_config, bg=COLORS["bg_tab_actionbar"])
    flag_frame.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(4, 2))

    # sudo checkbox (highlighted — important for privileged scans)
    sudo_var = tk.IntVar()
    sudo_cb = tk.Checkbutton(
        flag_frame, text="sudo", variable=sudo_var,
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["orange"],
        selectcolor=COLORS["bg_entry"],
        activebackground=COLORS["bg_tab_actionbar"],
        activeforeground=COLORS["orange"],
        font=FONTS["button"],
    )
    sudo_cb.pack(side=tk.LEFT, padx=(0, 4))
    all_widgets["nmap_sudo_var"] = sudo_var
    all_widgets["nmap_sudo_cb"] = sudo_cb

    # Separator between sudo and ports
    tk.Frame(
        flag_frame, bg=COLORS["separator"], width=1, height=16,
    ).pack(side=tk.LEFT, padx=6, fill="y")

    # Ports entry (e.g., "22,80,443" or "1-1024")
    tk.Label(
        flag_frame, text="Ports:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["teal_fg"],
    ).pack(side=tk.LEFT, padx=(0, 4))

    nmap_ports_entry = tk.Entry(
        flag_frame, width=18, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["mono_small"],
        relief="flat", bd=0,
    )
    nmap_ports_entry.pack(side=tk.LEFT, padx=(0, 4), ipady=2)
    _add_context_menu(nmap_ports_entry, readonly=False)
    all_widgets["nmap_ports_entry"] = nmap_ports_entry

    # Separator between ports and flags
    tk.Frame(
        flag_frame, bg=COLORS["separator"], width=1, height=16,
    ).pack(side=tk.LEFT, padx=6, fill="y")

    tk.Label(
        flag_frame, text="Flags:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"],
    ).pack(side=tk.LEFT, padx=(0, 4))

    nmap_flag_vars = []
    for flag, description in NMAP_COMMON_FLAGS:
        var = tk.IntVar()
        cb = tk.Checkbutton(
            flag_frame, text=flag, variable=var,
            bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"],
            selectcolor=COLORS["bg_entry"],
            activebackground=COLORS["bg_tab_actionbar"],
            activeforeground=COLORS["fg_primary"],
            font=FONTS["label"],
        )
        cb.pack(side=tk.LEFT, padx=3)
        nmap_flag_vars.append((flag, var))
    all_widgets["nmap_flag_vars"] = nmap_flag_vars

    # Row 2: Extra args + Run button
    extra_frame = tk.Frame(nmap_config, bg=COLORS["bg_tab_actionbar"])
    extra_frame.grid(row=2, column=0, columnspan=6, sticky="ew", pady=(2, 2))

    tk.Label(
        extra_frame, text="Extra args:", font=FONTS["label"],
        bg=COLORS["bg_tab_actionbar"], fg=COLORS["fg_secondary"],
    ).pack(side=tk.LEFT, padx=(0, 4))

    nmap_extra_entry = tk.Entry(
        extra_frame, bg=COLORS["bg_entry"], fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"], font=FONTS["mono_small"],
        relief="flat", bd=0,
    )
    nmap_extra_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=4, ipady=3)
    _add_context_menu(nmap_extra_entry, readonly=False)
    all_widgets["nmap_extra_entry"] = nmap_extra_entry

    nmap_stop_btn = _make_button(extra_frame, "Stop", "red", width=6)
    nmap_stop_btn.pack(side=tk.RIGHT, padx=(4, 0))
    all_widgets["nmap_stop_btn"] = nmap_stop_btn

    nmap_tab_run_btn = _make_button(extra_frame, "Run Nmap", "teal", width=10)
    nmap_tab_run_btn.pack(side=tk.RIGHT, padx=(8, 0))
    all_widgets["nmap_tab_run_btn"] = nmap_tab_run_btn

    _make_separator(nmap_frame).pack(fill="x")

    # --- Results pane (split: raw output + structured data) ---
    nmap_pane = tk.PanedWindow(
        nmap_frame, orient=tk.VERTICAL, sashrelief=tk.RAISED,
        sashwidth=6, bg=COLORS["bg_sash"], bd=0,
        opaqueresize=True,
    )
    nmap_pane.pack(expand=True, fill="both", padx=2, pady=(0, 0))
    all_widgets["nmap_pane"] = nmap_pane

    # Raw output (ANSI-colored)
    nmap_output_frame = tk.Frame(nmap_pane, bg=COLORS["bg_primary"])

    # Header bar with label + maximize button
    raw_header = tk.Frame(nmap_output_frame, bg=COLORS["bg_tab_actionbar"])
    raw_header.pack(fill="x")
    tk.Label(
        raw_header, text="Raw Output",
        font=FONTS["label"], bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["teal_fg"],
    ).pack(side=tk.LEFT, padx=8, pady=2)

    nmap_toggle_raw_btn = _make_button(raw_header, "Maximize", "teal", width=8)
    nmap_toggle_raw_btn.pack(side=tk.RIGHT, padx=4, pady=2)
    all_widgets["nmap_toggle_raw_btn"] = nmap_toggle_raw_btn

    nmap_output = _make_scrolled_text(nmap_output_frame, height=8)
    nmap_output.pack(expand=True, fill="both")
    nmap_pane.add(nmap_output_frame, stretch="always")
    all_widgets["nmap_output"] = nmap_output
    all_widgets["nmap_output_frame"] = nmap_output_frame

    # Structured data
    nmap_struct_frame = tk.Frame(nmap_pane, bg=COLORS["bg_primary"])

    # Header bar with label + maximize button
    struct_label_bar = tk.Frame(nmap_struct_frame, bg=COLORS["bg_tab_actionbar"])
    struct_label_bar.pack(fill="x")
    tk.Label(
        struct_label_bar, text="Structured Data",
        font=FONTS["label"], bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["teal_fg"],
    ).pack(side=tk.LEFT, padx=8, pady=2)

    nmap_toggle_struct_btn = _make_button(struct_label_bar, "Maximize", "teal", width=8)
    nmap_toggle_struct_btn.pack(side=tk.RIGHT, padx=4, pady=2)
    all_widgets["nmap_toggle_struct_btn"] = nmap_toggle_struct_btn

    nmap_structured = _make_scrolled_text(
        nmap_struct_frame, readonly=True, height=6,
    )
    nmap_structured.pack(expand=True, fill="both")
    nmap_pane.add(nmap_struct_frame, stretch="always")
    all_widgets["nmap_structured"] = nmap_structured
    all_widgets["nmap_struct_frame"] = nmap_struct_frame

    # --- Nmap action bar ---
    nmap_bar = _make_tab_action_bar(nmap_frame)
    nmap_bar.pack(fill="x")

    save_nmap_mb, save_nmap_menu, save_nmap_indices = _make_menubutton(
        nmap_bar, "Save \u25be", "green",
        [
            ("Save Raw Output...", "save_nmap_raw"),
            ("Save Structured (JSON)...", "save_nmap_json"),
        ],
    )
    save_nmap_mb.grid(row=0, column=0, padx=2, pady=2)
    all_widgets["save_nmap_menubutton"] = save_nmap_mb
    all_widgets["save_nmap_menu"] = save_nmap_menu
    all_widgets["save_nmap_menu_indices"] = save_nmap_indices

    nmap_bar.grid_columnconfigure(1, weight=1)

    clear_nmap_btn = _make_button(nmap_bar, "Clear", "red")
    clear_nmap_btn.grid(row=0, column=2, padx=2, pady=2)
    all_widgets["clear_nmap_btn"] = clear_nmap_btn

    notebook.add(nmap_frame, text="  Nmap  ")

    # ==================================================================
    # IOC History tab (SQLite-backed saved IOC collections)
    # ==================================================================
    history_frame = tk.Frame(notebook, bg=COLORS["bg_primary"])
    tk.Frame(history_frame, bg=COLORS["teal"], height=2).pack(fill="x")

    history_topbar = _make_tab_action_bar(history_frame)
    history_topbar.pack(fill="x")

    tk.Label(
        history_topbar,
        text="Search:",
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["teal_fg"],
        font=FONTS["label"],
    ).grid(row=0, column=0, padx=(0, 6), pady=2)

    history_search_entry = tk.Entry(
        history_topbar,
        bg=COLORS["bg_entry"],
        fg=COLORS["fg_primary"],
        insertbackground=COLORS["fg_primary"],
        font=FONTS["body"],
        relief="flat",
        bd=0,
    )
    history_search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6), ipady=3)
    _add_context_menu(history_search_entry, readonly=False)
    all_widgets["history_search_entry"] = history_search_entry

    history_search_btn = _make_button(history_topbar, "Search", "blue", width=8)
    history_search_btn.grid(row=0, column=2, padx=2, pady=2)
    all_widgets["history_search_btn"] = history_search_btn

    history_refresh_btn = _make_button(history_topbar, "Recent", "teal", width=8)
    history_refresh_btn.grid(row=0, column=3, padx=2, pady=2)
    all_widgets["history_refresh_btn"] = history_refresh_btn

    history_clear_search_btn = _make_button(history_topbar, "Clear", "red", width=7)
    history_clear_search_btn.grid(row=0, column=4, padx=(2, 8), pady=2)
    all_widgets["history_clear_search_btn"] = history_clear_search_btn

    history_topbar.grid_columnconfigure(1, weight=1)

    history_count_var = tk.StringVar(value="History: 0 collections")
    tk.Label(
        history_topbar,
        textvariable=history_count_var,
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["fg_secondary"],
        font=FONTS["label"],
    ).grid(row=0, column=5, padx=(8, 8), sticky="e")
    all_widgets["history_count_var"] = history_count_var

    history_save_current_btn = _make_button(history_topbar, "Save Current", "green")
    history_save_current_btn.grid(row=0, column=6, padx=(8, 2), pady=2)
    all_widgets["history_save_current_btn"] = history_save_current_btn

    history_load_btn = _make_button(history_topbar, "Load to Review", "blue")
    history_load_btn.grid(row=0, column=7, padx=2, pady=2)
    all_widgets["history_load_btn"] = history_load_btn

    history_main = tk.PanedWindow(
        history_frame,
        orient=tk.VERTICAL,
        sashrelief=tk.FLAT,
        sashwidth=5,
        bg=COLORS["bg_sash"],
        bd=0,
    )
    history_main.pack(expand=True, fill="both", padx=2, pady=(0, 0))
    all_widgets["history_split"] = history_main

    # Upper pane: collection summaries
    history_col_frame = tk.Frame(history_main, bg=COLORS["bg_primary"])
    history_col_header = tk.Frame(
        history_col_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=4
    )
    history_col_header.pack(fill="x")
    tk.Label(
        history_col_header,
        text="Saved IOC Collections",
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["teal_fg"],
        font=FONTS["label"],
    ).pack(side="left")

    history_col_wrap = tk.Frame(history_col_frame, bg=COLORS["bg_primary"])
    history_col_wrap.pack(expand=True, fill="both")

    history_collections_tree = ttk.Treeview(
        history_col_wrap,
        columns=("threat_context", "ioc_count", "category_count", "created_at", "source"),
        show=("tree", "headings"),
        selectmode="browse",
    )
    history_collections_tree.heading("#0", text="Collection Name")
    history_collections_tree.column("#0", width=280, minwidth=180, stretch=True)
    history_collections_tree.heading("threat_context", text="Threat / Malware / Group")
    history_collections_tree.column("threat_context", width=220, minwidth=140, stretch=True)
    history_collections_tree.heading("ioc_count", text="IOCs")
    history_collections_tree.column("ioc_count", width=70, minwidth=60, anchor="center", stretch=False)
    history_collections_tree.heading("category_count", text="Cats")
    history_collections_tree.column("category_count", width=70, minwidth=60, anchor="center", stretch=False)
    history_collections_tree.heading("created_at", text="Saved")
    history_collections_tree.column("created_at", width=165, minwidth=140, stretch=False)
    history_collections_tree.heading("source", text="Source")
    history_collections_tree.column("source", width=90, minwidth=80, anchor="center", stretch=False)
    history_collections_tree.tag_configure("muted", foreground=COLORS["fg_secondary"])
    _add_tree_context_menu(history_collections_tree)

    hist_col_y = ttk.Scrollbar(history_col_wrap, orient="vertical",
                               command=history_collections_tree.yview)
    hist_col_x = ttk.Scrollbar(history_col_wrap, orient="horizontal",
                               command=history_collections_tree.xview)
    history_collections_tree.configure(
        yscrollcommand=hist_col_y.set,
        xscrollcommand=hist_col_x.set,
    )

    history_collections_tree.grid(row=0, column=0, sticky="nsew")
    hist_col_y.grid(row=0, column=1, sticky="ns")
    hist_col_x.grid(row=1, column=0, sticky="ew")
    history_col_wrap.grid_columnconfigure(0, weight=1)
    history_col_wrap.grid_rowconfigure(0, weight=1)

    history_main.add(history_col_frame, stretch="always")
    all_widgets["history_collections_tree"] = history_collections_tree

    # Lower pane: IOC rows + metadata detail
    history_bottom = tk.PanedWindow(
        history_main,
        orient=tk.HORIZONTAL,
        sashrelief=tk.FLAT,
        sashwidth=5,
        bg=COLORS["bg_sash"],
        bd=0,
    )
    history_main.add(history_bottom, stretch="always")
    all_widgets["history_bottom_split"] = history_bottom

    history_entries_frame = tk.Frame(history_bottom, bg=COLORS["bg_primary"])
    history_entries_header = tk.Frame(
        history_entries_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=4
    )
    history_entries_header.pack(fill="x")
    tk.Label(
        history_entries_header,
        text="Collection IOCs",
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["fg_secondary"],
        font=FONTS["label"],
    ).pack(side="left")

    history_toggle_entries_btn = _make_button(history_entries_header, "Maximize", "teal", width=8)
    history_toggle_entries_btn.pack(side="right", padx=4, pady=2)
    all_widgets["history_toggle_entries_btn"] = history_toggle_entries_btn

    history_entries_wrap = tk.Frame(history_entries_frame, bg=COLORS["bg_primary"])
    history_entries_wrap.pack(expand=True, fill="both")

    history_entries_tree = ttk.Treeview(
        history_entries_wrap,
        columns=("ioc", "normalized", "source"),
        show=("tree", "headings"),
        selectmode="extended",
    )
    history_entries_tree.heading("#0", text="Type")
    history_entries_tree.column("#0", width=140, minwidth=110, stretch=False)
    history_entries_tree.heading("ioc", text="IOC")
    history_entries_tree.column("ioc", width=360, minwidth=180, stretch=True)
    history_entries_tree.heading("normalized", text="Normalized")
    history_entries_tree.column("normalized", width=360, minwidth=180, stretch=True)
    history_entries_tree.heading("source", text="Source")
    history_entries_tree.column("source", width=80, minwidth=70, anchor="center", stretch=False)
    history_entries_tree.tag_configure("category", foreground=COLORS["teal_fg"])
    history_entries_tree.tag_configure("muted", foreground=COLORS["fg_secondary"])
    _add_tree_context_menu(history_entries_tree)

    hist_entries_y = ttk.Scrollbar(
        history_entries_wrap, orient="vertical", command=history_entries_tree.yview
    )
    hist_entries_x = ttk.Scrollbar(
        history_entries_wrap, orient="horizontal", command=history_entries_tree.xview
    )
    history_entries_tree.configure(
        yscrollcommand=hist_entries_y.set,
        xscrollcommand=hist_entries_x.set,
    )

    history_entries_tree.grid(row=0, column=0, sticky="nsew")
    hist_entries_y.grid(row=0, column=1, sticky="ns")
    hist_entries_x.grid(row=1, column=0, sticky="ew")
    history_entries_wrap.grid_columnconfigure(0, weight=1)
    history_entries_wrap.grid_rowconfigure(0, weight=1)
    history_bottom.add(history_entries_frame, stretch="always")
    all_widgets["history_entries_tree"] = history_entries_tree
    all_widgets["history_entries_frame"] = history_entries_frame

    history_detail_frame = tk.Frame(history_bottom, bg=COLORS["bg_primary"])
    history_detail_header = tk.Frame(
        history_detail_frame, bg=COLORS["bg_tab_actionbar"], padx=8, pady=4
    )
    history_detail_header.pack(fill="x")
    tk.Label(
        history_detail_header,
        text="Collection Details",
        bg=COLORS["bg_tab_actionbar"],
        fg=COLORS["fg_secondary"],
        font=FONTS["label"],
    ).pack(side="left")

    history_toggle_details_btn = _make_button(history_detail_header, "Maximize", "teal", width=8)
    history_toggle_details_btn.pack(side="right", padx=4, pady=2)
    all_widgets["history_toggle_details_btn"] = history_toggle_details_btn

    history_details_text = _make_scrolled_text(history_detail_frame, readonly=True, height=8)
    history_details_text.pack(expand=True, fill="both")
    history_bottom.add(history_detail_frame, stretch="always")
    all_widgets["history_details_text"] = history_details_text
    all_widgets["history_detail_frame"] = history_detail_frame

    history_bar = _make_tab_action_bar(history_frame)
    history_bar.pack(fill="x")

    history_copy_btn = _make_button(history_bar, "Copy Selected IOCs", "blue")
    history_copy_btn.grid(row=0, column=0, padx=2, pady=2)
    all_widgets["history_copy_btn"] = history_copy_btn

    history_bar.grid_columnconfigure(1, weight=1)

    history_reload_btn = _make_button(history_bar, "Reload Search", "teal")
    history_reload_btn.grid(row=0, column=2, padx=2, pady=2)
    all_widgets["history_reload_btn"] = history_reload_btn

    notebook.add(history_frame, text="  IOC History  ")

    parent_pane.add(notebook, stretch="always")
    return all_widgets
