"""Visual theme: v1's neon-green-on-black terminal look, polished.

Same color identity as v1's THEME dict (main.py:34-42) — the point is a
graphical *upgrade*, not a rebrand — but with a wider token set (panel_alt,
border, muted) so buttons/panels/hover states have real depth instead of
one flat panel color, plus consistent ttk styling for every widget class
v1 left at Tk defaults.
"""

from __future__ import annotations

import tkinter.font as tk_font
from tkinter import ttk

THEME = {
    "bg": "#0a0f0a",
    "panel": "#12170f",
    "panel_alt": "#1b2318",
    "border": "#2a3527",
    "fg": "#d9ffd9",
    "accent": "#39ff6a",
    "accent_dim": "#1f8f3d",
    "accent_text": "#00140a",
    "warn": "#ffcc00",
    "error": "#ff5252",
    "info": "#4dd2ff",
    "muted": "#7f8f7a",
}


def apply(root) -> dict[str, tk_font.Font]:
    """Configure ttk styles + scalable fonts. Returns the font handles."""
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    families = set(tk_font.families())
    mono_family = next((f for f in ("Consolas", "DejaVu Sans Mono", "Liberation Mono") if f in families), "Courier")
    ui_family = next((f for f in ("Segoe UI", "DejaVu Sans", "Liberation Sans") if f in families), "TkDefaultFont")

    fonts = {
        "ui": tk_font.Font(family=ui_family, size=10),
        "ui_bold": tk_font.Font(family=ui_family, size=10, weight="bold"),
        "mono": tk_font.Font(family=mono_family, size=10),
        "mono_bold": tk_font.Font(family=mono_family, size=10, weight="bold"),
        "title": tk_font.Font(family=ui_family, size=13, weight="bold"),
    }
    root.option_add("*Font", fonts["ui"])
    root.configure(bg=THEME["bg"])

    style.configure("TFrame", background=THEME["bg"])
    style.configure("Panel.TFrame", background=THEME["panel"])
    style.configure("Toolbar.TFrame", background=THEME["panel"])

    style.configure("TLabel", background=THEME["bg"], foreground=THEME["fg"])
    style.configure("Panel.TLabel", background=THEME["panel"], foreground=THEME["fg"])
    style.configure("Toolbar.TLabel", background=THEME["panel"], foreground=THEME["fg"])
    style.configure("Muted.TLabel", background=THEME["bg"], foreground=THEME["muted"])
    style.configure("PanelMuted.TLabel", background=THEME["panel"], foreground=THEME["muted"])
    style.configure("Heading.TLabel", background=THEME["bg"], foreground=THEME["accent"], font=fonts["title"])
    style.configure("Warn.TLabel", background=THEME["bg"], foreground=THEME["warn"])
    style.configure("Error.TLabel", background=THEME["bg"], foreground=THEME["error"])

    style.configure("TButton", background=THEME["panel_alt"], foreground=THEME["fg"],
                     borderwidth=1, relief="flat", padding=(10, 6))
    style.map("TButton",
              background=[("active", THEME["border"]), ("disabled", THEME["panel"])],
              foreground=[("disabled", THEME["muted"])])

    style.configure("Accent.TButton", background=THEME["accent_dim"], foreground=THEME["accent_text"],
                     font=fonts["ui_bold"], padding=(10, 6))
    style.map("Accent.TButton",
              background=[("active", THEME["accent"]), ("disabled", THEME["panel"])],
              foreground=[("disabled", THEME["muted"])])

    style.configure("Danger.TButton", background=THEME["error"], foreground="#1a0000",
                     font=fonts["ui_bold"], padding=(10, 6))
    style.map("Danger.TButton", background=[("active", "#ff7676"), ("disabled", THEME["panel"])])

    style.configure("TCombobox", fieldbackground=THEME["panel_alt"], background=THEME["panel_alt"],
                     foreground=THEME["fg"], arrowcolor=THEME["fg"])
    style.map("TCombobox", fieldbackground=[("readonly", THEME["panel_alt"])])

    style.configure("TEntry", fieldbackground=THEME["panel_alt"], foreground=THEME["fg"],
                     insertcolor=THEME["fg"])

    style.configure("Treeview", background=THEME["bg"], fieldbackground=THEME["bg"],
                     foreground=THEME["fg"], font=fonts["mono"], rowheight=22, borderwidth=0)
    style.configure("Treeview.Heading", background=THEME["panel"], foreground=THEME["accent"],
                     font=fonts["mono_bold"], relief="flat")
    style.map("Treeview",
              background=[("selected", THEME["accent_dim"])],
              foreground=[("selected", THEME["accent_text"])])

    style.configure("TNotebook", background=THEME["bg"], borderwidth=0, tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=THEME["panel"], foreground=THEME["muted"], padding=(14, 7))
    # Both states listed explicitly, not just "selected" — under the clam
    # theme, leaving the unselected state to fall back on configure()
    # alone rendered backwards (inactive tab looked highlighted, active
    # tab looked plain), confirmed live/reported by the user.
    style.map("TNotebook.Tab",
              background=[("selected", THEME["accent_dim"]), ("!selected", THEME["panel"])],
              foreground=[("selected", THEME["accent_text"]), ("!selected", THEME["muted"])])

    style.configure("TPanedwindow", background=THEME["border"])

    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=THEME["panel"], troughcolor=THEME["bg"],
                         bordercolor=THEME["bg"], arrowcolor=THEME["fg"], relief="flat")

    style.configure("TSeparator", background=THEME["border"])
    style.configure("Status.TFrame", background=THEME["panel"])

    return fonts
