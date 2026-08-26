"""Visual theme: ATWA-NG's electric-blue-to-black identity.

2026-08-26: rebranded from an earlier neon-green-on-black palette to the
ATWA-NG brand (electric blue fading to black). This swaps the color
*values* only — every widget class still keys off the same semantic
tokens (bg/panel/panel_alt/border/accent/etc.), so the rebrand is
entirely contained here.

Not yet a true pixel gradient: ttk widgets paint flat per-style
backgrounds, not gradients, and retrofitting a real top-to-bottom canvas
gradient behind the existing pack/grid layout would mean redoing how
every frame is composited (each widget drawn as a canvas window instead
of packed directly) — a bigger, riskier change than a color swap. This
approximates the "electric blue up top, fading toward black" feel by
making progressively deeper/lower content panels progressively darker
(bg > panel > panel_alt, each a step closer to black), with the
brightest blue reserved for accents/headings. A real smooth gradient is
a legitimate follow-up once the logo's final colors are locked in.
"""

from __future__ import annotations

import tkinter.font as tk_font
from tkinter import ttk

THEME = {
    "bg": "#050b14",
    "panel": "#03060c",
    "panel_alt": "#010308",
    "border": "#123a55",
    "fg": "#e8faff",
    "accent": "#00f3ff",
    "accent_dim": "#0d94c9",
    "accent_text": "#00131a",
    "warn": "#ffe600",
    "error": "#ff3366",
    "info": "#7df9ff",
    "muted": "#5590ad",
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
