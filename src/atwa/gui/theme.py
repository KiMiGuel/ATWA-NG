"""Visual theme: ATWA-NG's electric-blue-on-black identity.

2026-08-27: reworked toward the old n2-ng v1 look (near-black background,
one vivid saturated color for all body text) after live-test feedback
that the prior palette's pale ice-blue fg (#e8faff) read as washed out
rather than vivid, and the background wasn't dark enough for it to pop.
Same token structure as before -- only the values changed.
"""

from __future__ import annotations

import tkinter.font as tk_font
from tkinter import ttk

THEME = {
    # 2026-08-28: softened pure #000 to a dark slate for a less flat/harsh
    # "modern dev-tool" feel (user-requested polish pass) -- still reads
    # as near-black, keeps the v1 identity intact.
    "bg": "#0a0e14",
    "panel": "#0f141c",
    "panel_alt": "#11161f",
    # White outline around every box/button (v1 reference screenshot) --
    # the old dark-blue border barely showed against a near-black bg.
    "border": "#e8f4ff",
    # Softer border for hover/active states -- flipping straight to the
    # full-white "border" color on every hover read as a harsh flash;
    # this mid-tone reads as a deliberate hover highlight instead.
    "border_dim": "#5c7a94",
    "fg": "#33bbff",
    # Plain white -- for the one spot (crack dialog output) that was
    # asked repeatedly to NOT use the blue body-text color like every
    # other widget.
    "bright": "#ffffff",
    "accent": "#00e5ff",
    "accent_dim": "#0d94c9",
    "accent_text": "#00131a",
    "warn": "#ffe600",
    "error": "#ff3366",
    "info": "#7df9ff",
    "muted": "#3d7fa3",
    # Green for open networks (user live-test note 2026-08-27: cyan/baby-blue
    # clashed with the blue background and was unreadable).
    "go": "#39ff6a",
    # Row banding for trees: near-black surface, odd rows one step up --
    # widened further (was #0d1f30) so light/dark banding reads clearly
    # even with just a couple of rows on screen, doubling as the main
    # row-separation cue since ttk.Treeview has no real per-cell gridline
    # option (2026-08-27 user report: rows "bunched up", hard to scan).
    "tree_bg": "#0a0e14",
    "tree_band": "#22456b",
}


def apply(root) -> dict[str, tk_font.Font]:
    """Configure ttk styles + scalable fonts. Returns the font handles."""
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    families = set(tk_font.families())
    mono_family = next((f for f in ("Consolas", "DejaVu Sans Mono", "Liberation Mono") if f in families), "Courier")
    ui_family = next((f for f in ("Segoe UI", "DejaVu Sans", "Liberation Sans") if f in families), "TkDefaultFont")

    # Sizes bumped and body text defaulted to bold (2026-08-27 user report:
    # fonts too small/thin next to v1's blocky bold-monospace look).
    fonts = {
        "ui": tk_font.Font(family=ui_family, size=11, weight="bold"),
        "ui_bold": tk_font.Font(family=ui_family, size=11, weight="bold"),
        "mono": tk_font.Font(family=mono_family, size=11, weight="bold"),
        "mono_bold": tk_font.Font(family=mono_family, size=11, weight="bold"),
        "title": tk_font.Font(family=ui_family, size=15, weight="bold"),
    }
    root.option_add("*Font", fonts["ui"])
    root.configure(bg=THEME["bg"])

    style.configure("TFrame", background=THEME["bg"])
    style.configure("Panel.TFrame", background=THEME["panel"])
    style.configure("Toolbar.TFrame", background=THEME["panel"])
    # Plain bordered box, no title -- ttk.LabelFrame with an empty text=""
    # still reserves a small gap in the top border for the (absent) label,
    # which read as a pointless blank notch (2026-08-27 user report).
    style.configure("Bordered.TFrame", background=THEME["bg"], relief="solid",
                     borderwidth=1, bordercolor=THEME["border"])

    style.configure("TLabel", background=THEME["bg"], foreground=THEME["fg"], font=fonts["ui"])
    style.configure("Panel.TLabel", background=THEME["panel"], foreground=THEME["fg"])
    style.configure("Toolbar.TLabel", background=THEME["panel"], foreground=THEME["fg"])
    style.configure("Muted.TLabel", background=THEME["bg"], foreground=THEME["muted"])
    style.configure("PanelMuted.TLabel", background=THEME["panel"], foreground=THEME["muted"])
    style.configure("Heading.TLabel", background=THEME["bg"], foreground=THEME["accent"], font=fonts["title"])
    style.configure("Warn.TLabel", background=THEME["bg"], foreground=THEME["warn"])
    style.configure("Error.TLabel", background=THEME["bg"], foreground=THEME["error"])

    style.configure("TButton", background=THEME["panel_alt"], foreground=THEME["fg"],
                     bordercolor=THEME["border"], borderwidth=1, relief="solid", padding=(8, 3))
    style.map("TButton",
              background=[("active", THEME["border_dim"]), ("disabled", THEME["panel"])],
              foreground=[("active", THEME["accent_text"]), ("disabled", THEME["muted"])])

    style.configure("Accent.TButton", background=THEME["accent_dim"], foreground=THEME["accent_text"],
                     bordercolor=THEME["border"], borderwidth=1, relief="solid",
                     font=fonts["ui_bold"], padding=(8, 3))
    style.map("Accent.TButton",
              background=[("active", THEME["accent"]), ("disabled", THEME["panel"])],
              foreground=[("disabled", THEME["muted"])])

    # Toolbar buttons get roomier padding than list/attack buttons (v1
    # reference: toolbar buttons are chunky with real breathing room, while
    # dense data panels stay tight -- 2026-08-27 user report: toolbar
    # buttons "not spaced out enough" next to v1's).
    style.configure("Toolbar.TButton", background=THEME["panel_alt"], foreground=THEME["fg"],
                     bordercolor=THEME["border"], borderwidth=1, relief="solid",
                     font=fonts["ui_bold"], padding=(11, 7))
    style.map("Toolbar.TButton",
              background=[("active", THEME["border_dim"]), ("disabled", THEME["panel"])],
              foreground=[("active", THEME["accent_text"]), ("disabled", THEME["muted"])])

    style.configure("Toolbar.Accent.TButton", background=THEME["accent_dim"], foreground=THEME["accent_text"],
                     bordercolor=THEME["border"], borderwidth=1, relief="solid",
                     font=fonts["ui_bold"], padding=(11, 7))
    style.map("Toolbar.Accent.TButton",
              background=[("active", THEME["accent"]), ("disabled", THEME["panel"])],
              foreground=[("disabled", THEME["muted"])])

    style.configure("Danger.TButton", background=THEME["error"], foreground="#1a0000",
                     bordercolor=THEME["border"], borderwidth=1, relief="solid",
                     font=fonts["ui_bold"], padding=(8, 3))
    style.map("Danger.TButton", background=[("active", "#ff7676"), ("disabled", THEME["panel"])])

    style.configure("TLabelframe", background=THEME["bg"], bordercolor=THEME["border"],
                     relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=THEME["bg"], foreground=THEME["accent"],
                     font=fonts["ui_bold"])

    style.configure("TCombobox", fieldbackground=THEME["panel_alt"], background=THEME["panel_alt"],
                     foreground=THEME["fg"], arrowcolor=THEME["fg"],
                     bordercolor=THEME["border"], borderwidth=1, relief="solid")
    style.map("TCombobox", fieldbackground=[("readonly", THEME["panel_alt"])])

    style.configure("TEntry", fieldbackground=THEME["panel_alt"], foreground=THEME["fg"],
                     insertcolor=THEME["fg"], bordercolor=THEME["border"], borderwidth=1, relief="solid")

    style.configure("Treeview", background=THEME["tree_bg"], fieldbackground=THEME["tree_bg"],
                     foreground=THEME["fg"], font=fonts["mono"], rowheight=22,
                     bordercolor=THEME["border"], borderwidth=1, relief="solid")
    # Each heading cell boxed individually (v1 reference, and 2026-08-27
    # user report: needs more outlines/separator lines) -- true per-cell
    # gridlines in the body rows aren't a real ttk.Treeview style option
    # under "clam" (row banding is the existing workaround for that), but
    # headings are separate elements and DO take a real border.
    style.configure("Treeview.Heading", background=THEME["panel"], foreground=THEME["accent"],
                     font=fonts["mono_bold"], relief="solid", borderwidth=1,
                     bordercolor=THEME["border"])
    style.map("Treeview",
              background=[("selected", THEME["accent_dim"])],
              foreground=[("selected", THEME["accent_text"])])

    style.configure("TPanedwindow", background=THEME["border"])

    # Unstyled "clam" TNotebook renders its tab strip and content pane in
    # the theme's default white/gray -- clashed hard against the rest of
    # the near-black window (2026-08-28 user report: "the tabs box is
    # completely white, needs to match colors") once the Target/Captures
    # split moved from a PanedWindow to a Notebook.
    style.configure("TNotebook", background=THEME["bg"], bordercolor=THEME["border"], borderwidth=1)
    style.configure("TNotebook.Tab", background=THEME["panel_alt"], foreground=THEME["fg"],
                     bordercolor=THEME["border"], borderwidth=1, font=fonts["ui_bold"], padding=(12, 6))
    style.map("TNotebook.Tab",
              background=[("selected", THEME["accent_dim"])],
              foreground=[("selected", THEME["accent_text"])])

    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=THEME["panel"], troughcolor=THEME["bg"],
                         bordercolor=THEME["bg"], arrowcolor=THEME["fg"], relief="flat")

    style.configure("TSeparator", background=THEME["border"])
    style.configure("Status.TFrame", background=THEME["panel"])

    return fonts
