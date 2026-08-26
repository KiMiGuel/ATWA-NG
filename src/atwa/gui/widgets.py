"""Small reusable Tk widgets for the GUI."""

from __future__ import annotations

import tkinter as tk
from collections import deque

from .theme import THEME


class SignalGraph:
    """Rolling line graph of a locked target's RSSI over time.

    Pure Canvas drawing logic. Y axis is clamped/scaled -90..-30 dBm
    (weak..strong); each new sample is one
    scan pass's reading for whatever target is currently locked, so a
    rising line means the signal is getting stronger, falling means
    weaker — not an attack-progress indicator.
    """

    def __init__(self, parent):
        self.canvas = tk.Canvas(parent, bg=THEME["panel"], height=110, highlightthickness=0)
        self.canvas.pack(fill=tk.X)
        self.samples: deque[int] = deque(maxlen=60)
        self._draw_after_id = None
        self.canvas.bind("<Configure>", lambda _e: self._draw())

    def reset(self):
        self.samples.clear()
        self._draw()

    def add_sample(self, pwr) -> None:
        try:
            val = int(pwr)
        except (TypeError, ValueError):
            val = -100
        self.samples.append(val)
        self._draw()

    def _draw_retry(self):
        self._draw_after_id = None
        self._draw()

    def _draw(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10:
            if self._draw_after_id is None:
                self._draw_after_id = self.canvas.after(100, self._draw_retry)
            return
        for y in range(0, h, 20):
            self.canvas.create_line(0, y, w, y, fill=THEME["border"])
        for label, dbm in (("-30 dBm", -30), ("-60 dBm", -60), ("-90 dBm", -90)):
            y = h - ((dbm + 90) / 60) * h
            self.canvas.create_text(4, min(max(y, 8), h - 8), text=label, fill=THEME["muted"],
                                     anchor="w", font=("TkDefaultFont", 7))
        if len(self.samples) < 1:
            return
        if len(self.samples) == 1:
            # A single seeded sample (e.g. right after selecting a target,
            # before the next scan hop lands a second reading) still needs
            # to render as *something* rather than nothing — draw it as a
            # dot instead of falling through to the line-drawing math below,
            # which divides by len(samples)-1 and would ZeroDivisionError.
            y = h - ((max(-90, min(-30, self.samples[0])) + 90) / 60) * h
            self.canvas.create_oval(-3, y - 3, 3, y + 3, fill=THEME["accent"], outline="")
            return
        step = w / (len(self.samples) - 1)
        points = []
        for i, val in enumerate(self.samples):
            y = h - ((max(-90, min(-30, val)) + 90) / 60) * h
            points.append((i * step, y))
        flat = [c for p in points for c in p]
        self.canvas.create_line(flat, fill=THEME["accent"], width=2, smooth=True)
