"""Attribute contract for the GUI seam mixins.

The GUI is one object split across gui/{toolbar,targets,captures,attacks,
logpane}.py as mixins, so every attribute those mixins touch is really an
attribute of the composed App -- but mypy resolves each mixin in isolation
and reports all ~90 of them as undefined.

Typing every one of them per-mixin would be duplication with no safety
gain. Instead the names App.__init__ creates are declared once here, and
each mixin inherits this stub: the type checker then knows the attribute
exists without caring which mixin uses it. The runtime contract is
unchanged -- these are annotations only, no code runs.

Anything a mixin references that App.__init__ does not assign will fail
here, which is the point: it catches a seam reaching for state nobody
creates.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from typing import Any

from ..scan import AccessPoint


class GuiState:
    """Every attribute App.__init__ assigns, declared for the type checker.

    Deliberately permissive in type (`Any`) and exhaustive in name: the
    names are the contract, the annotations are not load-bearing.
    """

    # --- Tk root and styling ------------------------------------------------
    root: tk.Tk
    fonts: Any
    THEME: dict[str, str]
    _icon_images: list[Any]

    # --- threading / queue plumbing -----------------------------------------
    _queue: queue.Queue
    _queue_coalesce_lock: threading.Lock
    _scan_update_queued: bool
    _pending_signal_sample: int | None
    _signal_sample_queued: bool
    _busy: bool
    _captures_refreshing: bool
    _scanning: threading.Event
    _scan_generation: int
    _stop_event: threading.Event
    _auto_deauth_thread: threading.Thread | None
    _auto_deauth_client: str | None
    _scan_thread: threading.Thread | None
    _progress_fn: Any

    # --- discovered state ---------------------------------------------------
    aps: dict[str, AccessPoint]
    selected_bssid: str | None
    _last_graphed_bssid: str | None
    _select_capture_watch_stop: threading.Event | None
    _lock_capture_proc: Any
    _crack_proc_holder: dict
    mon_iface: str | None
    own_mac: str | None
    _permanent_mac: str | None
    alfa_pair: tuple[str, str] | None
    settings: Any

    # --- channel lock -------------------------------------------------------
    channel_locked: bool
    locked_bssid: str | None
    locked_channel: int | None
    _scan_channels: list[int] | None
    _lock_lost_since: float | None

    # --- Tk variables -------------------------------------------------------
    adapter_var: tk.StringVar
    adapter_display_var: tk.StringVar
    iface_ap_var: tk.StringVar
    iface_ap_display_var: tk.StringVar
    _iface_display_to_name: dict[str, str]
    _iface_short_display: dict[str, str]
    mac_var: tk.StringVar
    adapter_mac_var: tk.StringVar
    monitor_status_var: tk.StringVar
    channel_lock_var: tk.StringVar
    wordlist_var: tk.StringVar
    john_rules_var: tk.StringVar
    capture_dir_var: tk.StringVar
    status_var: tk.StringVar
    randomize_mac_var: tk.BooleanVar
    security_filter_var: tk.StringVar
    deauth_interval_var: tk.IntVar
    auto_deauth_var: tk.BooleanVar

    # --- widgets built by the seam builders ---------------------------------
    tree: Any
    capture_tree: Any
    log_text: tk.Text
    signal_graph: Any
    capture_buttons: list[Any]
    attack_buttons: list[Any]
    pincer_button: Any
    client_tree: Any
    _sort_col: str | None
    _sort_reverse: bool
    column_order: list[str]
    _hidden_columns: set[str]

    # --- methods owned by another seam --------------------------------------
    # Seams legitimately call each other (attacks logs through logpane's
    # _log, targets validates through attacks' _require_target). Declaring
    # the signatures here keeps that cross-calls typed without importing
    # the owning mixin, which would be circular.
    def _log(self, msg: str) -> None: ...
    def _append_log(self, msg: str) -> None: ...
    def _require_target(self) -> Any: ...
    def _run_bg(self, label: str, fn: Any, *args: Any, result_kind: str | None = ..., **kwargs: Any) -> Any: ...
    def _run_capture_task(self, label: str, fn: Any, *args: Any, result_kind: str | None = ..., **kwargs: Any) -> Any: ...
    def _watch_capture_size(self, path: Any, stop_event: threading.Event) -> None: ...
    def _set_busy(self, busy: bool) -> None: ...
    def _start_lock_capture(self, ap: AccessPoint) -> None: ...
    def _stop_lock_capture(self) -> None: ...
    def _unlock_channel(self) -> None: ...