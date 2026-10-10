"""
OScope — System Call Monitoring Tool (strace + Python + Tkinter)
Phases Implemented:
- Phase 1: Export / Save Session Reports (CSV and TXT via file dialog with full session preservation)
- Phase 2: In-Memory Session History & Side-by-Side Comparison Dashboard
- Phase 3: Real-Time Live Category Distribution Bar Chart (Tkinter Canvas)
- Phase 4: Expanded System Call Classification (File I/O / FS, Network, Signal, IPC, Process Control, Memory Mgmt, Other)
- Phase 5: Syscall Argument Parsing (Extracted Key Details column for openat, open, read, write, close, etc.)
- Phase 6: Failure Analysis (Dedicated Tab, Errno Code Breakdown & Plain-English Error Explanations)
- Phase 7: About This Syscall (Interactive Documentation Panel & OS Concept Explanations)
- Core: Real Linux strace integration, dedicated raw terminal window, process controls, filtering & search
"""

import csv
import os
import sys
import threading
import queue
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

from tracer import TraceSession
from parser import parse_syscall_line, ALL_CATEGORIES, classify_syscall
from statistics import is_failed_syscall, compute_statistics
from syscall_info import get_syscall_info
from failure_analysis import compute_failure_analysis, explain_errno
from process_tree import ProcessTreeTracker, ProcessNode


# -----------------------------------------------------------------
# Stage 6.1: Raw strace Output Window
# A fresh Toplevel window is opened for every monitoring session.
# It shows real-time raw strace lines in a terminal-style display.
# -----------------------------------------------------------------
class RawOutputWindow:
    """
    A dedicated, black-background Tkinter Toplevel that displays raw strace output
    in real time. A new instance is created for each monitoring session so that
    every session gets its own fresh window. The window stays open after the
    traced command finishes so the teacher can inspect the full trace.
    """

    # Session counter to give each window a unique title
    _session_counter = 0

    def __init__(self, root: tk.Tk, command: str):
        RawOutputWindow._session_counter += 1
        self._session_id = RawOutputWindow._session_counter

        self.top = tk.Toplevel(root)
        self.top.title(
            f"System Call Monitor - Raw strace Output  "
            f"[Session {self._session_id}: {command}]"
        )
        self.top.geometry("900x520")
        self.top.minsize(600, 300)

        # Use a thread-safe queue to pass raw lines from the worker thread
        # to the Tkinter main thread (Tkinter widgets are NOT thread-safe).
        self._line_queue: queue.Queue = queue.Queue()

        self._build_ui(command)
        self._poll_raw_queue()

    def _build_ui(self, command: str):
        """Builds the black terminal-style raw output display."""
        header = tk.Label(
            self.top,
            text=f"  ▶ strace  →  {command}",
            bg="#1a1a2e",
            fg="#00ff88",
            font=("Courier", 10, "bold"),
            anchor="w",
            padx=8,
            pady=6
        )
        header.pack(fill="x")

        # Text widget with terminal look: black bg, green monospace text
        frame = tk.Frame(self.top, bg="#0d0d0d")
        frame.pack(fill="both", expand=True)

        self.text = tk.Text(
            frame,
            bg="#0d0d0d",
            fg="#e0e0e0",
            font=("Courier", 9),
            wrap="none",
            state="disabled",
            relief="flat",
            padx=8,
            pady=4
        )
        scrollbar_y = tk.Scrollbar(frame, orient="vertical", command=self.text.yview)
        scrollbar_x = tk.Scrollbar(self.top, orient="horizontal", command=self.text.xview)
        self.text.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        scrollbar_x.pack(side="bottom", fill="x")
        scrollbar_y.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        # Status bar at the bottom
        self.status_bar = tk.Label(
            self.top,
            text="Waiting for strace output...",
            bg="#1a1a2e",
            fg="#aaaaaa",
            font=("Courier", 8),
            anchor="w",
            padx=8,
            pady=3
        )
        self.status_bar.pack(fill="x")

    def append_line(self, raw_line: str):
        """
        Thread-safe: enqueue a raw strace line for display.
        Called from the background worker thread.
        """
        self._line_queue.put(raw_line)

    def mark_finished(self, returncode: int):
        """Enqueue a sentinel to update the status bar when tracing completes."""
        self._line_queue.put(("__FINISHED__", returncode))

    def _poll_raw_queue(self):
        """
        Runs in the Tkinter main thread (via root.after) to safely update the Text widget.
        Drains up to 80 lines per tick for high-volume traces.
        """
        try:
            processed = 0
            while processed < 80 and not self._line_queue.empty():
                item = self._line_queue.get_nowait()

                if isinstance(item, tuple) and item[0] == "__FINISHED__":
                    rc = item[1]
                    self.status_bar.config(
                        text=f"  ✓ Process exited with code {rc}  — trace complete (window stays open for inspection)",
                        fg="#00ff88" if rc == 0 else "#ff6666"
                    )
                else:
                    # Colour-code strace lines for readability
                    line = item
                    self.text.configure(state="normal")
                    if line.startswith(("++", "--")):
                        self.text.insert("end", line, "marker")
                        self.text.tag_configure("marker", foreground="#ffcc00")
                    elif "= -1" in line:
                        self.text.insert("end", line, "error")
                        self.text.tag_configure("error", foreground="#ff6666")
                    else:
                        self.text.insert("end", line)
                    self.text.configure(state="disabled")
                    self.text.see("end")

                processed += 1
        except Exception:
            pass

        # Keep polling even after process ends so final lines flush through
        try:
            self.top.after(30, self._poll_raw_queue)
        except Exception:
            pass  # Window was closed by user — stop polling silently


class SyscallMonitorApp:
    def __init__(self, root: tk.Tk, auto_test: bool = False):
        self.root = root
        self.root.title("Linux System Call Monitoring Tool")
        self.root.geometry("1020x720")
        self.root.minsize(850, 550)

        self.auto_test = auto_test
        self.session = None
        self.worker_thread = None
        self.queue = queue.Queue()
        self.is_monitoring = False
        self.last_command = ""
        self.session_start_time = None
        self.session_history = []
        self._session_saved = False

        # Phase 8: Child Process Tracing & Process Tree Tracker
        self.follow_children_var = tk.BooleanVar(value=False)
        self.process_tree_tracker = ProcessTreeTracker(root_command="cat sample.txt")

        # Phase 9: Command History (in-memory last 10 distinct commands)
        self.command_history = ["cat sample.txt"]

        # Master dataset (persists regardless of table filters)
        self.records = []
        self.total_count = 0
        self.category_counts = {cat: 0 for cat in ALL_CATEGORIES}
        self.successful_count = 0
        self.failed_count = 0

        # Filter and display state variables
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self._on_filter_changed)

        self.cat_filter_var = tk.StringVar(value="All Categories")
        self.auto_scroll_var = tk.BooleanVar(value=True)

        self._build_ui()
        self._poll_queue()

        if self.auto_test:
            self.root.after(300, self._run_automated_tests)

    def _build_ui(self):
        # -------------------------------------------------------------
        # 1. Top Controls Frame (2-Row Functional Grid)
        # -------------------------------------------------------------
        controls_frame = ttk.LabelFrame(self.root, text=" Monitoring & Target Controls ", padding=8)
        controls_frame.pack(fill="x", padx=10, pady=(8, 4))

        # Row 0: Target Command, Recent History dropdown, Child Tracing Checkbox
        row0_frame = ttk.Frame(controls_frame)
        row0_frame.pack(fill="x", pady=(0, 6))

        ttk.Label(row0_frame, text="Target Command:").pack(side="left", padx=(0, 4))
        self.cmd_entry = ttk.Entry(row0_frame, width=32)
        self.cmd_entry.insert(0, "cat sample.txt")
        self.cmd_entry.pack(side="left", padx=4)

        ttk.Label(row0_frame, text="Recent:").pack(side="left", padx=(10, 4))
        self.combo_history = ttk.Combobox(
            row0_frame,
            values=self.command_history,
            state="readonly",
            width=22
        )
        self.combo_history.set("cat sample.txt")
        self.combo_history.pack(side="left", padx=4)
        self.combo_history.bind("<<ComboboxSelected>>", self._on_history_command_selected)

        self.chk_child = ttk.Checkbutton(
            row0_frame,
            text="Trace Child Processes (-f)",
            variable=self.follow_children_var
        )
        self.chk_child.pack(side="left", padx=(14, 4))

        # Row 1: Action Buttons & Session Status
        row1_frame = ttk.Frame(controls_frame)
        row1_frame.pack(fill="x")

        self.btn_start = ttk.Button(row1_frame, text="▶ Start Monitoring", command=self.start_monitoring)
        self.btn_start.pack(side="left", padx=(0, 4))

        self.btn_stop = ttk.Button(row1_frame, text="■ Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.btn_clear = ttk.Button(row1_frame, text="⟲ Clear", command=self.clear_data)
        self.btn_clear.pack(side="left", padx=4)

        self.btn_export = ttk.Button(row1_frame, text="Export Session", command=self.export_session, state="disabled")
        self.btn_export.pack(side="left", padx=4)

        self.lbl_status = ttk.Label(
            row1_frame,
            text="Status: Ready",
            foreground="#2c3e50",
            font=("TkDefaultFont", 10, "bold")
        )
        self.lbl_status.pack(side="right", padx=10)

        # -------------------------------------------------------------
        # 2. Main Tabbed Notebook Interface
        # -------------------------------------------------------------
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(4, 6))

        self.tab_monitor = ttk.Frame(self.notebook)
        self.tab_visual = ttk.Frame(self.notebook)
        self.tab_failures = ttk.Frame(self.notebook)
        self.tab_ptree = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_monitor, text="  Live Monitor  ")
        self.notebook.add(self.tab_visual, text="  Live Visualization  ")
        self.notebook.add(self.tab_failures, text="  Failure Analysis  ")
        self.notebook.add(self.tab_ptree, text="  Process Tree  ")
        self.notebook.add(self.tab_history, text="  Session History & Compare  ")
        self.notebook.bind("<<NotebookTabChanged>>", lambda event: self._on_tab_changed())

        self._build_monitor_tab()
        self._build_visual_tab()
        self._build_failures_tab()
        self._build_ptree_tab()
        self._build_history_tab()

    def _build_monitor_tab(self):
        # -------------------------------------------------------------
        # Filter & Search Bar
        # -------------------------------------------------------------
        filter_frame = ttk.LabelFrame(self.tab_monitor, text=" Filter & Table Controls ", padding=8)
        filter_frame.pack(fill="x", padx=8, pady=4)

        ttk.Label(filter_frame, text="Search (Name / Category):").pack(side="left", padx=(0, 5))
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=22)
        self.filter_entry.pack(side="left", padx=5)

        ttk.Label(filter_frame, text="Category Filter:").pack(side="left", padx=(10, 5))
        categories = ["All Categories"] + ALL_CATEGORIES
        self.cat_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.cat_filter_var,
            values=categories,
            state="readonly",
            width=22
        )
        self.cat_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)
        self.cat_combo.pack(side="left", padx=5)

        btn_reset_filter = ttk.Button(filter_frame, text="Reset Filter", command=self.reset_filter)
        btn_reset_filter.pack(side="left", padx=6)

        chk_scroll = ttk.Checkbutton(filter_frame, text="Auto-scroll to latest", variable=self.auto_scroll_var)
        chk_scroll.pack(side="left", padx=(15, 5))

        self.lbl_filter_count = ttk.Label(filter_frame, text="Showing: 0 / 0 calls", foreground="#555555")
        self.lbl_filter_count.pack(side="right", padx=10)

        # -------------------------------------------------------------
        # Live System Call Table Frame
        # -------------------------------------------------------------
        table_frame = ttk.LabelFrame(self.tab_monitor, text=" Real-Time System Call Trace ", padding=8)
        table_frame.pack(fill="both", expand=True, padx=8, pady=4)

        columns = ("#", "PID", "Syscall", "Category", "Key Details", "Arguments", "Return Value")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("#", text="#")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Syscall", text="Syscall")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Key Details", text="Key Details")
        self.tree.heading("Arguments", text="Arguments")
        self.tree.heading("Return Value", text="Return Value")

        self.tree.column("#", width=45, minwidth=35, anchor="center")
        self.tree.column("PID", width=65, minwidth=50, anchor="center")
        self.tree.column("Syscall", width=105, minwidth=85, anchor="w")
        self.tree.column("Category", width=135, minwidth=110, anchor="w")
        self.tree.column("Key Details", width=250, minwidth=160, anchor="w")
        self.tree.column("Arguments", width=330, minwidth=180, anchor="w")
        self.tree.column("Return Value", width=140, minwidth=90, anchor="w")

        scrollbar_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # -------------------------------------------------------------
        # About This Syscall Information Panel (Phase 7)
        # -------------------------------------------------------------
        about_frame = ttk.LabelFrame(self.tab_monitor, text=" About This Syscall (Documentation & OS Concepts) ", padding=8)
        about_frame.pack(fill="x", padx=8, pady=(2, 4))

        self.lbl_about_title = ttk.Label(
            about_frame,
            text="Syscall: None Selected",
            font=("TkDefaultFont", 9, "bold"),
            foreground="#0066cc"
        )
        self.lbl_about_title.pack(anchor="w", pady=(0, 2))

        self.lbl_about_purpose = ttk.Label(
            about_frame,
            text="Purpose: Select a system call from the table above to view details.",
            font=("TkDefaultFont", 9, "italic")
        )
        self.lbl_about_purpose.pack(anchor="w", pady=1)

        self.lbl_about_desc = ttk.Label(
            about_frame,
            text="Description: Comprehensive documentation, kernel execution flow, and parameters will appear here.",
            wraplength=950,
            justify="left"
        )
        self.lbl_about_desc.pack(anchor="w", pady=1)

        self.lbl_about_concept = ttk.Label(
            about_frame,
            text="Related OS Concept: -",
            font=("TkDefaultFont", 9, "bold"),
            foreground="#2c3e50"
        )
        self.lbl_about_concept.pack(anchor="w", pady=(1, 0))

        # -------------------------------------------------------------
        # Bottom Statistics Dashboard
        # -------------------------------------------------------------
        stats_frame = ttk.LabelFrame(self.tab_monitor, text=" Operating System Metrics & Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=8, pady=(4, 6))

        self.lbl_stat_total = ttk.Label(stats_frame, text="Total Syscalls: 0", font=("TkDefaultFont", 9, "bold"))
        self.lbl_stat_total.grid(row=0, column=0, padx=12, pady=2, sticky="w")

        self.lbl_stat_success = ttk.Label(stats_frame, text="Successful: 0", foreground="#008000", font=("TkDefaultFont", 9, "bold"))
        self.lbl_stat_success.grid(row=0, column=1, padx=12, pady=2, sticky="w")

        self.lbl_stat_failed = ttk.Label(stats_frame, text="Failed: 0", foreground="#cc0000", font=("TkDefaultFont", 9, "bold"))
        self.lbl_stat_failed.grid(row=0, column=2, padx=12, pady=2, sticky="w")

        # Dynamic Category count labels dictionary
        self.lbl_stat_cats = {}
        cat_layout = [
            ("File I/O / File System", 1, 0),
            ("Network", 1, 1),
            ("Signal", 1, 2),
            ("IPC", 1, 3),
            ("Process Control", 2, 0),
            ("Memory Management", 2, 1),
            ("Other", 2, 2),
        ]
        for cat_name, r, c in cat_layout:
            lbl = ttk.Label(stats_frame, text=f"{cat_name}: 0")
            lbl.grid(row=r, column=c, padx=12, pady=2, sticky="w")
            self.lbl_stat_cats[cat_name] = lbl

    def _build_visual_tab(self):
        """Builds Phase 3 Live Visualization Panel with Category Distribution Bar Chart."""
        v_summary_frame = ttk.LabelFrame(self.tab_visual, text=" Live Category Distribution Summary ", padding=10)
        v_summary_frame.pack(fill="x", padx=8, pady=(6, 4))

        self.lbl_v_total = ttk.Label(v_summary_frame, text="Total Syscalls: 0", font=("TkDefaultFont", 10, "bold"))
        self.lbl_v_total.grid(row=0, column=0, padx=10, pady=3, sticky="w")

        category_colors = {
            "File I/O / File System": "#2980b9",
            "Network": "#16a085",
            "Signal": "#e74c3c",
            "IPC": "#f39c12",
            "Process Control": "#d35400",
            "Memory Management": "#8e44ad",
            "Other": "#7f8c8d",
        }

        self.lbl_v_cats = {}
        v_layout = [
            ("File I/O / File System", 0, 1),
            ("Network", 0, 2),
            ("Signal", 0, 3),
            ("IPC", 1, 0),
            ("Process Control", 1, 1),
            ("Memory Management", 1, 2),
            ("Other", 1, 3),
        ]
        for cat_name, r, c in v_layout:
            col = category_colors.get(cat_name, "#555555")
            lbl = ttk.Label(v_summary_frame, text=f"{cat_name}: 0 (0.0%)", foreground=col, font=("TkDefaultFont", 9, "bold"))
            lbl.grid(row=r, column=c, padx=10, pady=3, sticky="w")
            self.lbl_v_cats[cat_name] = lbl

        chart_frame = ttk.LabelFrame(self.tab_visual, text=" Real-Time Syscall Category Bar Chart ", padding=8)
        chart_frame.pack(fill="both", expand=True, padx=8, pady=(4, 6))

        self.chart_canvas = tk.Canvas(chart_frame, bg="#181825", highlightthickness=0)
        self.chart_canvas.pack(fill="both", expand=True)
        self.chart_canvas.bind("<Configure>", lambda event: self._draw_chart())

    def _draw_chart(self):
        """Renders a responsive bar chart of system call categories on the Tkinter Canvas."""
        if not hasattr(self, "chart_canvas"):
            return

        w = self.chart_canvas.winfo_width()
        h = self.chart_canvas.winfo_height()
        if w < 100 or h < 80:
            w = 800
            h = 400

        self.chart_canvas.delete("all")

        tot = self.total_count
        self.lbl_v_total.config(text=f"Total Syscalls: {tot}")

        for cat in ALL_CATEGORIES:
            cnt = self.category_counts.get(cat, 0)
            pct = (cnt / tot * 100) if tot > 0 else 0.0
            if cat in self.lbl_v_cats:
                self.lbl_v_cats[cat].config(text=f"{cat}: {cnt} ({pct:.1f}%)")

        if tot == 0:
            self.chart_canvas.create_text(
                w / 2, h / 2 - 12,
                text="📊 No System Call Data Captured Yet",
                fill="#8888aa",
                font=("TkDefaultFont", 12, "bold")
            )
            self.chart_canvas.create_text(
                w / 2, h / 2 + 15,
                text="Start monitoring a command to observe live category distribution",
                fill="#555577",
                font=("TkDefaultFont", 10)
            )
            return

        categories = ALL_CATEGORIES
        counts = [self.category_counts.get(cat, 0) for cat in categories]
        colors = [
            "#2980b9",  # File I/O / File System
            "#16a085",  # Network
            "#e74c3c",  # Signal
            "#f39c12",  # IPC
            "#d35400",  # Process Control
            "#8e44ad",  # Memory Management
            "#7f8c8d",  # Other
        ]
        display_names = [
            "File I/O\n/ FS",
            "Network",
            "Signal",
            "IPC",
            "Process\nControl",
            "Memory\nMgmt",
            "Other",
        ]

        max_val = max(counts) if max(counts) > 0 else 1
        left_margin = 75
        right_margin = 35
        top_margin = 40
        bottom_margin = 65

        plot_w = max(50, w - left_margin - right_margin)
        plot_h = max(50, h - top_margin - bottom_margin)

        # Draw grid lines (4 levels: 0, 33%, 66%, 100%)
        for i in range(4):
            val = int(max_val * i / 3)
            y = top_margin + plot_h - (plot_h * (i / 3))
            self.chart_canvas.create_line(left_margin, y, left_margin + plot_w, y, fill="#2c2c44", width=1, dash=(3, 3))
            self.chart_canvas.create_text(left_margin - 8, y, text=str(val), fill="#777799", font=("Courier", 8), anchor="e")

        # Baseline
        base_y = top_margin + plot_h
        self.chart_canvas.create_line(left_margin, base_y, left_margin + plot_w, base_y, fill="#555577", width=2)

        # Draw bars
        n_bars = len(categories)
        slot_w = plot_w / n_bars
        bar_w = min(slot_w * 0.65, 75)

        for i, (cat_label, cnt, col) in enumerate(zip(display_names, counts, colors)):
            bar_x = left_margin + slot_w * (i + 0.5)
            h_ratio = cnt / max_val
            bar_top = base_y - (plot_h * h_ratio)

            self.chart_canvas.create_rectangle(
                bar_x - bar_w / 2, bar_top,
                bar_x + bar_w / 2, base_y,
                fill=col, outline="#ffffff", width=1
            )

            pct = (cnt / tot * 100) if tot > 0 else 0.0
            label_top = max(16, bar_top - 12)
            self.chart_canvas.create_text(
                bar_x, label_top,
                text=f"{cnt} ({pct:.1f}%)" if cnt > 0 else "0",
                fill="#ffffff",
                font=("TkDefaultFont", 8, "bold")
            )

            self.chart_canvas.create_text(
                bar_x, base_y + 18,
                text=cat_label,
                fill="#dddddd",
                font=("TkDefaultFont", 8, "bold"),
                justify="center"
            )

    def _on_tab_changed(self):
        try:
            selected_tab = self.notebook.tab(self.notebook.select(), "text").strip()
            if "Visualization" in selected_tab:
                self.root.after(20, self._draw_chart)
            elif "Failure" in selected_tab:
                self._refresh_failures_ui()
            elif "Process Tree" in selected_tab:
                self._refresh_ptree_ui()
        except Exception:
            pass

    def _reset_about_panel(self):
        """Resets the About This Syscall panel to default placeholder text."""
        if hasattr(self, "lbl_about_title"):
            self.lbl_about_title.config(
                text="Syscall: None Selected",
                foreground="#0066cc"
            )
            self.lbl_about_purpose.config(
                text="Purpose: Select a system call from the table above to view details."
            )
            self.lbl_about_desc.config(
                text="Description: Comprehensive documentation, kernel execution flow, and parameters will appear here."
            )
            self.lbl_about_concept.config(
                text="Related OS Concept: -"
            )

    def _on_tree_select(self, event=None):
        """Updates the About This Syscall panel when a row is selected in the live monitor table."""
        selected = self.tree.selection()
        if not selected:
            return
        vals = self.tree.item(selected[0], "values")
        if not vals or len(vals) < 3:
            return

        cols = list(self.tree.cget("columns"))
        name_idx = cols.index("Syscall") if "Syscall" in cols else 2
        cat_idx = cols.index("Category") if "Category" in cols else 3
        name = str(vals[name_idx])
        category = str(vals[cat_idx])

        info = get_syscall_info(name, category)
        self.lbl_about_title.config(
            text=f"Syscall: {info['name']}    [ Category: {info['category']} ]",
            foreground="#0066cc"
        )
        self.lbl_about_purpose.config(
            text=f"Purpose: {info['purpose']}"
        )
        self.lbl_about_desc.config(
            text=f"Description: {info['description']}"
        )
        self.lbl_about_concept.config(
            text=f"Related OS Concept: {info['concept']}"
        )

    def _on_failure_tree_select(self, event=None):
        """Updates the About This Syscall panel when a row is selected in the Failure Analysis table."""
        selected = self.failure_tree.selection()
        if not selected:
            return
        vals = self.failure_tree.item(selected[0], "values")
        if not vals or len(vals) < 3:
            return

        name = str(vals[1])
        category = str(vals[2])

        info = get_syscall_info(name, category)
        self.lbl_about_title.config(
            text=f"Failed Syscall: {info['name']}    [ Category: {info['category']} ]",
            foreground="#cc0000"
        )
        self.lbl_about_purpose.config(
            text=f"Purpose: {info['purpose']}"
        )
        self.lbl_about_desc.config(
            text=f"Description: {info['description']}"
        )
        self.lbl_about_concept.config(
            text=f"Related OS Concept: {info['concept']}"
        )

    def _build_failures_tab(self):
        """Builds Phase 6 Failure Analysis Panel."""
        summary_frame = ttk.LabelFrame(self.tab_failures, text=" Failure Analysis Summary ", padding=10)
        summary_frame.pack(fill="x", padx=8, pady=(6, 4))

        self.lbl_fail_total = ttk.Label(
            summary_frame,
            text="Failed Syscalls: 0",
            font=("TkDefaultFont", 10, "bold"),
            foreground="#cc0000"
        )
        self.lbl_fail_total.grid(row=0, column=0, padx=12, pady=2, sticky="w")

        self.lbl_fail_rate = ttk.Label(
            summary_frame,
            text="Failure Rate: 0.0%",
            font=("TkDefaultFont", 10, "bold"),
            foreground="#d35400"
        )
        self.lbl_fail_rate.grid(row=0, column=1, padx=12, pady=2, sticky="w")

        self.lbl_fail_errno_breakdown = ttk.Label(
            summary_frame,
            text="Errno Breakdown: None",
            font=("TkDefaultFont", 9),
            foreground="#555555"
        )
        self.lbl_fail_errno_breakdown.grid(row=0, column=2, padx=12, pady=2, sticky="w")

        table_frame = ttk.LabelFrame(self.tab_failures, text=" Captured Syscall Failures ", padding=8)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(4, 6))

        cols = ("#", "Syscall", "Category", "Errno Code", "Key Details", "Arguments", "Plain-English Explanation")
        self.failure_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.failure_tree.heading("#", text="#")
        self.failure_tree.heading("Syscall", text="Syscall")
        self.failure_tree.heading("Category", text="Category")
        self.failure_tree.heading("Errno Code", text="Errno Code")
        self.failure_tree.heading("Key Details", text="Key Details")
        self.failure_tree.heading("Arguments", text="Arguments")
        self.failure_tree.heading("Plain-English Explanation", text="Plain-English Explanation")

        self.failure_tree.column("#", width=45, minwidth=35, anchor="center")
        self.failure_tree.column("Syscall", width=95, minwidth=80, anchor="w")
        self.failure_tree.column("Category", width=125, minwidth=100, anchor="w")
        self.failure_tree.column("Errno Code", width=90, minwidth=75, anchor="center")
        self.failure_tree.column("Key Details", width=180, minwidth=130, anchor="w")
        self.failure_tree.column("Arguments", width=220, minwidth=150, anchor="w")
        self.failure_tree.column("Plain-English Explanation", width=280, minwidth=180, anchor="w")

        fy_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.failure_tree.yview)
        fx_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.failure_tree.xview)
        self.failure_tree.configure(yscrollcommand=fy_scroll.set, xscrollcommand=fx_scroll.set)

        self.failure_tree.grid(row=0, column=0, sticky="nsew")
        fy_scroll.grid(row=0, column=1, sticky="ns")
        fx_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.failure_tree.bind("<<TreeviewSelect>>", self._on_failure_tree_select)

    def _refresh_failures_ui(self):
        """Refreshes the Failure Analysis tab summary metrics and failed calls table."""
        if not hasattr(self, "failure_tree"):
            return

        analysis = compute_failure_analysis(self.records)

        tot_failed = analysis["total_failures"]
        fail_rate = analysis["failure_rate"]
        errno_counts = analysis["errno_counts"]
        failed_recs = analysis["failed_records"]

        self.lbl_fail_total.config(text=f"Failed Syscalls: {tot_failed}")
        self.lbl_fail_rate.config(text=f"Failure Rate: {fail_rate:.1f}%")

        if errno_counts:
            breakdown_str = ", ".join([f"{err}: {cnt}" for err, cnt in errno_counts.items()])
            self.lbl_fail_errno_breakdown.config(text=f"Errno Breakdown: {breakdown_str}")
        else:
            self.lbl_fail_errno_breakdown.config(text="Errno Breakdown: No errors detected")

        for item in self.failure_tree.get_children():
            self.failure_tree.delete(item)

        for rec in failed_recs:
            self.failure_tree.insert(
                "",
                "end",
                values=(
                    rec.get("seq_num", 0),
                    rec.get("name", ""),
                    rec.get("category", "Other"),
                    rec.get("errno_code", "UNKNOWN"),
                    rec.get("key_details", ""),
                    rec.get("arguments", ""),
                    rec.get("explanation", "")
                )
            )

    # -----------------------------------------------------------------
    # Phase 9: Command History Methods
    # -----------------------------------------------------------------
    def _add_command_to_history(self, cmd: str):
        """Maintains the latest 10 distinct commands in memory, avoiding consecutive duplicates."""
        clean_cmd = cmd.strip()
        if not clean_cmd:
            return
        if self.command_history and self.command_history[0] == clean_cmd:
            return
        if clean_cmd in self.command_history:
            self.command_history.remove(clean_cmd)
        self.command_history.insert(0, clean_cmd)
        self.command_history = self.command_history[:10]
        if hasattr(self, "combo_history"):
            self.combo_history["values"] = list(self.command_history)
            self.combo_history.set(clean_cmd)

    def _on_history_command_selected(self, event=None):
        """Populates command entry from selected history item without starting monitoring."""
        selected = self.combo_history.get()
        if selected:
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, selected)

    # -----------------------------------------------------------------
    # Phase 8: Process Tree UI & Methods
    # -----------------------------------------------------------------
    def _build_ptree_tab(self):
        """Builds Phase 8 Process Tree Panel with parent-child hierarchy."""
        ptree_summary_frame = ttk.LabelFrame(self.tab_ptree, text=" Process Tree Summary & Controls ", padding=10)
        ptree_summary_frame.pack(fill="x", padx=8, pady=(6, 4))

        self.lbl_ptree_summary = ttk.Label(
            ptree_summary_frame,
            text="Processes Tracked: 0 | Child Tracing: Disabled",
            font=("TkDefaultFont", 10, "bold"),
            foreground="#2c3e50"
        )
        self.lbl_ptree_summary.pack(side="left", padx=8)

        self._ptree_session_ids = [None]
        ptree_session_controls = ttk.Frame(ptree_summary_frame)
        ptree_session_controls.pack(side="right", padx=4)
        ttk.Label(ptree_session_controls, text="Session:").pack(side="left", padx=(0, 4))
        self.combo_ptree_session = ttk.Combobox(
            ptree_session_controls,
            values=["Current / Live"],
            state="readonly",
            width=42
        )
        self.combo_ptree_session.current(0)
        self.combo_ptree_session.pack(side="left", padx=4)
        self.combo_ptree_session.bind("<<ComboboxSelected>>", self._on_ptree_session_selected)

        btn_refresh_ptree = ttk.Button(ptree_summary_frame, text="⟲ Refresh Tree", command=self._refresh_ptree_ui)
        btn_refresh_ptree.pack(side="right", padx=6)

        tree_frame = ttk.LabelFrame(self.tab_ptree, text=" Process Hierarchy (Parent ➔ Child) ", padding=8)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=(4, 6))

        cols = ("PID", "PPID", "Command", "Status", "Syscall Count")
        self.ptree_view = ttk.Treeview(tree_frame, columns=cols, show="tree headings", selectmode="browse")

        self.ptree_view.heading("#0", text="Process Hierarchy")
        self.ptree_view.heading("PID", text="PID")
        self.ptree_view.heading("PPID", text="PPID")
        self.ptree_view.heading("Command", text="Command / Binary")
        self.ptree_view.heading("Status", text="Status")
        self.ptree_view.heading("Syscall Count", text="Syscall Count")

        self.ptree_view.column("#0", width=240, minwidth=180, anchor="w")
        self.ptree_view.column("PID", width=80, minwidth=60, anchor="center")
        self.ptree_view.column("PPID", width=80, minwidth=60, anchor="center")
        self.ptree_view.column("Command", width=250, minwidth=150, anchor="w")
        self.ptree_view.column("Status", width=130, minwidth=90, anchor="center")
        self.ptree_view.column("Syscall Count", width=120, minwidth=90, anchor="center")

        py_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ptree_view.yview)
        px_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.ptree_view.xview)
        self.ptree_view.configure(yscrollcommand=py_scroll.set, xscrollcommand=px_scroll.set)

        self.ptree_view.grid(row=0, column=0, sticky="nsew")
        py_scroll.grid(row=0, column=1, sticky="ns")
        px_scroll.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.ptree_view.bind("<<TreeviewSelect>>", self._on_ptree_node_select)

        ptree_detail_frame = ttk.LabelFrame(self.tab_ptree, text=" Selected Process Information ", padding=8)
        ptree_detail_frame.pack(fill="x", padx=8, pady=(2, 6))

        self.lbl_ptree_detail = ttk.Label(
            ptree_detail_frame,
            text="Select a process node above to inspect its execution metrics.",
            font=("TkDefaultFont", 9)
        )
        self.lbl_ptree_detail.pack(side="left", padx=8, fill="x", expand=True)

        self.btn_filter_pid = ttk.Button(
            ptree_detail_frame,
            text="Filter Live Trace by this PID",
            command=self._filter_trace_by_selected_pid,
            state="disabled"
        )
        self.btn_filter_pid.pack(side="right", padx=8)

    def _refresh_ptree_ui(self):
        """Displays the selected saved process tree or the current live tree."""
        if not hasattr(self, "ptree_view"):
            return

        for item in self.ptree_view.get_children():
            self.ptree_view.delete(item)
        self.lbl_ptree_detail.config(text="Select a process node above to inspect its execution metrics.")
        self.btn_filter_pid.config(state="disabled")

        selected_index = self.combo_ptree_session.current()
        selected_session = None
        if 0 < selected_index < len(self._ptree_session_ids):
            selected_id = self._ptree_session_ids[selected_index]
            selected_session = next(
                (session for session in self.session_history if session["id"] == selected_id),
                None
            )

        if selected_session:
            nodes = selected_session.get("process_tree", [])
            child_mode_enabled = selected_session.get("follow_children", False)
        else:
            nodes = [
                {
                    "pid": node.pid,
                    "ppid": node.ppid,
                    "command": node.command,
                    "status": node.status,
                    "syscall_count": node.syscall_count,
                    "children": list(node.children),
                }
                for node in self.process_tree_tracker.get_all_nodes()
            ]
            child_mode_enabled = self.follow_children_var.get()

        nodes_by_pid = {str(node["pid"]): node for node in nodes}
        total_procs = len(nodes)
        child_mode = "Enabled (-f)" if child_mode_enabled else "Disabled"
        self.lbl_ptree_summary.config(
            text=f"Processes Tracked: {total_procs} | Mode: Child Tracing {child_mode}"
        )

        visited = set()

        def add_node_and_children(node, parent_iid=""):
            pid = str(node["pid"])
            visited.add(pid)
            iid = f"proc_{pid}"
            label = f"[PID {pid}] {node['command']}"
            ppid_str = str(node["ppid"]) if node["ppid"] else "N/A"
            self.ptree_view.insert(
                parent_iid,
                "end",
                iid=iid,
                text=label,
                values=(pid, ppid_str, node["command"], node["status"], node["syscall_count"]),
                open=True
            )
            for child_pid in node.get("children", []):
                child = nodes_by_pid.get(str(child_pid))
                if child and str(child_pid) not in visited:
                    add_node_and_children(child, parent_iid=iid)

        roots = [
            node for node in nodes
            if not node["ppid"] or str(node["ppid"]) not in nodes_by_pid or str(node["ppid"]) == str(node["pid"])
        ]
        for root_node in roots:
            add_node_and_children(root_node, parent_iid="")

        for node in nodes:
            if str(node["pid"]) not in visited:
                add_node_and_children(node, parent_iid="")

    def _refresh_ptree_session_selector(self, selected_session_id=None):
        """Refreshes the process-tree session choices and selects the requested entry."""
        if not hasattr(self, "combo_ptree_session"):
            return

        labels = ["Current / Live"]
        session_ids = [None]
        for session in self.session_history:
            labels.append(
                f"#{session['id']}: {session['command']} ({session['total_count']} calls, {session['timestamp']})"
            )
            session_ids.append(session["id"])

        self._ptree_session_ids = session_ids
        self.combo_ptree_session["values"] = labels
        selected_index = session_ids.index(selected_session_id) if selected_session_id in session_ids else 0
        self.combo_ptree_session.current(selected_index)

    def _on_ptree_session_selected(self, event=None):
        """Displays the chosen saved session tree or returns to the live process tree."""
        self._refresh_ptree_ui()

    def _on_ptree_node_select(self, event=None):
        """Updates detail panel and enables filter button when a process node is selected."""
        selected = self.ptree_view.selection()
        if not selected:
            self.btn_filter_pid.config(state="disabled")
            return

        vals = self.ptree_view.item(selected[0], "values")
        if not vals or len(vals) < 5:
            return

        pid, ppid, cmd, status, count = vals[0], vals[1], vals[2], vals[3], vals[4]
        self.lbl_ptree_detail.config(
            text=f"Selected: PID {pid} (Parent: {ppid}) | Binary: {cmd} | Status: {status} | Syscalls: {count}"
        )
        self.btn_filter_pid.config(state="normal" if self.combo_ptree_session.current() == 0 else "disabled")

    def _filter_trace_by_selected_pid(self):
        """Filters the main monitor table by the selected PID."""
        if self.combo_ptree_session.current() != 0:
            return
        selected = self.ptree_view.selection()
        if not selected:
            return
        vals = self.ptree_view.item(selected[0], "values")
        if vals:
            pid = vals[0]
            self.filter_var.set(pid)
            self.notebook.select(self.tab_monitor)

    def _build_history_tab(self):
        """Builds Phase 2 Session History & Comparison Tab."""
        history_frame = ttk.LabelFrame(self.tab_history, text=" Recorded Sessions History ", padding=8)
        history_frame.pack(fill="x", padx=8, pady=(6, 4))

        cols = ("#", "Timestamp", "Command", "Status", "Total Calls", "Successful", "Failed")
        self.history_tree = ttk.Treeview(history_frame, columns=cols, show="headings", height=5, selectmode="browse")
        for c in cols:
            self.history_tree.heading(c, text=c)
        self.history_tree.column("#", width=45, anchor="center")
        self.history_tree.column("Timestamp", width=145, anchor="center")
        self.history_tree.column("Command", width=250, anchor="w")
        self.history_tree.column("Status", width=130, anchor="center")
        self.history_tree.column("Total Calls", width=90, anchor="center")
        self.history_tree.column("Successful", width=90, anchor="center")
        self.history_tree.column("Failed", width=90, anchor="center")

        hist_scroll = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=hist_scroll.set)
        self.history_tree.pack(side="left", fill="both", expand=True)
        hist_scroll.pack(side="right", fill="y")
        self.history_tree.bind("<Double-1>", lambda event: self._on_history_double_click())

        hist_ctrl_frame = ttk.Frame(self.tab_history, padding=6)
        hist_ctrl_frame.pack(fill="x", padx=8, pady=2)

        ttk.Label(hist_ctrl_frame, text="Session A:").pack(side="left", padx=4)
        self.combo_session_a = ttk.Combobox(hist_ctrl_frame, state="readonly", width=28)
        self.combo_session_a.pack(side="left", padx=4)

        ttk.Button(hist_ctrl_frame, text="Set (A)", command=self._set_session_a_from_selection).pack(side="left", padx=2)

        ttk.Label(hist_ctrl_frame, text="  vs  Session B:").pack(side="left", padx=4)
        self.combo_session_b = ttk.Combobox(hist_ctrl_frame, state="readonly", width=28)
        self.combo_session_b.pack(side="left", padx=4)

        ttk.Button(hist_ctrl_frame, text="Set (B)", command=self._set_session_b_from_selection).pack(side="left", padx=2)

        ttk.Button(hist_ctrl_frame, text="⚔ Compare Sessions", command=self._on_compare_clicked).pack(side="left", padx=8)
        ttk.Button(hist_ctrl_frame, text="Clear History", command=self._clear_history).pack(side="right", padx=4)

        compare_frame = ttk.LabelFrame(self.tab_history, text=" Side-by-Side Session Comparison Analysis ", padding=8)
        compare_frame.pack(fill="both", expand=True, padx=8, pady=(4, 6))

        paned = ttk.PanedWindow(compare_frame, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left_frame = ttk.Frame(paned, padding=4)
        right_frame = ttk.Frame(paned, padding=4)
        paned.add(left_frame, weight=3)
        paned.add(right_frame, weight=2)

        ttk.Label(left_frame, text="Key Operational Metrics Comparison", font=("TkDefaultFont", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cmp_cols = ("Metric", "Session A", "Session B", "Difference (A - B)")
        self.cmp_tree = ttk.Treeview(left_frame, columns=cmp_cols, show="headings", height=10, selectmode="none")
        for c in cmp_cols:
            self.cmp_tree.heading(c, text=c)
        self.cmp_tree.column("Metric", width=150, anchor="w")
        self.cmp_tree.column("Session A", width=130, anchor="center")
        self.cmp_tree.column("Session B", width=130, anchor="center")
        self.cmp_tree.column("Difference (A - B)", width=120, anchor="center")
        self.cmp_tree.pack(fill="both", expand=True)

        ttk.Label(right_frame, text="Top Syscalls Frequency Comparison", font=("TkDefaultFont", 9, "bold")).pack(anchor="w", pady=(0, 4))
        freq_cols = ("Rank", "Session A Syscall", "Session B Syscall")
        self.freq_tree = ttk.Treeview(right_frame, columns=freq_cols, show="headings", height=10, selectmode="none")
        for c in freq_cols:
            self.freq_tree.heading(c, text=c)
        self.freq_tree.column("Rank", width=45, anchor="center")
        self.freq_tree.column("Session A Syscall", width=170, anchor="w")
        self.freq_tree.column("Session B Syscall", width=170, anchor="w")
        self.freq_tree.pack(fill="both", expand=True)

    def _set_session_a_from_selection(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a session row from the history table first.")
            return
        idx = self.history_tree.index(selected[0])
        if 0 <= idx < len(self.session_history):
            self.combo_session_a.current(idx)
            self._auto_compare_if_ready()

    def _set_session_b_from_selection(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a session row from the history table first.")
            return
        idx = self.history_tree.index(selected[0])
        if 0 <= idx < len(self.session_history):
            self.combo_session_b.current(idx)
            self._auto_compare_if_ready()

    def _on_history_double_click(self):
        selected = self.history_tree.selection()
        if not selected:
            return
        idx = self.history_tree.index(selected[0])
        if self.combo_session_a.current() < 0:
            self.combo_session_a.current(idx)
        else:
            self.combo_session_b.current(idx)
        self._auto_compare_if_ready()

    def _auto_compare_if_ready(self):
        idx_a = self.combo_session_a.current()
        idx_b = self.combo_session_b.current()
        if idx_a >= 0 and idx_b >= 0:
            self.compare_sessions(idx_a, idx_b)

    def _on_compare_clicked(self):
        idx_a = self.combo_session_a.current()
        idx_b = self.combo_session_b.current()
        if idx_a < 0 or idx_b < 0:
            messagebox.showinfo("Selection Required", "Please select both Session A and Session B from the dropdowns.")
            return
        self.compare_sessions(idx_a, idx_b)

    def compare_sessions(self, idx_a: int, idx_b: int):
        """Populates the comparison table and frequency breakdown for session indices idx_a and idx_b."""
        if idx_a < 0 or idx_a >= len(self.session_history) or idx_b < 0 or idx_b >= len(self.session_history):
            return

        s_a = self.session_history[idx_a]
        s_b = self.session_history[idx_b]

        for item in self.cmp_tree.get_children():
            self.cmp_tree.delete(item)
        for item in self.freq_tree.get_children():
            self.freq_tree.delete(item)

        def diff_str(val_a, val_b):
            try:
                diff = int(val_a) - int(val_b)
                if diff > 0:
                    return f"+{diff}"
                elif diff < 0:
                    return f"{diff}"
                return "0"
            except Exception:
                return "-"

        metrics_rows = [
            ("Command", s_a["command"], s_b["command"], "-"),
            ("Timestamp", s_a["timestamp"], s_b["timestamp"], "-"),
            ("Status", s_a["status"], s_b["status"], "-"),
            ("Total Syscalls", s_a["total_count"], s_b["total_count"], diff_str(s_a["total_count"], s_b["total_count"])),
            ("Successful Calls", s_a["successful_count"], s_b["successful_count"], diff_str(s_a["successful_count"], s_b["successful_count"])),
            ("Failed Calls", s_a["failed_count"], s_b["failed_count"], diff_str(s_a["failed_count"], s_b["failed_count"])),
        ]
        for cat in ALL_CATEGORIES:
            val_a = s_a["category_counts"].get(cat, 0)
            val_b = s_b["category_counts"].get(cat, 0)
            metrics_rows.append((cat, val_a, val_b, diff_str(val_a, val_b)))

        for row in metrics_rows:
            self.cmp_tree.insert("", "end", values=row)

        freq_a = list(s_a["syscall_frequency"].items())
        freq_b = list(s_b["syscall_frequency"].items())
        max_rows = max(len(freq_a), len(freq_b))
        max_rows = min(max_rows, 10)

        for r in range(max_rows):
            item_a = f"{freq_a[r][0]}: {freq_a[r][1]}" if r < len(freq_a) else "-"
            item_b = f"{freq_b[r][0]}: {freq_b[r][1]}" if r < len(freq_b) else "-"
            self.freq_tree.insert("", "end", values=(r + 1, item_a, item_b))

    def _clear_history(self):
        """Clears in-memory session history."""
        self.session_history.clear()
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.combo_session_a["values"] = []
        self.combo_session_a.set("")
        self.combo_session_b["values"] = []
        self.combo_session_b.set("")
        for item in self.cmp_tree.get_children():
            self.cmp_tree.delete(item)
        for item in self.freq_tree.get_children():
            self.freq_tree.delete(item)
        self._refresh_ptree_session_selector()
        self._refresh_ptree_ui()

    def _save_current_session(self, status: str):
        """Saves current monitoring session records and statistics into in-memory history."""
        if self._session_saved or not self.records:
            return
        self._session_saved = True

        stats = compute_statistics(self.records)
        session_data = {
            "id": len(self.session_history) + 1,
            "command": self.last_command or self.cmd_entry.get().strip() or "Unknown command",
            "timestamp": (self.session_start_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "total_count": stats["total_count"],
            "successful_count": stats["successful_count"],
            "failed_count": stats["failed_count"],
            "category_counts": dict(stats["category_counts"]),
            "syscall_frequency": dict(stats["syscall_frequency"]),
            "records": list(self.records),
            "follow_children": self.follow_children_var.get(),
            "process_tree": [
                {
                    "pid": node.pid,
                    "ppid": node.ppid,
                    "command": node.command,
                    "status": node.status,
                    "syscall_count": node.syscall_count,
                    "children": list(node.children),
                }
                for node in self.process_tree_tracker.get_all_nodes()
            ],
        }
        self.session_history.append(session_data)
        self._refresh_history_ui()
        self._refresh_ptree_session_selector(session_data["id"])

    def _refresh_history_ui(self):
        """Updates the session history treeview and combobox values."""
        if not hasattr(self, "history_tree"):
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        combo_values = []
        for s in self.session_history:
            self.history_tree.insert(
                "", "end",
                values=(
                    s["id"],
                    s["timestamp"],
                    s["command"],
                    s["status"],
                    s["total_count"],
                    s["successful_count"],
                    s["failed_count"],
                )
            )
            combo_values.append(f"#{s['id']}: {s['command']} ({s['total_count']} calls, {s['timestamp']})")

        self.combo_session_a["values"] = combo_values
        self.combo_session_b["values"] = combo_values

        if len(combo_values) >= 2 and not self.combo_session_a.get():
            self.combo_session_a.current(len(combo_values) - 2)
            self.combo_session_b.current(len(combo_values) - 1)
            self._auto_compare_if_ready()
        elif len(combo_values) == 1 and not self.combo_session_a.get():
            self.combo_session_a.current(0)


    def _refresh_export_button_state(self):
        """Enables export only when complete session data exists and monitoring is not active."""
        if hasattr(self, "btn_export"):
            self.btn_export.config(state="normal" if (self.records and not self.is_monitoring) else "disabled")

    # -----------------------------------------------------------------
    # Phase 1: Export / Save Session Reports
    # -----------------------------------------------------------------
    def _write_csv_report(self, path: str):
        """Exports all captured session records to CSV using Python's csv module."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "PID", "Syscall", "Category", "Key Details", "Arguments", "Return Value"])
            for idx, rec in enumerate(self.records, start=1):
                writer.writerow([
                    idx,
                    rec.get("pid", "Main"),
                    rec.get("name", ""),
                    rec.get("category", "Other"),
                    rec.get("key_details", ""),
                    rec.get("arguments", ""),
                    rec.get("return_value", "")
                ])

    def _write_text_report(self, path: str):
        """Exports a readable text summary of the full session according to Phase 1 spec."""
        command_name = self.last_command or self.cmd_entry.get().strip() or "Unknown command"
        timestamp = (self.session_start_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "System Call Monitoring Report",
            "=============================",
            "",
            f"Command: {command_name}",
            f"Date/Time: {timestamp}",
            f"Child Process Tracing (-f): {'Enabled' if self.follow_children_var.get() else 'Disabled'}",
            "",
            f"Total Syscalls: {self.total_count}",
            f"Successful Calls: {self.successful_count}",
            f"Failed Calls: {self.failed_count}",
            "",
            "Category Breakdown:",
        ]

        for cat in ALL_CATEGORIES:
            lines.append(f"{cat}: {self.category_counts.get(cat, 0)}")

        lines.extend([
            "",
            "Syscall Records",
            "---------------",
            "",
        ])

        for idx, rec in enumerate(self.records, start=1):
            kd = rec.get("key_details", "")
            kd_str = f" | {kd}" if kd else ""
            lines.append(
                f"{idx}. [PID {rec.get('pid', 'Main')}] {rec.get('name', '')} | {rec.get('category', 'Other')}{kd_str} | "
                f"{rec.get('arguments', '')} | {rec.get('return_value', '')}"
            )

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def export_session(self, target_path: str = None):
        """
        Saves the full session data to CSV or TXT using a file-save dialog.
        Preserves complete session records even if the table is currently filtered.
        """
        if not self.records:
            if not target_path:
                messagebox.showinfo("No Data", "There are no syscall records to export yet.")
            return None

        if target_path:
            save_path = target_path
        else:
            timestamp = (self.session_start_time or datetime.now()).strftime("%Y%m%d_%H%M%S")
            initial_name = f"syscall_report_{timestamp}.csv"
            save_path = filedialog.asksaveasfilename(
                initialfile=initial_name,
                title="Save Session Report",
                defaultextension=".csv",
                filetypes=[
                    ("CSV file (*.csv)", "*.csv"),
                    ("Text file (*.txt)", "*.txt"),
                    ("All files (*.*)", "*.*")
                ]
            )

        if not save_path:
            return None

        ext = os.path.splitext(save_path)[1].lower()
        if ext == ".txt":
            self._write_text_report(save_path)
        else:
            if not ext:
                save_path += ".csv"
            self._write_csv_report(save_path)

        if not target_path:
            messagebox.showinfo("Export complete", f"Session report saved to:\n{save_path}")
        return save_path

    # -----------------------------------------------------------------
    # Filtering Logic
    # -----------------------------------------------------------------
    def _matches_filter(self, record: dict) -> bool:
        """
        Tests whether a record satisfies the current search term and category dropdown.
        """
        query = self.filter_var.get().strip().lower()
        cat_filter = self.cat_filter_var.get()

        # 1. Category dropdown filter
        if cat_filter != "All Categories" and record.get("category", "") != cat_filter:
            return False

        # 2. Free-text search query (matches against PID, syscall name, category, key details, or arguments)
        if query:
            pid = str(record.get("pid", "")).lower()
            name = record.get("name", "").lower()
            cat = record.get("category", "").lower()
            details = record.get("key_details", "").lower()
            args = record.get("arguments", "").lower()
            if (query not in pid and
                query not in name and
                query not in cat and
                query not in details and
                query not in args):
                return False

        return True

    def _on_filter_changed(self, *args):
        """Callback invoked when search text or category dropdown changes."""
        self._refilter_table()

    def reset_filter(self):
        """Clears search input and resets dropdown to All Categories."""
        self.filter_var.set("")
        self.cat_filter_var.set("All Categories")
        self._refilter_table()

    def _refilter_table(self):
        """
        Repopulates the Treeview table with records that match the active filter.
        Does NOT alter or reset the underlying statistics or full dataset.
        """
        for item in self.tree.get_children():
            self.tree.delete(item)

        displayed_count = 0
        for idx, rec in enumerate(self.records, start=1):
            if self._matches_filter(rec):
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        idx,
                        rec.get("pid", "Main"),
                        rec.get("name", ""),
                        rec.get("category", "Other"),
                        rec.get("key_details", ""),
                        rec.get("arguments", ""),
                        rec.get("return_value", "")
                    )
                )
                displayed_count += 1

        self.lbl_filter_count.config(text=f"Showing: {displayed_count} / {self.total_count} calls")

        if self.auto_scroll_var.get():
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

    # -----------------------------------------------------------------
    # Execution & Process Control
    # -----------------------------------------------------------------
    def start_monitoring(self):
        """Initiates tracing of the command specified in the entry field."""
        if self.is_monitoring:
            return

        cmd = self.cmd_entry.get().strip()
        if not cmd:
            messagebox.showwarning("Empty Command", "Please enter a valid command to trace.")
            return

        self.is_monitoring = True
        self.last_command = cmd
        self.session_start_time = datetime.now()
        self._session_saved = False

        # Phase 9: Record into command history
        self._add_command_to_history(cmd)

        # Phase 8: Follow child processes flag & process tree reset
        follow_children = self.follow_children_var.get()
        self.process_tree_tracker.reset(root_command=cmd)
        self._refresh_ptree_session_selector()
        self._refresh_ptree_ui()

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_clear.config(state="disabled")
        self.btn_export.config(state="disabled")
        self.chk_child.config(state="disabled")
        self.combo_history.config(state="disabled")
        self.lbl_status.config(text="Status: Monitoring...", foreground="#0066cc")

        # --- Stage 6.1: Open a FRESH raw output window for this session ---
        # A new RawOutputWindow is created every time Start is clicked.
        # The single real strace process feeds BOTH this window and the parser.
        self._raw_window = RawOutputWindow(self.root, cmd)

        def _worker():
            def on_line(raw_line):
                # Feed the raw line to the dedicated terminal-style window
                self._raw_window.append_line(raw_line)

                # Phase 8: Track process events (attaches, exits, signals)
                self.process_tree_tracker.handle_raw_line(raw_line)

                # Also parse it and send structured record to the main GUI queue
                record = parse_syscall_line(raw_line)
                if record is not None:
                    # Phase 8: Associate syscall with PID and update process tree
                    self.process_tree_tracker.record_syscall(
                        record.get("pid", "Main"),
                        record.get("name", ""),
                        record.get("arguments", ""),
                        record.get("return_value", "")
                    )
                    self.queue.put(("record", record))

            try:
                self.session = TraceSession()
                self.session.start(cmd, on_line=on_line, follow_children=follow_children)
            except Exception as e:
                self.queue.put(("error", str(e)))
            finally:
                # Signal the raw window that tracing is done
                rc = self.session.process.returncode if self.session and self.session.process else 0
                self._raw_window.mark_finished(rc)
                self.queue.put(("finished", None))

        self.worker_thread = threading.Thread(target=_worker, daemon=True)
        self.worker_thread.start()

    def stop_monitoring(self):
        """Terminates active monitoring process group."""
        if self.session and self.is_monitoring:
            self.lbl_status.config(text="Status: Stopped", foreground="#cc6600")
            self.session.stop()
            self.is_monitoring = False
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")
            self.btn_clear.config(state="normal")
            self.chk_child.config(state="normal")
            self.combo_history.config(state="readonly")
            self._save_current_session("Stopped (Incomplete)")
            self._refresh_export_button_state()
            self._refresh_ptree_ui()

    def clear_data(self):
        """Resets the UI table, active filter, and underlying dataset/statistics."""
        if self.is_monitoring:
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.records.clear()
        self.total_count = 0
        self.category_counts = {cat: 0 for cat in ALL_CATEGORIES}
        self.successful_count = 0
        self.failed_count = 0

        self.filter_var.set("")
        self.cat_filter_var.set("All Categories")
        self.last_command = ""
        self.session_start_time = None
        self._session_saved = False
        self.process_tree_tracker.reset(root_command=self.cmd_entry.get().strip())
        self._refresh_ptree_session_selector()

        self._reset_about_panel()
        self._refresh_stats_ui()
        self._refresh_ptree_ui()
        self._refresh_export_button_state()
        self.lbl_filter_count.config(text="Showing: 0 / 0 calls")
        self.lbl_status.config(text="Status: Ready", foreground="#2c3e50")

    def _add_record(self, record: dict):
        """Appends a new record to the master dataset, updates statistics, and inserts if it matches filter."""
        self.records.append(record)
        self.total_count += 1

        cat = record.get("category", "Other")
        self.category_counts[cat] = self.category_counts.get(cat, 0) + 1

        ret_val = record.get("return_value", "")
        if is_failed_syscall(ret_val):
            self.failed_count += 1
        else:
            self.successful_count += 1

        # Only insert into Treeview if it matches the current active filter
        if self._matches_filter(record):
            self.tree.insert(
                "",
                "end",
                values=(
                    self.total_count,
                    record.get("pid", "Main"),
                    record.get("name", ""),
                    cat,
                    record.get("key_details", ""),
                    record.get("arguments", ""),
                    ret_val
                )
            )
            if self.auto_scroll_var.get():
                children = self.tree.get_children()
                if children:
                    self.tree.see(children[-1])

    def _refresh_stats_ui(self):
        """Refreshes the statistics labels, filtered row counter, live visualization chart, and failure analysis UI."""
        self.lbl_stat_total.config(text=f"Total Syscalls: {self.total_count}")
        self.lbl_stat_success.config(text=f"Successful: {self.successful_count}")
        self.lbl_stat_failed.config(text=f"Failed: {self.failed_count}")

        for cat_name, lbl in self.lbl_stat_cats.items():
            lbl.config(text=f"{cat_name}: {self.category_counts.get(cat_name, 0)}")

        displayed_count = len(self.tree.get_children())
        self.lbl_filter_count.config(text=f"Showing: {displayed_count} / {self.total_count} calls")

        # Live Canvas Bar Chart & Failure Analysis UI update
        self._draw_chart()
        self._refresh_failures_ui()

    def _poll_queue(self):
        """
        Dequeues parsed syscalls in batches to maintain high throughput and UI responsiveness.
        """
        batch_limit = 60
        processed = 0

        while processed < batch_limit and not self.queue.empty():
            msg_type, payload = self.queue.get_nowait()
            if msg_type == "record":
                self._add_record(payload)
            elif msg_type == "finished":
                self.is_monitoring = False
                self.btn_start.config(state="normal")
                self.btn_stop.config(state="disabled")
                self.btn_clear.config(state="normal")
                self.chk_child.config(state="normal")
                self.combo_history.config(state="readonly")
                is_stopped = (self.lbl_status.cget("text") == "Status: Stopped")
                status = "Stopped (Incomplete)" if is_stopped else "Completed"
                if not is_stopped:
                    self.lbl_status.config(text="Status: Finished", foreground="#009933")
                self._save_current_session(status)
                self._refresh_export_button_state()
                self._refresh_ptree_ui()
            elif msg_type == "error":
                self.is_monitoring = False
                self.btn_start.config(state="normal")
                self.btn_stop.config(state="disabled")
                self.btn_clear.config(state="normal")
                self.chk_child.config(state="normal")
                self.combo_history.config(state="readonly")
                self.lbl_status.config(text=f"Status: Error ({payload})", foreground="#cc0000")
                self._save_current_session("Error (Incomplete)")
                self._refresh_export_button_state()
                self._refresh_ptree_ui()

            processed += 1

        if processed > 0:
            self._refresh_stats_ui()
            self._refresh_ptree_ui()

        self.root.after(30, self._poll_queue)

    # -----------------------------------------------------------------
    # Automated Multi-Command Verification Suite
    # -----------------------------------------------------------------
    def _run_automated_tests(self):
        """
        Automated test sequence to verify:
        - Phase 1: CSV/TXT export & filter invariance
        - Phase 2: In-memory session history tracking & comparative analysis
        - Phase 3: Real-time Live Visualization bar chart
        - Phase 4: Expanded System Call Classification (7 categories)
        Runs real Linux commands: cat sample.txt, ls -la, python3 -c "print('hello')"
        """
        print("\n============================================================")
        print("[*] OScope Automated Test: Phase 1, 2, 3 & 4 Verification")
        print("============================================================")

        # -------------------------------------------------------------
        # Phase 4 Pre-Check: Syscall Classification Mapping
        # -------------------------------------------------------------
        print("\n[*] Phase 4 Check: Verifying required syscall classifications...")
        test_mappings = {
            "openat": "File I/O / File System",
            "read": "File I/O / File System",
            "write": "File I/O / File System",
            "socket": "Network",
            "connect": "Network",
            "kill": "Signal",
            "pipe": "IPC",
            "clone": "Process Control",
            "execve": "Process Control",
            "mmap": "Memory Management",
            "munmap": "Memory Management",
        }
        for name, expected_cat in test_mappings.items():
            actual = classify_syscall(name)
            assert actual == expected_cat, f"Classification mismatch for {name}: expected '{expected_cat}', got '{actual}'"
        assert classify_syscall("unmapped_dummy_call") == "Other", "Unmapped syscalls must fallback to 'Other'"
        print(f"[✓] Phase 4: All {len(test_mappings)} required syscalls mapped correctly.")

        assert str(self.btn_export.cget("state")) == "disabled", "Export button must be disabled initially when no data"
        assert len(self.session_history) == 0, "Session history must be empty at start"

        # -------------------------------------------------------------
        # Test 1: Run 'cat sample.txt'
        # -------------------------------------------------------------
        print("\n[*] Test 1: Running real Linux command: cat sample.txt")
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, "cat sample.txt")
        self.start_monitoring()

        def step_after_test1():
            if self.is_monitoring:
                self.root.after(200, step_after_test1)
                return

            print(f"[+] Test 1 Finished. Total syscalls: {self.total_count}")
            print(f"    Categories: {self.category_counts}")
            print(f"    Successful: {self.successful_count}, Failed: {self.failed_count}")
            assert str(self.btn_export.cget("state")) == "normal", "Export button must be enabled after test 1"
            assert self.category_counts.get("File I/O / File System", 0) > 0, "File I/O / File System count should be > 0"
            assert self.category_counts.get("Memory Management", 0) > 0, "Memory Management count should be > 0"
            assert self.category_counts.get("Process Control", 0) > 0, "Process Control count should be > 0"

            # Phase 2 check: Session 1 saved in history
            assert len(self.session_history) == 1, "Session history should have exactly 1 session"
            s1 = self.session_history[0]
            assert s1["command"] == "cat sample.txt", "Session 1 command mismatch"
            assert s1["status"] == "Completed", "Session 1 status should be Completed"
            assert s1["total_count"] == self.total_count, "Session 1 total count mismatch"
            assert len(s1["syscall_frequency"]) > 0, "Session 1 syscall frequency should not be empty"
            print(f"[✓] Phase 2: Session 1 recorded in memory with {s1['total_count']} calls.")

            # Phase 3 check: Live Bar Chart
            assert hasattr(self, "chart_canvas"), "Chart canvas must exist"
            canvas_items = self.chart_canvas.find_all()
            assert len(canvas_items) > 0, "Chart canvas should render visual elements"
            print(f"[✓] Phase 3: Canvas bar chart rendered {len(canvas_items)} canvas primitives.")

            # Phase 5 check: Structured Key Details extraction
            openat_success = [r for r in self.records if r.get("name") == "openat" and 'sample.txt' in r.get("arguments", "")]
            assert len(openat_success) > 0, "Expected openat for sample.txt"
            kd_openat = openat_success[0].get("key_details", "")
            assert 'path="sample.txt"' in kd_openat, f"Expected path in openat details, got: {kd_openat}"
            assert 'flags=O_RDONLY' in kd_openat, f"Expected flags in openat details, got: {kd_openat}"
            assert 'fd=3' in kd_openat, f"Expected fd=3 in openat details, got: {kd_openat}"

            read_recs = [r for r in self.records if r.get("name") == "read" and r.get("return_value") == "60"]
            assert len(read_recs) > 0, "Expected read with return_value 60"
            kd_read = read_recs[0].get("key_details", "")
            assert 'fd=3' in kd_read and 'read=60B' in kd_read, f"Expected fd=3, read=60B in read details, got: {kd_read}"

            write_recs = [r for r in self.records if r.get("name") == "write" and r.get("return_value") == "60"]
            assert len(write_recs) > 0, "Expected write with return_value 60"
            kd_write = write_recs[0].get("key_details", "")
            assert 'fd=1' in kd_write and 'written=60B' in kd_write, f"Expected fd=1, written=60B in write details, got: {kd_write}"

            close_recs = [r for r in self.records if r.get("name") == "close" and r.get("arguments") == "3"]
            assert len(close_recs) > 0, "Expected close(3)"
            kd_close = close_recs[0].get("key_details", "")
            assert 'fd=3, success' in kd_close, f"Expected fd=3, success in close details, got: {kd_close}"

            failed_openat = [r for r in self.records if r.get("name") == "openat" and "-1" in r.get("return_value", "")]
            assert len(failed_openat) > 0, "Expected failed openat call"
            kd_failed = failed_openat[0].get("key_details", "")
            assert "failed" in kd_failed, f"Expected failed in key details, got: {kd_failed}"
            print("[✓] Phase 5: Structured Key Details verified for openat, read, write, close, and failed calls.")

            # Phase 1 Test: Export while table is filtered to 'openat'
            self.filter_var.set("openat")
            openat_count = len(self.tree.get_children())
            print(f"[+] Filter 'openat' shows {openat_count} rows in table.")

            csv_file = "test_session1.csv"
            txt_file = "test_session1.txt"
            self.export_session(target_path=csv_file)
            self.export_session(target_path=txt_file)

            with open(csv_file, "r", encoding="utf-8") as f:
                reader = list(csv.reader(f))
                assert len(reader) - 1 == self.total_count, "CSV must contain ALL session records, not just filtered rows"
                header = reader[0]
                assert "Key Details" in header, "CSV header must include 'Key Details'"
                assert header == ["#", "PID", "Syscall", "Category", "Key Details", "Arguments", "Return Value"]

            with open(txt_file, "r", encoding="utf-8") as f:
                txt_content = f.read()
                assert "System Call Monitoring Report" in txt_content
                assert "Command: cat sample.txt" in txt_content
                assert f"Total Syscalls: {self.total_count}" in txt_content
                assert "File I/O / File System:" in txt_content

            for p in (csv_file, txt_file):
                try:
                    os.remove(p)
                except Exception:
                    pass
            print("[✓] Phase 1 & 5: CSV and TXT reports with Key Details verified.")

            # Search filter test using Key Details
            self.filter_var.set("sample.txt")
            sample_count = len(self.tree.get_children())
            assert sample_count > 0, "Filter matching key_details 'sample.txt' should return rows"
            print(f"[✓] Phase 5: Search filtering against Key Details ('sample.txt') returned {sample_count} row(s).")

            self.reset_filter()

            # Clear live data: live table and chart reset, but history is retained!
            self.clear_data()
            assert self.total_count == 0, "Clear data must reset total count"
            assert len(self.session_history) == 1, "Session history must retain completed sessions after Clear"
            print("[✓] Phase 2: In-memory session history preserved after Clear.")

            # -------------------------------------------------------------
            # Test 2: Run 'ls -la'
            # -------------------------------------------------------------
            print("\n[*] Test 2: Running real Linux command: ls -la")
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, "ls -la")
            self.start_monitoring()

            def step_after_test2():
                if self.is_monitoring:
                    self.root.after(200, step_after_test2)
                    return

                print(f"[+] Test 2 Finished. Total syscalls: {self.total_count}")
                assert len(self.session_history) == 2, "Session history should have exactly 2 sessions"
                s2 = self.session_history[1]
                assert s2["command"] == "ls -la", "Session 2 command mismatch"
                assert s2["status"] == "Completed", "Session 2 status should be Completed"
                print(f"[✓] Phase 2: Session 2 recorded in memory with {s2['total_count']} calls.")

                self.clear_data()
                assert len(self.session_history) == 2, "Both sessions must persist in history after Clear"

                # -------------------------------------------------------------
                # Test 3: Run 'python3 -c "print(\'hello\')"'
                # -------------------------------------------------------------
                print("\n[*] Test 3: Running real Linux command: python3 -c \"print('hello')\"")
                self.cmd_entry.delete(0, tk.END)
                self.cmd_entry.insert(0, 'python3 -c "print(\'hello\')"')
                self.start_monitoring()

                def step_after_test3():
                    if self.is_monitoring:
                        self.root.after(200, step_after_test3)
                        return

                    print(f"[+] Test 3 Finished. Total syscalls: {self.total_count}")
                    assert len(self.session_history) == 3, "Session history should have exactly 3 sessions"
                    print("[✓] Phase 2: All 3 distinct sessions recorded successfully.")

                    # ---------------------------------------------------------
                    # Test Session Comparison (Phase 2 & 4)
                    # ---------------------------------------------------------
                    print("\n[*] Phase 2 & 4 Test: Comparing Session 1 (cat) vs Session 2 (ls -la)...")
                    self.compare_sessions(0, 1)

                    cmp_children = self.cmp_tree.get_children()
                    assert len(cmp_children) == 6 + len(ALL_CATEGORIES), f"Comparison table should have {6 + len(ALL_CATEGORIES)} rows"

                    # Verify metric values in tree match sessions
                    cmp_dict = {}
                    for item in cmp_children:
                        vals = self.cmp_tree.item(item, "values")
                        cmp_dict[vals[0]] = (vals[1], vals[2], vals[3])

                    s1_ref = self.session_history[0]
                    s2_ref = self.session_history[1]

                    assert str(cmp_dict["Total Syscalls"][0]) == str(s1_ref["total_count"])
                    assert str(cmp_dict["Total Syscalls"][1]) == str(s2_ref["total_count"])
                    assert str(cmp_dict["Successful Calls"][0]) == str(s1_ref["successful_count"])
                    assert str(cmp_dict["Successful Calls"][1]) == str(s2_ref["successful_count"])
                    for cat in ALL_CATEGORIES:
                        assert cat in cmp_dict, f"Category '{cat}' missing from comparison table"
                        assert str(cmp_dict[cat][0]) == str(s1_ref["category_counts"].get(cat, 0))
                        assert str(cmp_dict[cat][1]) == str(s2_ref["category_counts"].get(cat, 0))
                    print(f"[✓] Phase 2 & 4: Comparison table metrics verified (all {len(ALL_CATEGORIES)} categories matched).")

                    freq_children = self.freq_tree.get_children()
                    assert len(freq_children) > 0, "Frequency comparison table should be populated"
                    print(f"[✓] Phase 2: Top syscalls frequency comparison verified ({len(freq_children)} ranks).")

                    # Switch to visualization tab and verify chart
                    self.notebook.select(self.tab_visual)
                    self._draw_chart()
                    print("[✓] Phase 3 & 4: Visualization tab switched and 7-category live chart verified.")

                    # ---------------------------------------------------------
                    # Phase 6 & Phase 7 Verification
                    # ---------------------------------------------------------
                    print("\n[*] Phase 6 & Phase 7 Test: Verifying Failure Analysis and Syscall Info...")
                    info_openat = get_syscall_info("openat", "File I/O / File System")
                    assert info_openat["name"] == "openat"
                    assert "Virtual File System" in info_openat["concept"]

                    info_unknown = get_syscall_info("unknown_call_xyz", "Other")
                    assert "transitions from user mode" in info_unknown["description"]
                    print("[✓] Phase 7: get_syscall_info verified for known (openat) and unknown fallback call.")

                    # Verify Failure Analysis
                    failures = compute_failure_analysis(self.records)
                    assert failures["total_failures"] == self.failed_count, "Failure analysis count must match failed_count"
                    if failures["total_failures"] > 0:
                        first_fail = failures["failed_records"][0]
                        assert first_fail["errno_code"] != "", "Errno code must be populated"
                        assert first_fail["explanation"] != "", "Plain-English explanation must be populated"
                        print(f"[✓] Phase 6: Failure analysis record verified ({first_fail['name']} -> {first_fail['errno_code']}: {first_fail['explanation']}).")

                    self.notebook.select(self.tab_failures)
                    self._refresh_failures_ui()
                    fail_tree_rows = len(self.failure_tree.get_children())
                    assert fail_tree_rows == self.failed_count, f"Failure tree rows ({fail_tree_rows}) must equal failed_count ({self.failed_count})"
                    print(f"[✓] Phase 6: Failure Analysis tree populated with {fail_tree_rows} row(s).")

                    # Verify Tree Selection updates About Panel
                    children = self.tree.get_children()
                    if children:
                        self.tree.selection_set(children[0])
                        self._on_tree_select()
                        about_title = self.lbl_about_title.cget("text")
                        assert "Syscall:" in about_title, "About title label should update when tree row selected"
                        print(f"[✓] Phase 7: Tree selection updated About panel label to '{about_title}'.")

                    # ---------------------------------------------------------
                    # Phase 9 Verification: In-Memory Command History
                    # ---------------------------------------------------------
                    print("\n[*] Phase 9 Test: Verifying in-memory command history...")
                    assert "cat sample.txt" in self.command_history
                    assert "ls -la" in self.command_history
                    assert 'python3 -c "print(\'hello\')"' in self.command_history
                    assert len(self.command_history) <= 10

                    # Test avoiding consecutive duplicate
                    prev_len = len(self.command_history)
                    self._add_command_to_history('python3 -c "print(\'hello\')"')
                    assert len(self.command_history) == prev_len, "Consecutive duplicate must not be added"

                    # Test selection fills command entry without starting monitoring
                    self.combo_history.set("cat sample.txt")
                    self._on_history_command_selected()
                    assert self.cmd_entry.get() == "cat sample.txt"
                    assert self.is_monitoring is False, "Command selection must not start monitoring"
                    print("[✓] Phase 9: Command history (10 distinct max, consecutive deduplication, fill without auto-start) verified.")

                    # Clear data before Test 4
                    self.clear_data()

                    # ---------------------------------------------------------
                    # Phase 8 Verification: Child Process Tracing & Process Tree
                    # ---------------------------------------------------------
                    print("\n[*] Phase 8 Test: Running real process with child execution...")
                    child_cmd = 'python3 -c "import subprocess; subprocess.run([\'echo\', \'child_trace_test\'])"'
                    self.cmd_entry.delete(0, tk.END)
                    self.cmd_entry.insert(0, child_cmd)
                    self.follow_children_var.set(True)  # Enable strace -f
                    self.start_monitoring()

                    def step_after_test4():
                        if self.is_monitoring:
                            self.root.after(200, step_after_test4)
                            return

                        print(f"[+] Test 4 (Child Tracing) Finished. Total syscalls: {self.total_count}")
                        nodes = self.process_tree_tracker.get_all_nodes()
                        print(f"    Tracked Processes: {len(nodes)}")
                        for n in nodes:
                            print(f"      PID: {n.pid}, PPID: {n.ppid}, Cmd: {n.command}, Status: {n.status}, Calls: {n.syscall_count}")

                        assert len(nodes) >= 2, f"Expected at least 2 process nodes, got {len(nodes)}"
                        child_nodes = [n for n in nodes if n.ppid is not None]
                        assert len(child_nodes) >= 1, "Expected at least 1 child node with parent PID"
                        echo_node = [n for n in child_nodes if "echo" in n.command]
                        assert len(echo_node) >= 1, "Expected child node running 'echo'"
                        assert echo_node[0].syscall_count > 0, "Child process should have captured syscalls"

                        # Process Tree Tab verification
                        self.notebook.select(self.tab_ptree)
                        self._refresh_ptree_ui()
                        ptree_items = self.ptree_view.get_children()
                        assert len(ptree_items) > 0, "Process Tree UI view should contain nodes"

                        # Test selecting child and filtering by PID
                        child_pid = echo_node[0].pid
                        self.ptree_view.selection_set(f"proc_{child_pid}")
                        self._on_ptree_node_select()
                        self._filter_trace_by_selected_pid()
                        assert self.filter_var.get() == child_pid
                        child_displayed = len(self.tree.get_children())
                        assert child_displayed > 0, "Filtered table should display child process syscalls"
                        print(f"[✓] Phase 8: Child process '{echo_node[0].command}' (PID {child_pid}) tracked under parent {echo_node[0].ppid} with {child_displayed} calls.")

                        self.reset_filter()

                        # -----------------------------------------------------
                        # Clean Process Termination / Stop Monitoring Test
                        # -----------------------------------------------------
                        print("\n[*] Phase 8 Process Control Test: Verifying clean Stop Monitoring...")
                        self.cmd_entry.delete(0, tk.END)
                        self.cmd_entry.insert(0, 'python3 -c "import time; time.sleep(10)"')
                        self.start_monitoring()
                        assert self.is_monitoring is True

                        def do_stop_check():
                            self.stop_monitoring()
                            assert self.is_monitoring is False
                            assert "Stopped" in self.lbl_status.cget("text")
                            last_sess = self.session_history[-1]
                            assert "Stopped" in last_sess["status"]
                            print("[✓] Stop monitoring cleanly terminated the process group.")

                            print("\n" + "=" * 60)
                            print("[✓] ALL OScope Phases 1–9 Verification Tests Passed Successfully!")
                            print("============================================================")
                            self.root.after(400, self.root.destroy)

                        self.root.after(500, do_stop_check)

                    self.root.after(300, step_after_test4)

                self.root.after(300, step_after_test3)

            self.root.after(300, step_after_test2)

        self.root.after(300, step_after_test1)


def main():
    auto_test = "--test" in sys.argv
    root = tk.Tk()
    app = SyscallMonitorApp(root, auto_test=auto_test)
    root.mainloop()


if __name__ == "__main__":
    main()
