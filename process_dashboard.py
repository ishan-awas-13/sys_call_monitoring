"""
OScope — Process & Resource Dashboard Module
Extracts running process information, scheduler metrics, memory usage, and process
hierarchies directly from the Linux /proc virtual filesystem (procfs), with optional
psutil acceleration.

Distinguishes:
- Process Resource Metrics: Periodic sampling of kernel state (/proc)
- Syscall-Derived Statistics: Event-driven cumulative tracing (strace/ptrace)
"""

import os
import sys
import time
import pwd
from typing import Dict, List, Optional, Tuple, Any

# Informational constant explaining the fundamental OS architectural difference
DISTINCTION_EXPLANATION = {
    "resource_metrics": {
        "title": "Process Resource Metrics (Sampling / Snapshot)",
        "source": "Linux Virtual File System (/proc)",
        "mechanism": "Periodic snapshot of kernel data structures (task_struct, mm_struct)",
        "metrics": "CPU utilization %, Memory RSS/VmSize, Process State (R/S/D/Z), Thread Count",
        "overhead": "Near-zero overhead; non-intrusive polling interval",
        "purpose": "Observes macroscopic operating system resource allocation and scheduler state"
    },
    "syscall_statistics": {
        "title": "System Call Statistics (Event-Driven / Continuous Trace)",
        "source": "Linux ptrace via strace",
        "mechanism": "Dynamic trap intercepting user-kernel boundary transitions for every syscall",
        "metrics": "Syscall frequency, execution latency, errno failure breakdown, arguments/return values",
        "overhead": "Higher per-syscall trap overhead (context switches & signal traps)",
        "purpose": "Observes microscopic interactions between application code and OS kernel services"
    }
}

STATE_DESCRIPTIONS = {
    "R": "R (Running / Runnable) — Actively executing on CPU or waiting in the scheduler run-queue.",
    "S": "S (Interruptible Sleep) — Blocked waiting for an event (e.g. I/O completion, timer, signal).",
    "D": "D (Uninterruptible Disk Sleep) — Blocked on critical hardware/device I/O; cannot be interrupted by signals.",
    "Z": "Z (Zombie / Defunct) — Terminated; entry remains in process table until parent calls wait()/waitpid().",
    "T": "T (Stopped / Traced) — Paused by a job control signal (SIGSTOP/SIGTSTP) or paused under ptrace.",
    "t": "t (Tracing Stop) — Paused by a debugger/tracer (e.g. strace / gdb) at a syscall entry/exit boundary.",
    "I": "I (Idle Kernel Thread) — Kernel thread in deep idle state.",
    "X": "X (Dead) — Terminated and being cleared from kernel memory."
}


class ProcessCollector:
    """
    Collects live process information, resource usage, and process lineage directly
    from Linux /proc with sub-second performance.
    """

    def __init__(self):
        self._user_cache: Dict[int, str] = {}
        self._prev_proc_ticks: Dict[int, int] = {}
        self._prev_sys_time: float = 0.0
        self._prev_total_ticks: int = 0
        self._num_cpus = os.cpu_count() or 1
        self._clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

    def _resolve_username(self, uid: int) -> str:
        """Translates numeric UID to username with caching."""
        if uid in self._user_cache:
            return self._user_cache[uid]
        try:
            name = pwd.getpwuid(uid).pw_name
        except Exception:
            name = str(uid)
        self._user_cache[uid] = name
        return name

    def _read_total_cpu_ticks(self) -> int:
        """Reads cumulative CPU ticks across all cores from /proc/stat."""
        try:
            with open("/proc/stat", "r") as f:
                for line in f:
                    if line.startswith("cpu "):
                        parts = line.split()[1:]
                        return sum(int(p) for p in parts if p.isdigit())
        except Exception:
            pass
        return 0

    def get_process_list(self) -> List[Dict[str, Any]]:
        """
        Scans /proc for all running processes and calculates periodic CPU & memory metrics.
        Returns a sorted list of process dictionaries.
        """
        curr_sys_ticks = self._read_total_cpu_ticks()
        delta_sys_ticks = curr_sys_ticks - self._prev_total_ticks if self._prev_total_ticks > 0 else 0

        curr_proc_ticks: Dict[int, int] = {}
        processes: List[Dict[str, Any]] = []

        try:
            entries = os.listdir("/proc")
        except Exception:
            return []

        for entry in entries:
            if not entry.isdigit():
                continue

            pid = int(entry)
            status_path = f"/proc/{pid}/status"
            stat_path = f"/proc/{pid}/stat"
            cmdline_path = f"/proc/{pid}/cmdline"

            try:
                # 1. Parse /proc/[pid]/status
                name = ""
                state_code = "S"
                ppid = 0
                uid = 0
                threads = 1
                vm_rss_kb = 0
                vm_size_kb = 0

                with open(status_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("Name:"):
                            name = line.split(None, 1)[1].strip()
                        elif line.startswith("State:"):
                            state_val = line.split(None, 1)[1].strip()
                            state_code = state_val.split()[0] if state_val else "S"
                        elif line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                        elif line.startswith("Uid:"):
                            uid = int(line.split()[1])
                        elif line.startswith("Threads:"):
                            threads = int(line.split()[1])
                        elif line.startswith("VmRSS:"):
                            vm_rss_kb = int(line.split()[1])
                        elif line.startswith("VmSize:"):
                            vm_size_kb = int(line.split()[1])

                # 2. Parse /proc/[pid]/stat for CPU user/system ticks
                utime = 0
                stime = 0
                with open(stat_path, "r", encoding="utf-8", errors="ignore") as f:
                    stat_content = f.read()
                    # Comm can contain spaces or parens, so find the last ')' to parse remaining fields reliably
                    rparen_idx = stat_content.rfind(")")
                    if rparen_idx != -1:
                        post_fields = stat_content[rparen_idx + 1:].split()
                        # post_fields[0] is state (field 3)
                        # post_fields[1] is ppid (field 4)
                        # utime is field 14 -> index 11 in post_fields
                        # stime is field 15 -> index 12 in post_fields
                        if len(post_fields) >= 13:
                            utime = int(post_fields[11])
                            stime = int(post_fields[12])

                total_ticks = utime + stime
                curr_proc_ticks[pid] = total_ticks

                # Calculate CPU % delta
                cpu_pct = 0.0
                if delta_sys_ticks > 0 and pid in self._prev_proc_ticks:
                    proc_delta = total_ticks - self._prev_proc_ticks[pid]
                    if proc_delta > 0:
                        cpu_pct = (proc_delta / delta_sys_ticks) * 100.0 * self._num_cpus
                        cpu_pct = min(100.0 * self._num_cpus, max(0.0, cpu_pct))

                # 3. Parse /proc/[pid]/cmdline for full argument string
                cmdline = ""
                try:
                    with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_cmd = f.read()
                        cmdline = raw_cmd.replace("\0", " ").strip()
                except Exception:
                    pass

                if not cmdline:
                    cmdline = f"[{name}]"

                user_name = self._resolve_username(uid)
                rss_mb = vm_rss_kb / 1024.0
                vmsize_mb = vm_size_kb / 1024.0

                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "user": user_name,
                    "state": state_code,
                    "cpu_percent": round(cpu_pct, 1),
                    "memory_rss_mb": round(rss_mb, 2),
                    "memory_vmsize_mb": round(vmsize_mb, 2),
                    "threads": threads,
                    "cmdline": cmdline,
                })

            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            except Exception:
                continue

        # Save snapshots for next measurement interval
        self._prev_proc_ticks = curr_proc_ticks
        self._prev_total_ticks = curr_sys_ticks

        # Sort by CPU % desc, then RSS desc, then PID asc
        processes.sort(key=lambda p: (p["cpu_percent"], p["memory_rss_mb"]), reverse=True)
        return processes

    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Gathers comprehensive inspection details and process lineage for a specific PID.
        """
        status_path = f"/proc/{pid}/status"
        stat_path = f"/proc/{pid}/stat"
        cmdline_path = f"/proc/{pid}/cmdline"
        cwd_path = f"/proc/{pid}/cwd"
        exe_path = f"/proc/{pid}/exe"

        if not os.path.exists(status_path):
            return None

        details: Dict[str, Any] = {
            "pid": pid,
            "ppid": 0,
            "name": "",
            "state_code": "S",
            "state_desc": "",
            "user": "",
            "uid": 0,
            "threads": 1,
            "vm_rss_kb": 0,
            "vm_size_kb": 0,
            "vm_data_kb": 0,
            "vm_stk_kb": 0,
            "cmdline": "",
            "cwd": "N/A",
            "exe": "N/A",
            "priority": 0,
            "nice": 0,
            "lineage": [],
            "children": [],
        }

        try:
            with open(status_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("Name:"):
                        details["name"] = line.split(None, 1)[1].strip()
                    elif line.startswith("State:"):
                        state_val = line.split(None, 1)[1].strip()
                        details["state_code"] = state_val.split()[0] if state_val else "S"
                        details["state_desc"] = STATE_DESCRIPTIONS.get(
                            details["state_code"],
                            f"{details['state_code']} ({state_val})"
                        )
                    elif line.startswith("PPid:"):
                        details["ppid"] = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        details["uid"] = int(line.split()[1])
                        details["user"] = self._resolve_username(details["uid"])
                    elif line.startswith("Threads:"):
                        details["threads"] = int(line.split()[1])
                    elif line.startswith("VmRSS:"):
                        details["vm_rss_kb"] = int(line.split()[1])
                    elif line.startswith("VmSize:"):
                        details["vm_size_kb"] = int(line.split()[1])
                    elif line.startswith("VmData:"):
                        details["vm_data_kb"] = int(line.split()[1])
                    elif line.startswith("VmStk:"):
                        details["vm_stk_kb"] = int(line.split()[1])

            # Parse stat for priority & nice
            if os.path.exists(stat_path):
                with open(stat_path, "r", encoding="utf-8", errors="ignore") as f:
                    stat_content = f.read()
                    rparen_idx = stat_content.rfind(")")
                    if rparen_idx != -1:
                        post_fields = stat_content[rparen_idx + 1:].split()
                        # post_fields[15] is priority (field 18)
                        # post_fields[16] is nice (field 19)
                        if len(post_fields) >= 17:
                            details["priority"] = int(post_fields[15])
                            details["nice"] = int(post_fields[16])

            # Cmdline
            if os.path.exists(cmdline_path):
                try:
                    with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                        cmdline = f.read().replace("\0", " ").strip()
                        details["cmdline"] = cmdline or f"[{details['name']}]"
                except Exception:
                    details["cmdline"] = f"[{details['name']}]"

            # Resolve cwd and exe links
            try:
                details["cwd"] = os.readlink(cwd_path)
            except Exception:
                details["cwd"] = "(Restricted / Unreadable)"

            try:
                details["exe"] = os.readlink(exe_path)
            except Exception:
                details["exe"] = "(Kernel Thread / Restricted)"

            # Build Process Lineage (Ancestors)
            ancestors = []
            curr_ppid = details["ppid"]
            visited = {pid}
            while curr_ppid > 0 and curr_ppid not in visited:
                visited.add(curr_ppid)
                parent_status = f"/proc/{curr_ppid}/status"
                if os.path.exists(parent_status):
                    p_name = ""
                    next_ppid = 0
                    try:
                        with open(parent_status, "r", encoding="utf-8", errors="ignore") as pf:
                            for pline in pf:
                                if pline.startswith("Name:"):
                                    p_name = pline.split(None, 1)[1].strip()
                                elif pline.startswith("PPid:"):
                                    next_ppid = int(pline.split()[1])
                        ancestors.append({"pid": curr_ppid, "name": p_name})
                        curr_ppid = next_ppid
                    except Exception:
                        break
                else:
                    break

            # Reverse ancestors so list is Root -> Grandparent -> Parent
            details["lineage"] = list(reversed(ancestors))

            # Find immediate children of this PID
            children = []
            try:
                for entry in os.listdir("/proc"):
                    if entry.isdigit() and int(entry) != pid:
                        child_pid = int(entry)
                        c_status = f"/proc/{child_pid}/status"
                        if os.path.exists(c_status):
                            try:
                                with open(c_status, "r", encoding="utf-8", errors="ignore") as cf:
                                    c_name = ""
                                    c_ppid = -1
                                    for cline in cf:
                                        if cline.startswith("Name:"):
                                            c_name = cline.split(None, 1)[1].strip()
                                        elif cline.startswith("PPid:"):
                                            c_ppid = int(cline.split()[1])
                                    if c_ppid == pid:
                                        children.append({"pid": child_pid, "name": c_name})
                            except Exception:
                                pass
            except Exception:
                pass

            details["children"] = children

        except Exception:
            return None

        return details
