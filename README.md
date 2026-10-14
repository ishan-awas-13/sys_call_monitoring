# OScope — Linux System Call Monitoring & Inspection Tool

**OScope** is an interactive, real-time Linux Operating Systems observability tool built with **Python 3**, **Tkinter**, and native Linux **`strace`**. It captures, parses, categorizes, and visualizes live system calls executed by real Linux processes running in native Linux or Windows Subsystem for Linux (WSL2).

---

## 🎯 Features & Architectural Highlights

### 1. Real-Time Syscall Trace Table
- Captures live kernel transitions and displays them in a high-throughput, virtualized table.
- Columns: `#`, `PID`, `Syscall Name`, `Category`, `Key Details`, `Arguments`, and `Return Value`.
- Free-text search and category-specific filtering with instant table updates.

### 2. Dedicated Raw `strace` Terminal
- Launches an independent, dark-themed monospace terminal window (`Toplevel`) for every session.
- Displays raw, unparsed `strace` stream lines with real-time autoscroll.

### 3. Expanded 7-Category OS Classification
Categorizes system calls according to Operating System fundamentals:
- **File I/O / File System** (`openat`, `read`, `write`, `close`, `stat`, `lseek`, ...)
- **Network** (`socket`, `connect`, `bind`, `listen`, `accept4`, `sendto`, `recvfrom`, ...)
- **Signal** (`rt_sigaction`, `rt_sigprocmask`, `kill`, `tgkill`, ...)
- **IPC** (`pipe`, `pipe2`, `shmget`, `semget`, `msgget`, ...)
- **Process Control** (`clone`, `clone3`, `fork`, `vfork`, `execve`, `wait4`, `exit_group`, ...)
- **Memory Management** (`mmap`, `munmap`, `mprotect`, `brk`, `madvise`, ...)
- **Other** (Fallback for specialized or unmapped calls)

### 4. Structured Syscall Details Extraction
- Extracts high-value parameters into a readable **Key Details** column:
  - `openat` / `open`: resolved file path, file flags (`O_RDONLY`, `O_CLOEXEC`), returned file descriptor (`fd=3`).
  - `read` / `write`: target file descriptor, requested byte buffer, actual bytes read/written.
  - `close`: descriptor number and status.

### 5. Live Category Distribution Chart
- Dynamic Tkinter Canvas bar chart displaying live category distribution, percentage breakdowns, gridlines, and animated metric indicators.

### 6. Dedicated Failure Analysis Tab
- Isolates system calls returning negative error codes accompanied by kernel errno annotations.
- Displays errno codes (`ENOENT`, `EACCES`, `EPERM`, `EBADF`, `ENOMEM`, etc.) alongside plain-English explanations.

### 7. Interactive Syscall Documentation ("About This Syscall")
- Clicking any syscall in the trace table reveals its Unix manual purpose, kernel execution path, and related Operating System concept (e.g., *Virtual File System*, *Virtual Memory*, *Inter-Process Communication*).

### 8. Process Tree & Child Process Tracing (`strace -f`)
- Toggle **Trace Child Processes (-f)** to trace child processes spawned via `fork`, `vfork`, `clone`, or `clone3`.
- Interactive **Process Tree** tab presents the true parent-child execution hierarchy with per-process syscall counters, command names, and status (`Running`, `Exited`).
- Includes a 1-click **Filter Live Trace by this PID** feature.

### 9. In-Memory Command History
- Retains the last 10 distinct executed commands in memory.
- Avoids consecutive duplicate entries and allows instant selection via dropdown without auto-starting.

### 10. Session History & Side-by-Side Comparison
- Persists completed monitoring sessions in memory.
- Compare any two sessions side-by-side with numerical diffs (`+`/`-`) and top 10 syscall frequency breakdowns.

### 11. Report Export
- Export complete session records and statistical summaries to **CSV** or human-readable **TXT** reports via native file-save dialogs.

### 12. Working Directory Selection (CWD Selector)
- Execute monitored commands in any directory on your system.
- Includes a **📁 Select Directory...** dialog, manual path entry with automatic Windows-to-WSL path translation (`C:\...` -> `/mnt/c/...`), and a **Default** reset button.
- The execution working directory is tracked in session history, side-by-side session comparisons, and exported reports.

### 13. Live Process & Resource Dashboard (Linux `/proc` Engine)
- Dedicated **Processes & Resources** tab providing a macroscopic view of all active processes running in the Linux operating system.
- Zero external package dependencies: directly reads and parses the Linux Virtual File System (`/proc/stat`, `/proc/[pid]/status`, `/proc/[pid]/stat`, `/proc/[pid]/cmdline`).
- Live metrics: **PID**, **PPID**, **Binary Name**, **Owner User**, **Process State** (`R`, `S`, `D`, `Z`, `T`), **CPU Utilization %**, **Physical RAM (RSS)**, **Virtual Memory (VmSize)**, **Thread Count**, and **Full Command Line**.
- Configurable periodic auto-refresh (1s, 2s, 5s) plus manual **⟲ Refresh Now**.
- Instant search filter and state filter (`All States`, `Running`, `Sleeping`, `Stopped`, `Zombie`), with an optional **Hide Kernel Threads** toggle.
- Interactive column sorting: click any header (CPU %, Memory, PID, etc.) to sort ascending or descending.

### 14. OS Architecture Distinction: Resource Metrics vs. Syscall Statistics
OScope explicitly contrasts two foundational paradigms in operating system observability:
- **Process Resource Metrics** (*Sampling-Based / Macroscopic*): Periodic snapshots of OS kernel scheduler and memory manager structures (`task_struct`, `mm_struct`). Measures macroscopic state (CPU %, physical RSS in RAM, virtual address space, run-queue states).
- **System Call Statistics** (*Event-Driven / Microscopic*): Continuous, deterministic trace via kernel `ptrace`. Measures microscopic events across the user-space to kernel-space boundary (syscall frequencies, argument payloads, file descriptors, errno codes).

### 15. Direct Attach & Trace Syscalls (`strace -p <PID>`)
- Select any active process in the dashboard and click **"🔍 Attach & Trace Syscalls (PID: X)"** or double-click the row.
- OScope automatically jumps to the **Live Monitor** tab and initiates tracing on the running process.
- **Clean Detachment**: When monitoring is stopped, OScope sends `SIGINT` to `strace`, detaching cleanly without terminating the monitored process.
- **Linux Security (Yama LSM) Diagnostics**: Provides clear, plain-English guidance if Linux Yama restricts attaching across unprivileged boundaries (`kernel.yama.ptrace_scope = 1`).

---

## 🏗️ Project Architecture

```text
                                 REAL Linux Process Group
                                            │
                                     strace [-f]
                                            │
                                        tracer.py
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
                RawOutputWindow                         parser.py
           (Dedicated Toplevel window)                        │
                                                              ▼
                                                   process_tree.py & statistics.py
                                                              │
               Linux /proc Virtual FS                         ▼
                         │                        Tkinter GUI (gui.py)
                         ▼             ┌──────────────────────┼──────────────────────┐
                process_dashboard.py   ▼                      ▼                      ▼
                         │        Live Monitor      Processes & Resources     Live Category
                         └───────► (with PID)       (Procfs & CPU/RAM)          Bar Chart
                                       │                      │                      │
                                       ▼                      ▼                      ▼
                                Failure Analysis        Process Tree          Session History
                                (Errno Breakdown)         Hierarchy             & Comparison
```

---

## 🚀 Getting Started

### Prerequisites

OScope requires a Linux environment (Native Linux or Windows Subsystem for Linux / WSL2) with `strace` and Python Tkinter installed:

```bash
sudo apt update
sudo apt install -y strace python3-tk python3
```

### Running OScope

Clone the repository and launch the application:

```bash
# If running inside Linux or WSL terminal:
python3 gui.py

# If running from Windows PowerShell via WSL:
wsl python3 gui.py
```

### Running the Automated Verification Suite

To run the end-to-end multi-command verification suite testing all phases, working directory execution, process dashboard inspection, and attach-to-PID flows:

```bash
wsl python3 gui.py --test
```

---

## 📂 Project Structure

| File | Description |
| :--- | :--- |
| `gui.py` | Main application window, tabbed notebook, canvas charts, process table, and event coordination. |
| `process_dashboard.py` | Linux `/proc` Virtual File System collector, CPU/memory metric engine, and process lineage inspector. |
| `tracer.py` | Subprocess controller managing `strace [-f] [-p PID]` execution, attach/detach handling, and process group cleanup. |
| `parser.py` | High-performance regex parser extracting PIDs, syscall names, arguments, and return values. |
| `detail_parser.py` | Parameter extractor resolving paths, flags, file descriptors, and byte counts. |
| `process_tree.py` | Process hierarchy tracker mapping parent-child relationships and process lifecycles. |
| `statistics.py` | Computes totals, category distributions, failure metrics, and syscall frequencies. |
| `failure_analysis.py` | Errno parser and plain-English error dictionary. |
| `syscall_info.py` | Documentation database for system calls, kernel workflows, and OS concepts. |
| `sample.txt` | Sample text file used for default file I/O tracing demonstrations. |
