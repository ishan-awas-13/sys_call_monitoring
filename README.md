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
                                                              ▼
                                                  Tkinter GUI (gui.py)
                   ┌─────────────────┬───────────────────┬─────────────────┬─────────────────┐
                   ▼                 ▼                   ▼                 ▼                 ▼
             Live Monitor     Live Category      Failure Analysis    Process Tree     Session History
              (with PID)       Bar Chart        (Errno Breakdown)     Hierarchy        & Comparison
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

To run the end-to-end multi-command verification suite testing all 9 phases:

```bash
wsl python3 gui.py --test
```

---

## 📂 Project Structure

| File | Description |
| :--- | :--- |
| `gui.py` | Main application window, tabs, canvas charts, and event coordination. |
| `tracer.py` | Subprocess controller managing `strace [-f]` execution and process group cleanup. |
| `parser.py` | High-performance regex parser extracting PIDs, syscall names, arguments, and return values. |
| `detail_parser.py` | Parameter extractor resolving paths, flags, file descriptors, and byte counts. |
| `process_tree.py` | Process hierarchy tracker mapping parent-child relationships and process lifecycles. |
| `statistics.py` | Computes totals, category distributions, failure metrics, and syscall frequencies. |
| `failure_analysis.py` | Errno parser and plain-English error dictionary. |
| `syscall_info.py` | Documentation database for system calls, kernel workflows, and OS concepts. |
| `sample.txt` | Sample text file used for default file I/O tracing demonstrations. |
