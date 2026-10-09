"""
Stage 3: Syscall Parser
Parses raw strace output lines into structured Python dictionaries.
Extracts: syscall name, category, arguments, and return value.
"""

import re
from typing import Optional, Dict, List

from detail_parser import extract_key_details

# Phase 4: Expanded System Call Classification Mapping
ALL_CATEGORIES = [
    "File I/O / File System",
    "Network",
    "Signal",
    "IPC",
    "Process Control",
    "Memory Management",
    "Other"
]

SYSCALL_CATEGORIES = {
    # File I/O / File System
    "open": "File I/O / File System",
    "openat": "File I/O / File System",
    "read": "File I/O / File System",
    "write": "File I/O / File System",
    "pread64": "File I/O / File System",
    "pwrite64": "File I/O / File System",
    "close": "File I/O / File System",
    "stat": "File I/O / File System",
    "fstat": "File I/O / File System",
    "lstat": "File I/O / File System",
    "newfstatat": "File I/O / File System",
    "lseek": "File I/O / File System",
    "readlink": "File I/O / File System",
    "readlinkat": "File I/O / File System",
    "access": "File I/O / File System",
    "faccessat": "File I/O / File System",
    "mkdir": "File I/O / File System",
    "mkdirat": "File I/O / File System",
    "rmdir": "File I/O / File System",
    "unlink": "File I/O / File System",
    "unlinkat": "File I/O / File System",
    "rename": "File I/O / File System",
    "renameat": "File I/O / File System",
    "chmod": "File I/O / File System",
    "fchmod": "File I/O / File System",
    "chdir": "File I/O / File System",
    "getcwd": "File I/O / File System",

    # Network
    "socket": "Network",
    "connect": "Network",
    "bind": "Network",
    "listen": "Network",
    "accept": "Network",
    "accept4": "Network",
    "sendto": "Network",
    "recvfrom": "Network",
    "sendmsg": "Network",
    "recvmsg": "Network",
    "shutdown": "Network",
    "getsockname": "Network",
    "getpeername": "Network",

    # Signal
    "rt_sigaction": "Signal",
    "rt_sigprocmask": "Signal",
    "rt_sigreturn": "Signal",
    "kill": "Signal",
    "tgkill": "Signal",

    # IPC
    "pipe": "IPC",
    "pipe2": "IPC",
    "dup": "IPC",
    "dup2": "IPC",
    "dup3": "IPC",
    "shmget": "IPC",
    "shmat": "IPC",
    "shmdt": "IPC",
    "semget": "IPC",
    "semop": "IPC",

    # Process Control
    "clone": "Process Control",
    "clone3": "Process Control",
    "fork": "Process Control",
    "vfork": "Process Control",
    "execve": "Process Control",
    "execveat": "Process Control",
    "wait4": "Process Control",
    "waitid": "Process Control",
    "exit": "Process Control",
    "exit_group": "Process Control",

    # Memory Management
    "mmap": "Memory Management",
    "mmap2": "Memory Management",
    "munmap": "Memory Management",
    "mremap": "Memory Management",
    "brk": "Memory Management",
    "mprotect": "Memory Management",
    "madvise": "Memory Management",
    "mlock": "Memory Management",
    "munlock": "Memory Management",
}

# Regular expression patterns to parse realistic strace output lines.
# Handles optional [pid 1234] prefix, normal syscalls, and resumed syscalls.
PID_PREFIX_PATTERN = re.compile(r'^\[pid\s+(\d+)\]\s+(.*)$')
RESUMED_PATTERN = re.compile(r'^<\.\.\.\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+resumed>(.*)\)\s*=\s*(.+)$')
SYSCALL_PATTERN = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)\s*=\s*(.+)$')


def classify_syscall(name: str) -> str:
    """
    Classifies a system call name into an OS category.
    Defaults to 'Other' if not present in the initial category mapping.
    """
    return SYSCALL_CATEGORIES.get(name, "Other")


def parse_syscall_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parses a single raw line of strace output into a structured dictionary.
    Extracts PID, syscall name, category, arguments, return value, and key details.

    Returns:
        A dictionary with keys 'pid', 'name', 'category', 'arguments', 'return_value', 'key_details'
        if successfully parsed, or None if the line is not a syscall (e.g. exit message, signal).
    """
    clean_line = line.strip()

    # Gracefully ignore empty lines and strace markers like +++ exited with 0 +++ or signals --- SIG... ---
    if not clean_line or clean_line.startswith(("+++", "---")):
        return None

    pid_str = "Main"
    pid_match = PID_PREFIX_PATTERN.match(clean_line)
    if pid_match:
        pid_str = pid_match.group(1)
        clean_line = pid_match.group(2).strip()

    # Check for resumed calls: e.g. <... wait4 resumed>[{WIFEXITED(s)}], 0, NULL) = 768
    resumed_match = RESUMED_PATTERN.match(clean_line)
    if resumed_match:
        name = resumed_match.group(1)
        raw_args = resumed_match.group(2).strip().lstrip("([")
        ret_val = resumed_match.group(3).strip()
    else:
        match = SYSCALL_PATTERN.match(clean_line)
        if not match:
            return None
        name = match.group(1)
        raw_args = match.group(2).strip()
        ret_val = match.group(3).strip()

    category = classify_syscall(name)
    key_details = extract_key_details(name, raw_args, ret_val)

    return {
        "pid": pid_str,
        "name": name,
        "category": category,
        "arguments": raw_args,
        "return_value": ret_val,
        "key_details": key_details
    }


def parse_syscall_lines(lines: List[str]) -> List[Dict[str, str]]:
    """
    Parses a sequence of raw strace output lines into a list of structured dictionaries.
    Lines that cannot be parsed are safely skipped without crashing.
    """
    parsed_records = []
    for line in lines:
        record = parse_syscall_line(line)
        if record is not None:
            parsed_records.append(record)
    return parsed_records


if __name__ == "__main__":
    # Integration test with real Stage 2 tracer
    from tracer import trace_command

    print("[*] Running Stage 3 Integration Test: Real Process -> strace -> tracer.py -> parser.py")
    raw_lines = trace_command("cat sample.txt")

    print("\n" + "=" * 60)
    print(f"[*] Parsing {len(raw_lines)} raw strace lines...")
    parsed = parse_syscall_lines(raw_lines)
    print(f"[*] Successfully parsed {len(parsed)} structured syscall records.\n" + "=" * 60)

    # Display examples for requested target syscalls: openat, read, write, close, mmap, exit_group
    targets = ["openat", "read", "write", "close", "mmap", "exit_group"]
    shown = set()

    print("\n[*] Demonstrating specific real parsed syscalls:\n")
    for record in parsed:
        name = record["name"]
        if name in targets and name not in shown:
            print("Parsed syscall:")
            print(f"  Name:         {record['name']}")
            print(f"  Category:     {record['category']}")
            print(f"  Key Details:  {record.get('key_details', '')}")
            print(f"  Arguments:    {record['arguments']}")
            print(f"  Return value: {record['return_value']}")
            print("-" * 40)
            shown.add(name)
            if len(shown) == len(targets):
                break
