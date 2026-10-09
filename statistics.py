"""
Stage 4: Syscall Classification & Statistics Module
Analyzes structured syscall records produced by parser.py.
Computes:
- Total syscall count
- Category distribution (File I/O / File System, Network, Signal, IPC, Process Control, Memory Management, Other)
- Syscall frequency (most frequent syscalls)
- Successful vs failed calls
"""

from collections import Counter
from typing import List, Dict, Any


def is_failed_syscall(return_value: str) -> bool:
    """
    Determines whether a system call failed based on its return value in strace.

    In Linux/strace:
    - Successful calls return non-negative integers (e.g. 0, 3, 60) or memory addresses (e.g. 0x7f...).
    - Failed calls return -1 accompanied by an errno code (e.g. -1 ENOENT (No such file or directory)).
    - Calls that do not return to userspace (e.g. exit_group) have return value '?'.
    """
    clean_val = return_value.strip()
    return clean_val.startswith("-")


def compute_statistics(records: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Calculates operational statistics from a list of structured syscall records.

    Args:
        records: List of parsed syscall dictionaries from parser.py.

    Returns:
        A dictionary containing:
        - total_count: Total number of parsed syscalls
        - category_counts: Frequency dictionary for each category
        - syscall_frequency: Frequency dictionary for each syscall name (descending)
        - successful_count: Number of successful syscalls
        - failed_count: Number of failed syscalls
    """
    total = len(records)
    category_counter = Counter()
    syscall_counter = Counter()
    failed_count = 0
    successful_count = 0

    for rec in records:
        name = rec.get("name", "unknown")
        category = rec.get("category", "Other")
        ret_val = rec.get("return_value", "")

        category_counter[category] += 1
        syscall_counter[name] += 1

        if is_failed_syscall(ret_val):
            failed_count += 1
        else:
            successful_count += 1

    return {
        "total_count": total,
        "category_counts": dict(category_counter),
        "syscall_frequency": dict(syscall_counter.most_common()),
        "successful_count": successful_count,
        "failed_count": failed_count,
    }


def print_statistics_summary(stats: Dict[str, Any]) -> None:
    """
    Prints a formatted, human-readable summary of the syscall statistics.
    """
    print("-" * 40)
    print("        SYSTEM CALL SUMMARY")
    print("-" * 40)
    print(f"Total syscalls: {stats['total_count']}")
    print("\nCategories:")
    for cat, count in stats["category_counts"].items():
        print(f"  {cat}: {count}")

    print("\nMost frequent syscalls (top 8):")
    freq_items = list(stats["syscall_frequency"].items())[:8]
    for name, count in freq_items:
        print(f"  {name}: {count}")

    print(f"\nSuccessful calls: {stats['successful_count']}")
    print(f"Failed calls:     {stats['failed_count']}")
    print("-" * 40)


if __name__ == "__main__":
    from tracer import trace_command
    from parser import parse_syscall_lines

    print("[*] Running Stage 4 Pipeline: Real Process -> strace -> tracer.py -> parser.py -> statistics.py")
    raw_lines = trace_command("cat sample.txt")
    records = parse_syscall_lines(raw_lines)
    stats = compute_statistics(records)

    print("\n")
    print_statistics_summary(stats)
