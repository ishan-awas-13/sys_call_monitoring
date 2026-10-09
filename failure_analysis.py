"""
Phase 6: Failure Analysis Module
Extracts, categorizes, and explains failed Linux system calls with plain-English
explanations for common errno codes.
"""

from typing import Dict, List, Tuple, Any
from statistics import is_failed_syscall
from detail_parser import parse_return_details, parse_return_value

# Plain-English explanations for Linux errno codes
ERRNO_DESCRIPTIONS: Dict[str, str] = {
    "ENOENT": "No such file or directory (path does not exist or invalid symlink).",
    "EACCES": "Permission denied (insufficient file or directory access permissions).",
    "EPERM": "Operation not permitted (requires root superuser or capability privileges).",
    "EBADF": "Bad file descriptor (invalid, closed, or unopened file handle).",
    "ENOMEM": "Out of memory (kernel or process memory allocation limit reached).",
    "EEXIST": "File exists (attempted to create a file/directory that already exists).",
    "EINVAL": "Invalid argument (invalid parameter or out-of-range flag passed to kernel).",
    "ENOTDIR": "Not a directory (a path prefix component is not a directory).",
    "ECONNREFUSED": "Connection refused (target network port or host is not listening).",
    "ECONNRESET": "Connection reset by peer (connection closed unexpectedly by remote host).",
    "EAGAIN": "Resource temporarily unavailable (try again later / non-blocking socket mode).",
    "EWOULDBLOCK": "Operation would block (non-blocking I/O mode).",
    "EPIPE": "Broken pipe (writing to a pipe or socket with no active reader).",
    "ECHILD": "No child processes (wait() called with no child processes).",
    "EISDIR": "Is a directory (attempted file operation on a directory path).",
    "ENOSPC": "No space left on device (storage disk partition is full).",
    "ETIMEDOUT": "Connection timed out (network route or server response timed out).",
    "ESRCH": "No such process (target process ID or thread ID does not exist).",
    "EINTR": "Interrupted system call (operation interrupted by an asynchronous signal).",
    "EFBIG": "File too large (exceeded process file size limit).",
    "EROFS": "Read-only file system (write operation attempted on read-only mount).",
    "ENOTTY": "Inappropriate ioctl for device (terminal control operation attempted on non-tty descriptor)."
}


def explain_errno(errno_code: str) -> str:
    """
    Returns a plain-English explanation for an errno code string.
    Provides a clean fallback for unknown codes.
    """
    clean_code = errno_code.strip().upper()
    if clean_code in ERRNO_DESCRIPTIONS:
        return ERRNO_DESCRIPTIONS[clean_code]
    return f"System error code ({clean_code}). Refer to Linux errno man pages."


def analyze_record_failure(record: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Determines if a record represents a genuine syscall failure,
    extracting the errno code and plain-English explanation directly from strace output.

    Returns:
        (is_failed, errno_code, explanation)
    """
    ret_val = record.get("return_value", "")
    if not is_failed_syscall(ret_val):
        return False, "", ""

    is_success, errno_code, strace_desc, full_text = parse_return_details(ret_val)
    if is_success:
        return False, "", ""

    clean_code = errno_code.strip().upper()
    if clean_code in ERRNO_DESCRIPTIONS:
        explanation = ERRNO_DESCRIPTIONS[clean_code]
    elif strace_desc:
        explanation = strace_desc
    elif clean_code and clean_code != ret_val.strip():
        explanation = f"System error code ({clean_code})."
    else:
        # Preserve raw record without inventing an errno or false explanation
        explanation = f"System call failed with return value ({ret_val})."

    return True, errno_code, explanation


def compute_failure_analysis(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes a list of syscall records and compiles failure metrics and error records.
    """
    total_calls = len(records)
    failed_records = []
    errno_counts: Dict[str, int] = {}

    for idx, rec in enumerate(records, start=1):
        is_failed, errno_code, explanation = analyze_record_failure(rec)
        if is_failed:
            failed_entry = dict(rec)
            failed_entry["seq_num"] = idx
            failed_entry["errno_code"] = errno_code
            failed_entry["explanation"] = explanation
            failed_records.append(failed_entry)
            errno_counts[errno_code] = errno_counts.get(errno_code, 0) + 1

    total_failures = len(failed_records)
    failure_rate = (total_failures / total_calls * 100) if total_calls > 0 else 0.0

    return {
        "total_calls": total_calls,
        "total_failures": total_failures,
        "failure_rate": failure_rate,
        "errno_counts": errno_counts,
        "failed_records": failed_records
    }


if __name__ == "__main__":
    print("[*] Testing failure_analysis.py module...")

    # 1. Successful records (0, 3, pointer address, ?)
    rec_succ1 = {"name": "openat", "arguments": 'AT_FDCWD, "file.txt", O_RDONLY', "return_value": "3"}
    rec_succ2 = {"name": "mmap", "arguments": 'NULL, 4096, PROT_READ', "return_value": "0x7ff89a00"}
    rec_succ3 = {"name": "exit_group", "arguments": '0', "return_value": "?"}
    
    # 2. Call with -1 in arguments but positive return value
    rec_succ_args = {"name": "lseek", "arguments": '3, -1, SEEK_END', "return_value": "120"}
    rec_succ_text = {"name": "write", "arguments": '1, "Error ENOENT occurred", 20', "return_value": "20"}

    # 3. Genuine failure records with strace annotations
    rec_fail1 = {"name": "openat", "arguments": 'AT_FDCWD, "missing.txt", O_RDONLY', "return_value": "-1 ENOENT (No such file or directory)"}
    rec_fail2 = {"name": "openat", "arguments": 'AT_FDCWD, "/root/secret", O_RDONLY', "return_value": "-1 EACCES (Permission denied)"}
    rec_fail3 = {"name": "ioctl", "arguments": '4, TCGETS, 0x1234', "return_value": "-1 ENOTTY (Inappropriate ioctl for device)"}
    
    # 4. Incomplete/ambiguous negative return value
    rec_fail_unannotated = {"name": "custom_call", "arguments": '1, 2', "return_value": "-1"}

    records = [
        rec_succ1, rec_succ2, rec_succ3, rec_succ_args, rec_succ_text,
        rec_fail1, rec_fail2, rec_fail3, rec_fail_unannotated
    ]

    analysis = compute_failure_analysis(records)
    
    assert analysis["total_calls"] == 9, f"Expected 9 total calls, got {analysis['total_calls']}"
    assert analysis["total_failures"] == 4, f"Expected 4 failures, got {analysis['total_failures']}"
    
    # Check specific failure extractions
    failed_recs = analysis["failed_records"]
    assert failed_recs[0]["errno_code"] == "ENOENT"
    assert "No such file or directory" in failed_recs[0]["explanation"]
    
    assert failed_recs[1]["errno_code"] == "EACCES"
    assert "Permission denied" in failed_recs[1]["explanation"]

    assert failed_recs[2]["errno_code"] == "ENOTTY"
    assert "Inappropriate ioctl for device" in failed_recs[2]["explanation"]

    assert failed_recs[3]["errno_code"] == "-1"
    assert "System call failed with return value (-1)" in failed_recs[3]["explanation"]

    print("[✓] All failure_analysis unit tests passed successfully!")
