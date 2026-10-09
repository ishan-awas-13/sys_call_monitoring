"""
Phase 5: Syscall Argument & Detail Parser
Extracts structured, human-readable key details from raw syscall arguments
and return values for common Linux system calls.
"""

import re
from typing import List, Tuple, Optional


def split_arguments(args: str) -> List[str]:
    """
    Safely splits a C-style syscall argument string by comma, respecting:
    - Quoted strings (including escaped quotes: \")
    - Curly braces ({...})
    - Square brackets ([...])
    - Parentheses ((...))
    """
    tokens = []
    current = []
    in_quote = False
    escape = False
    brace_depth = 0
    bracket_depth = 0
    paren_depth = 0

    for ch in args:
        if escape:
            current.append(ch)
            escape = False
            continue

        if ch == '\\' and in_quote:
            current.append(ch)
            escape = True
            continue

        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue

        if not in_quote:
            if ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth = max(0, brace_depth - 1)
            elif ch == '[':
                bracket_depth += 1
            elif ch == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == '(':
                paren_depth += 1
            elif ch == ')':
                paren_depth = max(0, paren_depth - 1)
            elif ch == ',' and brace_depth == 0 and bracket_depth == 0 and paren_depth == 0:
                token = "".join(current).strip()
                tokens.append(token)
                current = []
                continue

        current.append(ch)

    if current:
        tokens.append("".join(current).strip())

    return tokens


def parse_return_details(return_value: str) -> Tuple[bool, str, str, str]:
    """
    Analyzes an strace return value.

    Returns:
        (is_success, clean_val_or_errno_code, strace_description, full_text)
    """
    ret = return_value.strip()
    if ret.startswith("-"):
        # Match pattern: e.g. -1 ENOENT (No such file or directory)
        # or -1 EACCES
        m = re.match(r'^-\d+\s+([A-Z0-9_]+)(?:\s+\((.*?)\))?', ret)
        if m:
            errno_code = m.group(1)
            strace_desc = m.group(2) if m.group(2) else ""
            return False, errno_code, strace_desc, ret
        else:
            # Check for pattern without explicit errno code, e.g. -1 (No such file)
            m2 = re.match(r'^-\d+(?:\s+\((.*?)\))?', ret)
            if m2 and m2.group(1):
                return False, "-1", m2.group(1), ret
            return False, ret, "", ret
    elif ret == "?":
        return True, "?", "", ret
    else:
        # Success: e.g. 0, 3, 60, 0x7f...
        return True, ret, "", ret


def parse_return_value(return_value: str) -> Tuple[bool, str, str]:
    """
    Analyzes an strace return value.

    Returns:
        (is_success, clean_val_or_error_code, full_text)
    """
    is_success, err_code, _, full_text = parse_return_details(return_value)
    return is_success, err_code, full_text


def clean_path(token: str) -> str:
    """Strips outer quotes from file or directory paths."""
    t = token.strip()
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        return t[1:-1]
    return t


def extract_key_details(name: str, args: str, return_value: str) -> str:
    """
    Extracts structured, readable key details for common syscalls.
    Returns an empty string if the call is not supported or arguments cannot be parsed.
    """
    if not args:
        return ""

    tokens = split_arguments(args)
    is_success, val_code, _ = parse_return_value(return_value)

    try:
        # -------------------------------------------------------------
        # 1. openat(dirfd, pathname, flags[, mode])
        # -------------------------------------------------------------
        if name == "openat":
            if len(tokens) >= 2:
                dirfd = tokens[0]
                path = clean_path(tokens[1])
                flags = tokens[2] if len(tokens) >= 3 else ""

                parts = []
                if dirfd != "AT_FDCWD":
                    parts.append(f"dirfd={dirfd}")
                parts.append(f'path="{path}"')
                if flags:
                    parts.append(f"flags={flags}")

                if is_success:
                    parts.append(f"fd={val_code}")
                else:
                    parts.append(f"failed ({val_code})")
                return ", ".join(parts)

        # -------------------------------------------------------------
        # 2. open(pathname, flags[, mode])
        # -------------------------------------------------------------
        elif name == "open":
            if len(tokens) >= 1:
                path = clean_path(tokens[0])
                flags = tokens[1] if len(tokens) >= 2 else ""

                parts = [f'path="{path}"']
                if flags:
                    parts.append(f"flags={flags}")

                if is_success:
                    parts.append(f"fd={val_code}")
                else:
                    parts.append(f"failed ({val_code})")
                return ", ".join(parts)

        # -------------------------------------------------------------
        # 3. read(fd, buf, count)
        # -------------------------------------------------------------
        elif name in ("read", "pread64"):
            if len(tokens) >= 3:
                fd = tokens[0]
                count = tokens[2]
                parts = [f"fd={fd}", f"req={count}B"]
                if is_success:
                    if val_code == "0":
                        parts.append("read=0B (EOF)")
                    else:
                        parts.append(f"read={val_code}B")
                else:
                    parts.append(f"failed ({val_code})")
                return ", ".join(parts)

        # -------------------------------------------------------------
        # 4. write(fd, buf, count)
        # -------------------------------------------------------------
        elif name in ("write", "pwrite64"):
            if len(tokens) >= 3:
                fd = tokens[0]
                count = tokens[2]
                parts = [f"fd={fd}", f"req={count}B"]
                if is_success:
                    parts.append(f"written={val_code}B")
                else:
                    parts.append(f"failed ({val_code})")
                return ", ".join(parts)

        # -------------------------------------------------------------
        # 5. close(fd)
        # -------------------------------------------------------------
        elif name == "close":
            if len(tokens) >= 1:
                fd = tokens[0]
                status = "success" if is_success else f"failed ({val_code})"
                return f"fd={fd}, {status}"

        # -------------------------------------------------------------
        # 6. mmap(addr, length, prot, flags, fd, offset)
        # -------------------------------------------------------------
        elif name in ("mmap", "mmap2"):
            if len(tokens) >= 3:
                length = tokens[1]
                prot = tokens[2]
                if is_success:
                    return f"len={length}B, prot={prot}, addr={val_code}"
                else:
                    return f"len={length}B, prot={prot}, failed ({val_code})"

        # -------------------------------------------------------------
        # 7. munmap(addr, length)
        # -------------------------------------------------------------
        elif name == "munmap":
            if len(tokens) >= 2:
                addr = tokens[0]
                length = tokens[1]
                status = "success" if is_success else f"failed ({val_code})"
                return f"addr={addr}, len={length}B, {status}"

        # -------------------------------------------------------------
        # 8. execve(filename, argv, envp)
        # -------------------------------------------------------------
        elif name in ("execve", "execveat"):
            if len(tokens) >= 1:
                path = clean_path(tokens[0])
                status = "success" if is_success else f"failed ({val_code})"
                return f'path="{path}", {status}'

        # -------------------------------------------------------------
        # 9. socket(domain, type, protocol)
        # -------------------------------------------------------------
        elif name == "socket":
            if len(tokens) >= 2:
                dom = tokens[0]
                stype = tokens[1]
                if is_success:
                    return f"domain={dom}, type={stype}, fd={val_code}"
                else:
                    return f"domain={dom}, type={stype}, failed ({val_code})"

        # -------------------------------------------------------------
        # 10. connect(sockfd, addr, addrlen)
        # -------------------------------------------------------------
        elif name == "connect":
            if len(tokens) >= 1:
                fd = tokens[0]
                status = "success" if is_success else f"failed ({val_code})"
                return f"fd={fd}, {status}"

        # -------------------------------------------------------------
        # 11. pipe / pipe2
        # -------------------------------------------------------------
        elif name in ("pipe", "pipe2"):
            if len(tokens) >= 1:
                status = f"fds={tokens[0]}" if is_success else f"failed ({val_code})"
                return status

        # -------------------------------------------------------------
        # 12. dup / dup2 / dup3
        # -------------------------------------------------------------
        elif name in ("dup", "dup2", "dup3"):
            if len(tokens) >= 1:
                oldfd = tokens[0]
                if name == "dup":
                    return f"oldfd={oldfd}, newfd={val_code}" if is_success else f"oldfd={oldfd}, failed ({val_code})"
                elif len(tokens) >= 2:
                    newfd = tokens[1]
                    status = "success" if is_success else f"failed ({val_code})"
                    return f"oldfd={oldfd}, newfd={newfd}, {status}"

    except Exception:
        # Never crash the application on unfamiliar or truncated arguments
        return ""

    return ""


if __name__ == "__main__":
    test_cases = [
        ("openat", 'AT_FDCWD, "sample.txt", O_RDONLY', "3"),
        ("openat", 'AT_FDCWD, "/invalid/path.txt", O_RDONLY|O_CLOEXEC', "-1 ENOENT (No such file or directory)"),
        ("open", '"file.txt", O_WRONLY|O_CREAT', "4"),
        ("read", '3, "Hello, world! Some, commas, here", 131072', "60"),
        ("read", '3, "", 131072', "0"),
        ("read", '4, 0x7ffd, 8192', "-1 EAGAIN (Resource temporarily unavailable)"),
        ("write", '1, "hello\\n", 6', "6"),
        ("write", '1, "err", 100', "-1 EPIPE (Broken pipe)"),
        ("close", '3', "0"),
        ("close", '99', "-1 EBADF (Bad file descriptor)"),
        ("mmap", 'NULL, 139264, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0', "0x7e8b16e6e000"),
        ("munmap", '0x7e8b16e6e000, 139264', "0"),
        ("execve", '"/usr/bin/cat", ["cat", "sample.txt"], 0x7ffd', "0"),
        ("socket", 'AF_INET, SOCK_STREAM, IPPROTO_IP', "3"),
        ("connect", '3, {sa_family=AF_INET}, 16', "0"),
    ]

    print("Running detail_parser test suite...")
    for sc, args, ret in test_cases:
        det = extract_key_details(sc, args, ret)
        print(f"[{sc}] -> {det}")
