"""
Phase 7: About This Syscall Module
Provides detailed documentation, kernel descriptions, purpose explanations,
and underlying Operating System concepts for common Linux system calls.
"""

from typing import Dict, Any

SYSCALL_DATABASE: Dict[str, Dict[str, str]] = {
    "openat": {
        "name": "openat",
        "category": "File I/O / File System",
        "purpose": "Opens or creates a file relative to a directory file descriptor.",
        "description": "Modern Linux system call for opening files securely. Accepts a directory file descriptor (e.g. AT_FDCWD for current directory), file path, and access flags.",
        "concept": "Virtual File System (VFS) & Directory File Descriptors"
    },
    "open": {
        "name": "open",
        "category": "File I/O / File System",
        "purpose": "Opens a file path and returns a new file descriptor.",
        "description": "Legacy system call to open a file. Allocates an entry in the process file descriptor table pointing to the open file description.",
        "concept": "File Descriptors & Process File Tables"
    },
    "read": {
        "name": "read",
        "category": "File I/O / File System",
        "purpose": "Reads bytes from an open file descriptor into a memory buffer.",
        "description": "Transfers data from kernel page cache / device driver into process user-space buffer up to requested count bytes.",
        "concept": "Kernel-to-User Buffer Copy & Page Cache I/O"
    },
    "write": {
        "name": "write",
        "category": "File I/O / File System",
        "purpose": "Writes bytes from a memory buffer to a file descriptor.",
        "description": "Transfers data from process user memory buffer into a file, pipe, socket, or terminal device stdout/stderr.",
        "concept": "I/O Buffering, Device Drivers & Stream Redirection"
    },
    "close": {
        "name": "close",
        "category": "File I/O / File System",
        "purpose": "Closes an open file descriptor.",
        "description": "Releases the file descriptor integer handle back to process table and decrements kernel file reference count.",
        "concept": "Resource Lifetime Management & Descriptor Cleanup"
    },
    "mmap": {
        "name": "mmap",
        "category": "Memory Management",
        "purpose": "Maps files or physical device memory into virtual address space.",
        "description": "Creates new virtual memory pages in process address space. Used for memory-mapped file I/O, shared memory, and large heap allocations.",
        "concept": "Virtual Memory Management, Page Tables & Demand Paging"
    },
    "mmap2": {
        "name": "mmap2",
        "category": "Memory Management",
        "purpose": "Maps files or memory into virtual address space (page offset variant).",
        "description": "Variant of mmap supporting 32-bit offset parameters in units of system page size (4096 bytes).",
        "concept": "Virtual Memory & Page Offsets"
    },
    "munmap": {
        "name": "munmap",
        "category": "Memory Management",
        "purpose": "Unmaps virtual memory pages from process address space.",
        "description": "Deletes virtual page table entries for specified address range and releases physical memory pages back to OS kernel.",
        "concept": "Page Unmapping & Memory Deallocation"
    },
    "brk": {
        "name": "brk",
        "category": "Memory Management",
        "purpose": "Adjusts the process heap break address to allocate/deallocate heap memory.",
        "description": "Sets the end address of the process data segment (break point). Called under the hood by glibc malloc() and free().",
        "concept": "Heap Segment Management & Dynamic Memory Allocation"
    },
    "mprotect": {
        "name": "mprotect",
        "category": "Memory Management",
        "purpose": "Sets access protections (read, write, execute) on memory pages.",
        "description": "Changes permissions for a virtual memory range (e.g. PROT_READ, PROT_WRITE, PROT_EXEC) to enforce security restrictions.",
        "concept": "Memory Protection Flags & W^X Security Policies"
    },
    "execve": {
        "name": "execve",
        "category": "Process Control",
        "purpose": "Executes a new executable binary program.",
        "description": "Overwrites current process address space (code, data, stack, heap) with a fresh executable binary image. Does not return on success.",
        "concept": "Process Program Execution & ELF Loading"
    },
    "execveat": {
        "name": "execveat",
        "category": "Process Control",
        "purpose": "Executes a new executable program relative to a directory file descriptor.",
        "description": "Relative directory variant of execve allowing secure execution without path race conditions.",
        "concept": "Path Execution & File Descriptors"
    },
    "clone": {
        "name": "clone",
        "category": "Process Control",
        "purpose": "Creates a child process or lightweight thread with configurable sharing.",
        "description": "Core Linux primitives underlying fork() and pthread_create(). Allows fine-grained sharing of memory, file descriptors, and signal handlers.",
        "concept": "Multi-threading, Process Creation & Namespace Isolation"
    },
    "clone3": {
        "name": "clone3",
        "category": "Process Control",
        "purpose": "Extensible system call to create threads and child processes.",
        "description": "Modern version of clone system call using structured clone_args struct parameter.",
        "concept": "Extensible Thread & Process Creation"
    },
    "fork": {
        "name": "fork",
        "category": "Process Control",
        "purpose": "Duplicates calling process to create an exact child process.",
        "description": "Creates child process with copy-on-write memory pages and duplicated file descriptor table.",
        "concept": "Process Duplication & Copy-on-Write (COW)"
    },
    "vfork": {
        "name": "vfork",
        "category": "Process Control",
        "purpose": "Creates child process suspending parent until exec or exit.",
        "description": "Lightweight process fork variant where child shares parent memory without copying until execve() is called.",
        "concept": "Efficient Process Execution & Shared Memory"
    },
    "wait4": {
        "name": "wait4",
        "category": "Process Control",
        "purpose": "Waits for child process state changes and collects resource statistics.",
        "description": "Suspends parent execution until a child process exits or stops, returning exit code status and rusage statistics.",
        "concept": "Process State Synchronization & Zombie Process Prevention"
    },
    "exit_group": {
        "name": "exit_group",
        "category": "Process Control",
        "purpose": "Terminates all threads in a process group immediately.",
        "description": "Ends process execution across all worker threads and passes exit status code to parent process.",
        "concept": "Process Group Termination & Cleanup"
    },
    "exit": {
        "name": "exit",
        "category": "Process Control",
        "purpose": "Terminates the calling thread.",
        "description": "Ends execution of calling thread and returns exit status to operating system kernel.",
        "concept": "Thread Termination"
    },
    "pipe": {
        "name": "pipe",
        "category": "IPC",
        "purpose": "Creates a unidirectional inter-process communication pipe.",
        "description": "Allocates two connected file descriptors (read end pipefd[0] and write end pipefd[1]) connected by ring buffer.",
        "concept": "Inter-Process Communication (IPC) & Ring Buffers"
    },
    "pipe2": {
        "name": "pipe2",
        "category": "IPC",
        "purpose": "Creates an IPC pipe with flags like O_CLOEXEC and O_NONBLOCK.",
        "description": "Atomic pipe creation with descriptor flags to avoid inheritance race conditions in multi-threaded programs.",
        "concept": "IPC & Descriptor Atomic Flags"
    },
    "socket": {
        "name": "socket",
        "category": "Network",
        "purpose": "Creates a network communication socket endpoint.",
        "description": "Allocates a network socket handle with domain family (AF_INET, AF_UNIX) and type (SOCK_STREAM, SOCK_DGRAM).",
        "concept": "Socket Abstraction & Protocol Stack"
    },
    "connect": {
        "name": "connect",
        "category": "Network",
        "purpose": "Initiates a network connection on a socket descriptor.",
        "description": "Establishes a connection to target server IP and port (e.g. TCP 3-way handshake).",
        "concept": "Network Connections & Transport Layer Protocols"
    },
    "futex": {
        "name": "futex",
        "category": "Other",
        "purpose": "Fast userspace mutex lock / wait / wake primitive.",
        "description": "Kernel primitive for fast userspace locking. Avoids kernel context switches when mutex is uncontended.",
        "concept": "Thread Synchronization & Futex Primitive Locks"
    },
    "kill": {
        "name": "kill",
        "category": "Signal",
        "purpose": "Sends a signal to a process or process group.",
        "description": "Dispatches an asynchronous signal (SIGINT, SIGKILL, SIGTERM) to target process ID for interruption or termination.",
        "concept": "Asynchronous Signal Delivery & Kernel Signal Handling"
    },
    "stat": {
        "name": "stat",
        "category": "File I/O / File System",
        "purpose": "Retrieves file status and inode metadata by path.",
        "description": "Fills stat structure with file size, permissions, modification timestamp, owner UID/GID, and inode number.",
        "concept": "File Metadata & Inodes"
    },
    "fstat": {
        "name": "fstat",
        "category": "File I/O / File System",
        "purpose": "Retrieves file status and metadata by open file descriptor.",
        "description": "Fills stat metadata buffer using an open file descriptor handle instead of a string path.",
        "concept": "File Descriptor Inode Inspection"
    },
    "newfstatat": {
        "name": "newfstatat",
        "category": "File I/O / File System",
        "purpose": "Retrieves file metadata relative to directory file descriptor.",
        "description": "Standard modern Linux system call for querying file inode metadata relative to dirfd.",
        "concept": "Relative Path File Inode Queries"
    },
    "lseek": {
        "name": "lseek",
        "category": "File I/O / File System",
        "purpose": "Repositions file offset pointer for read/write operations.",
        "description": "Changes byte position offset in open file description (SEEK_SET, SEEK_CUR, SEEK_END).",
        "concept": "File Pointer Position & Sequential/Random Access"
    },
    "access": {
        "name": "access",
        "category": "File I/O / File System",
        "purpose": "Checks process permissions for a file path.",
        "description": "Tests read, write, execute permissions (R_OK, W_OK, X_OK, F_OK) against real user/group IDs.",
        "concept": "File Access Control & Real/Effective UIDs"
    },
    "getcwd": {
        "name": "getcwd",
        "category": "File I/O / File System",
        "purpose": "Gets current working directory path string.",
        "description": "Copies absolute pathname of process current working directory into user memory buffer.",
        "concept": "Process Context & Working Directory"
    },
    "chdir": {
        "name": "chdir",
        "category": "File I/O / File System",
        "purpose": "Changes current working directory of calling process.",
        "description": "Updates current working directory pointer stored in process task_struct.",
        "concept": "Process Context & Directory Traversal"
    },
    "rt_sigaction": {
        "name": "rt_sigaction",
        "category": "Signal",
        "purpose": "Examines or changes signal action handler.",
        "description": "Installs user signal handler routine or changes default disposition for a real-time signal.",
        "concept": "Signal Handlers & Real-Time Signal Handling"
    },
    "rt_sigprocmask": {
        "name": "rt_sigprocmask",
        "category": "Signal",
        "purpose": "Examines or changes blocked signals mask.",
        "description": "Fetches or modifies current process signal mask (SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK).",
        "concept": "Signal Masking & Critical Sections"
    },
}


def get_syscall_info(name: str, category: str = "Other") -> Dict[str, str]:
    """
    Retrieves information dictionary for a system call.
    Provides informative fallback details if syscall is not in database.
    """
    if name in SYSCALL_DATABASE:
        info = dict(SYSCALL_DATABASE[name])
        if category and category != "Other":
            info["category"] = category
        return info

    return {
        "name": name,
        "category": category,
        "purpose": f"Executes Linux kernel service for '{name}'.",
        "description": f"The '{name}' system call transitions from user mode to kernel mode to perform low-level OS operations.",
        "concept": "System Call Interface & Kernel Privilege Traps (INT 0x80 / SYSCALL)"
    }
