"""
Phase 8: Process Tree & Hierarchy Tracker
Tracks process hierarchy, parent-child relationships, PID mapping,
command names, and status for monitored processes and their children.
"""

import re
from typing import Dict, List, Optional, Any


class ProcessNode:
    """Represents a monitored process or child process in the execution tree."""
    def __init__(self, pid: str, ppid: Optional[str] = None, command: str = ""):
        self.pid = str(pid)
        self.ppid = str(ppid) if ppid is not None else None
        self.command = command or "unknown"
        self.status = "Running"
        self.syscall_count = 0
        self.children: List[str] = []  # PIDs of child processes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid or "N/A",
            "command": self.command,
            "status": self.status,
            "syscall_count": self.syscall_count,
            "children": list(self.children)
        }


class ProcessTreeTracker:
    """
    Maintains parent-child process relationships and per-process metrics
    during a system call monitoring session.
    """
    def __init__(self, root_command: str = ""):
        self.root_command = root_command
        self.root_pid: Optional[str] = None
        self.nodes: Dict[str, ProcessNode] = {}

        if root_command:
            # Seed root process
            self.ensure_process("Main", ppid=None, command=self._clean_cmd_name(root_command))

    def _clean_cmd_name(self, raw_cmd: str) -> str:
        """Extracts executable base name from command string."""
        if not raw_cmd:
            return "unknown"
        parts = raw_cmd.strip().split()
        if not parts:
            return raw_cmd
        base = parts[0].split("/")[-1]
        if len(parts) > 1 and base in ("python", "python3", "sh", "bash"):
            # Provide descriptive command name, e.g. "python3 (script)" or "sh (-c echo)"
            return f"{base} {' '.join(parts[1:3])}"
        return base

    def reset(self, root_command: str = ""):
        """Resets tracker state for a new monitoring session."""
        self.root_command = root_command
        self.root_pid = None
        self.nodes.clear()
        if root_command:
            self.ensure_process("Main", ppid=None, command=self._clean_cmd_name(root_command))

    def ensure_process(self, pid: str, ppid: Optional[str] = None, command: str = "") -> ProcessNode:
        """Retrieves or creates a process node, recording parent-child linkage if available."""
        pid = str(pid)
        if pid == "Main" and self.root_pid and self.root_pid != "Main":
            pid = self.root_pid
        if ppid is not None:
            ppid = str(ppid)

        if pid not in self.nodes:
            if self.root_pid is None:
                self.root_pid = pid
                if not command and self.root_command:
                    command = self._clean_cmd_name(self.root_command)

            node = ProcessNode(pid, ppid=ppid, command=command)
            self.nodes[pid] = node

            if ppid and ppid in self.nodes:
                if pid not in self.nodes[ppid].children:
                    self.nodes[ppid].children.append(pid)
        else:
            node = self.nodes[pid]
            if ppid and not node.ppid:
                node.ppid = ppid
                if ppid in self.nodes and pid not in self.nodes[ppid].children:
                    self.nodes[ppid].children.append(pid)
            if command and (node.command == "unknown" or not node.command):
                node.command = command

        return self.nodes[pid]

    def _adopt_main_as_pid(self, real_pid: str):
        """Unifies the initial 'Main' process node with its detected numeric PID."""
        real_pid = str(real_pid)
        if "Main" in self.nodes and real_pid != "Main":
            main_node = self.nodes.pop("Main")
            if real_pid in self.nodes:
                existing = self.nodes[real_pid]
                main_node.syscall_count += existing.syscall_count
                for c in existing.children:
                    if c not in main_node.children:
                        main_node.children.append(c)
                if existing.command != "unknown":
                    main_node.command = existing.command
                if existing.status != "Running":
                    main_node.status = existing.status
            main_node.pid = real_pid
            self.nodes[real_pid] = main_node
            self.root_pid = real_pid
            for n in self.nodes.values():
                if n.ppid == "Main":
                    n.ppid = real_pid

    def record_syscall(self, pid: str, name: str, args: str, ret_val: str):
        """
        Updates process metrics and inspects process creation/execution syscalls.
        Derives parent-child links only from actual kernel return values.
        """
        pid = str(pid)
        node = self.ensure_process(pid)
        node.syscall_count += 1

        # 1. Process creation: clone, clone3, fork, vfork
        # Return value in parent is the child PID (positive integer)
        if name in ("clone", "clone3", "fork", "vfork"):
            if pid != "Main" and "Main" in self.nodes:
                self._adopt_main_as_pid(pid)
            ret_token = ret_val.split()[0] if ret_val else ""
            if ret_token.isdigit() and int(ret_token) > 0:
                child_pid = ret_token
                self.ensure_process(child_pid, ppid=pid)

        # 2. Executable replacement: execve, execveat
        elif name in ("execve", "execveat"):
            # Parse path from first argument: e.g. "/bin/echo" or "echo"
            m = re.search(r'^(?:AT_FDCWD,\s*)?"([^"]+)"', args.strip())
            if m:
                path = m.group(1)
                exe = path.split("/")[-1]
                node.command = exe
            elif args:
                token = args.split(",")[0].strip().strip('"')
                if token:
                    node.command = token.split("/")[-1]

        # 3. getpid: reveal actual PID of Main process
        elif name == "getpid":
            ret_token = ret_val.split()[0] if ret_val else ""
            if ret_token.isdigit() and int(ret_token) > 0:
                self._adopt_main_as_pid(ret_token)

    def handle_raw_line(self, line: str):
        """
        Inspects raw strace output lines for process lifecycle events:
        process attachment, exit codes, and SIGCHLD notifications.
        """
        clean = line.strip()

        # 1. strace: Process 768 attached
        m_attach = re.search(r'Process\s+(\d+)\s+attached', clean)
        if m_attach:
            child_pid = m_attach.group(1)
            # Only associate parent if unambiguous (single parent) or already known
            ppid = self.root_pid if (self.root_pid and len(self.nodes) == 1) else None
            self.ensure_process(child_pid, ppid=ppid)

        # 2. [pid  768] +++ exited with 0 +++
        m_exit = re.search(r'(?:\[pid\s+(\d+)\]\s+)?\+{3}\s+exited with (\d+)\s+\+{3}', clean)
        if m_exit:
            pid = m_exit.group(1) or self.root_pid or "Main"
            rc = m_exit.group(2)
            if pid in self.nodes:
                self.nodes[pid].status = f"Exited (code {rc})"

        # 3. SIGCHLD signal: si_pid=768, si_status=0
        m_sig = re.search(r'si_pid=(\d+)(?:,\s+si_uid=\d+)?,\s+si_status=(\d+)', clean)
        if m_sig:
            child_pid = m_sig.group(1)
            status_code = m_sig.group(2)
            if child_pid in self.nodes:
                self.nodes[child_pid].status = f"Exited (code {status_code})"

        # 4. execve / execveat in raw line: [pid 200] execve("/bin/echo", ...)
        m_exec = re.search(r'(?:\[pid\s+(\d+)\]\s+)?execve(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)"', clean)
        if m_exec:
            pid = m_exec.group(1) or self.root_pid or "Main"
            exe_path = m_exec.group(2)
            exe = exe_path.split("/")[-1]
            if pid in self.nodes:
                self.nodes[pid].command = exe

    def get_root_nodes(self) -> List[ProcessNode]:
        """Returns processes without parents or whose parent is not in tracked nodes."""
        roots = []
        for pid, node in self.nodes.items():
            if not node.ppid or node.ppid not in self.nodes or node.ppid == pid:
                roots.append(node)
        return roots

    def get_children(self, pid: str) -> List[ProcessNode]:
        """Returns list of child nodes for a given PID."""
        pid = str(pid)
        if pid not in self.nodes:
            return []
        return [self.nodes[c_pid] for c_pid in self.nodes[pid].children if c_pid in self.nodes]

    def get_all_nodes(self) -> List[ProcessNode]:
        """Returns all tracked processes."""
        return list(self.nodes.values())
