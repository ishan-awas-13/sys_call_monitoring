"""
Stage 2 & 5: Python + strace Integration
Launches a real Linux command under strace, captures raw syscall trace lines
from stderr in real time, and prints them to the terminal.
Supports start/stop controls for live GUI integration.
"""

import subprocess
import sys
import os
import signal
import shlex


class TraceSession:
    """
    Manages an active strace monitoring session for a target command.
    Allows streaming output lines to a callback in real time and cancelling on demand.
    """

    def __init__(self):
        self.process = None
        self._stopped = False
        self.is_attached = False
        self.target_pid = None

    def start(self, command: str = "", on_line=None, follow_children: bool = False, cwd: str = None, pid: int = None):
        """
        Launches strace and reads lines from stderr until completion or stop() is called.
        If pid is provided (or if command is like 'PID: 1234' or purely numeric),
        attaches strace directly to that running process using -p <PID>.
        If follow_children is True, attaches -f flag to strace to trace child processes.
        If cwd is provided, the command and strace execute inside that directory.
        """
        self._stopped = False
        self.is_attached = False
        self.target_pid = None

        # Detect PID attachment mode from parameter or command string
        target_pid = pid
        clean_cmd = (command or "").strip()
        if target_pid is None and clean_cmd.lower().startswith("pid:"):
            try:
                target_pid = int(clean_cmd.split(":", 1)[1].strip())
            except ValueError:
                target_pid = None
        elif target_pid is None and clean_cmd.isdigit():
            target_pid = int(clean_cmd)

        strace_cmd = ["strace", "-f"] if follow_children else ["strace"]

        if target_pid is not None:
            self.is_attached = True
            self.target_pid = target_pid
            cmd_args = strace_cmd + ["-p", str(target_pid)]
            target_cwd = None
            print(f"[+] Attaching strace to running PID: {target_pid} (follow_children={follow_children})")
        else:
            target_cwd = cwd if (cwd and os.path.isdir(cwd)) else None
            display_cwd = target_cwd or os.getcwd()
            print(f"[+] Target command: {command} (cwd={display_cwd}, follow_children={follow_children})")
            cmd_args = strace_cmd + shlex.split(command)

        print("[+] Launching strace...\n" + "=" * 60)

        # os.setsid creates a new process group so strace and the child process
        # can both be cleanly terminated together if stop() is requested.
        self.process = subprocess.Popen(
            cmd_args,
            stdout=None,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid,
            cwd=target_cwd
        )

        captured_syscall_lines = []

        if self.process.stderr:
            for line in iter(self.process.stderr.readline, ''):
                if self._stopped:
                    break
                # Print raw strace output to terminal for transparency
                print(line, end="", flush=True)
                captured_syscall_lines.append(line)
                if on_line:
                    on_line(line)
            try:
                self.process.stderr.close()
            except Exception:
                pass

        returncode = self.process.wait()

        print("=" * 60)
        print(f"[+] Process exited with returncode: {returncode}")
        print(f"[+] Total raw syscall lines captured: {len(captured_syscall_lines)}")

        return captured_syscall_lines

    def stop(self):
        """
        Terminates the active strace and child processes cleanly.
        If attached to an external PID, sends SIGINT to strace so it cleanly detaches
        without terminating the monitored target process.
        """
        self._stopped = True
        if self.process and self.process.poll() is None:
            try:
                if self.is_attached:
                    # SIGINT causes strace to detach cleanly from the target PID
                    self.process.send_signal(signal.SIGINT)
                else:
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass


def trace_command(command: str = "", on_line=None, follow_children: bool = False, cwd: str = None, pid: int = None):
    """
    Execute a command under strace and capture its system calls.
    Maintains backward compatibility with earlier stages.
    """
    session = TraceSession()
    return session.start(command, on_line=on_line, follow_children=follow_children, cwd=cwd, pid=pid)


if __name__ == "__main__":
    # Default to tracing 'cat sample.txt' if no CLI arguments are supplied
    target = "cat sample.txt"
    if len(sys.argv) > 1:
        target = " ".join(sys.argv[1:])

    trace_command(target)
