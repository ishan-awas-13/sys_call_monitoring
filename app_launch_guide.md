# System Call Monitor Launch Guide

## One-time setup

Open a PowerShell terminal and install the Linux dependencies in WSL once:

```powershell
wsl
sudo apt update
sudo apt install -y python3 python3-tk strace
exit
```

You do not need to reinstall these packages every time you open VS Code or Antigravity.

## Launch the app

In a PowerShell terminal, run:

```powershell
wsl.exe --cd "/mnt/c/Users/ishan/OneDrive/Desktop/College_Files/SEM-5/Operating Systems/sys_call_monitoring" --exec python3 gui.py
```

Keep the terminal session open while using the app. The default monitored command is `cat sample.txt`, so launching from the project directory is important. Avoid the editor's top-right Run button, which may use Windows Python instead of the WSL environment.

If you already have a WSL terminal open, you can instead run:

```bash
cd "/mnt/c/Users/ishan/OneDrive/Desktop/College_Files/SEM-5/Operating Systems/sys_call_monitoring"
python3 gui.py
```

## If the app does not start

- `No module named tkinter`: enter WSL and run `sudo apt install -y python3-tk`.
- `strace: command not found`: enter WSL and run `sudo apt install -y strace`.
- `can't open file` or `sample.txt` is missing: check that the terminal is in the project directory shown above.
- `couldn't connect to display` or `no display name`: confirm WSLg is available by running `wsl.exe --exec printenv WAYLAND_DISPLAY` from PowerShell. A value such as `wayland-0` indicates a display is configured.

## If only a taskbar icon appears

1. Click the monitor's taskbar icon. You can also try `Alt+Tab` or `Win+Tab` and select **Linux System Call Monitoring Tool**.
2. Do not launch another copy while the first process is still running. If needed, stop it with `Ctrl+C` in its launch terminal.
3. From PowerShell, reset WSLg and relaunch:

   ```powershell
   wsl.exe --shutdown
   wsl.exe --cd "/mnt/c/Users/ishan/OneDrive/Desktop/College_Files/SEM-5/Operating Systems/sys_call_monitoring" --exec python3 gui.py
   ```
   `wsl.exe --shutdown` closes all running programs in WSL, not just this app. Save work in other Linux programs first.
4. If the window is still invisible after the WSLg reset, save your work and restart Windows. A reboot should be a last resort; reinstalling the Python packages is not normally necessary.
