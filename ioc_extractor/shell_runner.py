"""
shell_runner.py - Shell command execution with timeout protection.

Provides a safe wrapper around subprocess that captures stdout/stderr
and enforces a configurable timeout to prevent GUI freezes.
"""

import os
import signal
import subprocess
from typing import Optional

from .constants import SHELL_COMMAND_TIMEOUT


_IS_WINDOWS = os.name == "nt"


def _popen_group_kwargs() -> dict:
    """Launch shell commands in a separate process group/session for reliable timeout cleanup."""
    if _IS_WINDOWS:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return {"creationflags": flags} if flags else {}
    return {"start_new_session": True}


def _kill_process_tree(process: Optional[subprocess.Popen]) -> None:
    """Best-effort kill of the shell process and its child process group."""
    if process is None:
        return
    try:
        if process.poll() is not None:
            return
    except Exception:
        return

    if _IS_WINDOWS:
        try:
            process.kill()
        except Exception:
            pass
        return

    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        process.kill()
    except Exception:
        pass


def run_command(
    command: str,
    timeout: int = SHELL_COMMAND_TIMEOUT,
) -> dict:
    """
    Execute a shell command string and return structured results.

    Parameters
    ----------
    command : str
        The shell command to run (supports pipes, redirection, etc.).
    timeout : int
        Maximum seconds to wait before killing the process.

    Returns
    -------
    dict with keys:
        - ``stdout`` : str
        - ``stderr`` : str
        - ``return_code`` : int
        - ``timed_out`` : bool
    """
    process: Optional[subprocess.Popen] = None
    timed_out = False
    stdout = ""
    stderr = ""
    return_code = -1

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **_popen_group_kwargs(),
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_tree(process)
            try:
                stdout, stderr = process.communicate(timeout=2)
            except Exception as post_kill:
                stderr = (stderr or "") + f"\nError after kill: {post_kill}"
            return_code = process.returncode if process.returncode is not None else -9

    except Exception as exc:
        stderr = f"{type(exc).__name__}: {exc}"
        # Ensure process is cleaned up
        if process and process.poll() is None:
            try:
                _kill_process_tree(process)
            except Exception:
                pass

    return {
        "stdout": stdout or "",
        "stderr": stderr or "",
        "return_code": return_code,
        "timed_out": timed_out,
    }


def run_command_raw(
    command: str,
    timeout: int = SHELL_COMMAND_TIMEOUT,
) -> dict:
    """
    Execute a shell command preserving ANSI escape codes in stdout.

    Like run_command() but uses binary mode for stdout so ANSI color
    codes are not stripped. The result is decoded to str with
    errors='replace'.

    Parameters
    ----------
    command : str
        The shell command to run.
    timeout : int
        Maximum seconds to wait before killing the process.

    Returns
    -------
    dict with keys:
        - ``stdout`` : str (with ANSI escape codes preserved)
        - ``stderr`` : str
        - ``return_code`` : int
        - ``timed_out`` : bool
    """
    process: Optional[subprocess.Popen] = None
    timed_out = False
    stdout_bytes = b""
    stderr = ""
    return_code = -1

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # stdout is binary to preserve ANSI codes
            **_popen_group_kwargs(),
        )

        try:
            raw_stdout, raw_stderr = process.communicate(timeout=timeout)
            stdout_bytes = raw_stdout or b""
            stderr = (raw_stderr or b"").decode("utf-8", errors="replace")
            return_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_tree(process)
            try:
                raw_stdout, raw_stderr = process.communicate(timeout=2)
                stdout_bytes = raw_stdout or b""
                stderr = (raw_stderr or b"").decode("utf-8", errors="replace")
            except Exception as post_kill:
                stderr = stderr + f"\nError after kill: {post_kill}"
            return_code = process.returncode if process.returncode is not None else -9

    except Exception as exc:
        stderr = f"{type(exc).__name__}: {exc}"
        if process and process.poll() is None:
            try:
                _kill_process_tree(process)
            except Exception:
                pass

    return {
        "stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "stderr": stderr,
        "return_code": return_code,
        "timed_out": timed_out,
    }
