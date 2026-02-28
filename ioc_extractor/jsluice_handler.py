"""
jsluice_handler.py - Jsluice tool integration.

Manages detection of the jsluice binary/script, execution against
temporary files, structured parsing of JSON-line output, and
automatic cleanup of stale temp files.
"""

import glob
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import (
    JSLUICE_TEMP_MAX_AGE,
    JSLUICE_TEMP_PREFIX,
    JSLUICE_TEMP_SUFFIX,
)


class JsluiceHandler:
    """Wraps jsluice discovery, execution, and output formatting."""

    def __init__(self, temp_max_age: int = JSLUICE_TEMP_MAX_AGE):
        self.path: Optional[str] = shutil.which("jsluice")
        self.needs_python: bool = False
        self.executable_name: Optional[str] = None
        self.base_command: List[str] = []
        self._init_warning: Optional[str] = None
        self._created_temps: List[str] = []
        self._temp_max_age = max(60, int(temp_max_age))

        # Fallback: check GOBIN / GOPATH/bin / ~/go/bin directly.
        # macOS GUI apps don't inherit shell profile PATH additions,
        # so shutil.which() may miss a perfectly valid installation.
        if not self.path:
            self.path = self._probe_gobin_jsluice()

        if self.path:
            self.executable_name = os.path.basename(self.path)
            if self.path.lower().endswith(".py"):
                py = shutil.which("python") or shutil.which("python3")
                if py:
                    self.needs_python = True
                    self.base_command = [py, self.path]
                else:
                    self._disable(
                        "Found jsluice.py but no 'python'/'python3' executable."
                    )
            else:
                self.base_command = [self.path]

        # Clean up old temp files from previous sessions on startup
        self._cleanup_stale_temps()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self.path is not None

    @property
    def init_warning(self) -> Optional[str]:
        return self._init_warning

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def run(
        self,
        input_text: str,
        mode: str,
        custom_options: str = "",
        raw_output: bool = False,
    ) -> dict:
        """
        Execute jsluice and return structured results.

        Returns a dict with keys:
          - ``temp_file``: path to the created temporary file
          - ``success``: bool
          - ``output``: formatted string for display
          - ``error``: error string (only present on failure)
        """
        if not self.available:
            return {"success": False, "error": "jsluice command not found."}

        # Parse custom options safely
        additional_args: List[str] = []
        if custom_options.strip():
            try:
                additional_args = shlex.split(custom_options)
            except ValueError as exc:
                return {"success": False, "error": f"Option parse error: {exc}"}

        # Create timestamped temp file
        try:
            temp_path = self._create_temp_file(input_text)
            self._created_temps.append(temp_path)
        except Exception as exc:
            return {"success": False, "error": f"Temp file error: {exc}"}

        # Build and run command
        cmd = self.base_command + [mode] + additional_args + [temp_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            cmd_name = self.base_command[0] if self.base_command else "jsluice"
            return {
                "temp_file": temp_path,
                "success": False,
                "error": f"Command '{cmd_name}' not found.",
            }
        except Exception as exc:
            return {
                "temp_file": temp_path,
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

        # Process output
        if proc.returncode != 0:
            error_text = proc.stderr or "(No error message on stderr)"
            stdout_text = ""
            if proc.stdout:
                stdout_text = (
                    "\n--- Stdout Received Before Error ---\n" + proc.stdout
                )
            return {
                "temp_file": temp_path,
                "success": False,
                "error": (
                    f"Exit Code: {proc.returncode}\n{error_text}{stdout_text}"
                ),
            }

        if not proc.stdout.strip():
            return {
                "temp_file": temp_path,
                "success": True,
                "output": "(No output produced by jsluice)",
            }

        if raw_output:
            return {
                "temp_file": temp_path,
                "success": True,
                "output": proc.stdout,
            }

        # Structured formatting
        formatted = self._format_output(proc.stdout, mode)
        return {"temp_file": temp_path, "success": True, "output": formatted}

    def cleanup(self):
        """Remove all temp files created during this session."""
        removed = 0
        for path in self._created_temps:
            try:
                if os.path.exists(path):
                    os.unlink(path)
                    removed += 1
            except OSError:
                pass
        self._created_temps.clear()
        return removed

    def reinitialize(self):
        """Re-detect jsluice binary (e.g. after installation).

        Augments PATH with GOPATH/bin, then re-runs the full
        detection logic so ``self.available`` reflects the new state.
        """
        from .jsluice_installer import JsluiceInstaller

        installer = JsluiceInstaller()
        installer.augment_path_with_gobin()

        self.path = shutil.which("jsluice") or installer.find_jsluice()
        self.needs_python = False
        self.executable_name = None
        self.base_command = []
        self._init_warning = None

        if self.path:
            self.executable_name = os.path.basename(self.path)
            if self.path.lower().endswith(".py"):
                py = shutil.which("python") or shutil.which("python3")
                if py:
                    self.needs_python = True
                    self.base_command = [py, self.path]
                else:
                    self._disable(
                        "Found jsluice.py but no 'python'/'python3' executable."
                    )
            else:
                self.base_command = [self.path]

    def set_temp_max_age(self, seconds: int) -> None:
        """Update stale-temp cleanup age for future startup/manual cleanup."""
        self._temp_max_age = max(60, int(seconds))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _probe_gobin_jsluice() -> Optional[str]:
        """Check common Go binary directories for jsluice.

        Handles .exe suffix on Windows automatically.
        """
        import platform as _plat
        exe = ".exe" if _plat.system() == "Windows" else ""
        name = "jsluice" + exe

        home = str(Path.home())
        gobin = os.environ.get("GOBIN")
        gopath = os.environ.get("GOPATH", os.path.join(home, "go"))

        candidates = []
        if gobin:
            candidates.append(os.path.join(gobin, name))
        candidates.append(os.path.join(gopath, "bin", name))
        # Default ~/go/bin if GOPATH is non-default
        default = os.path.join(home, "go", "bin", name)
        if default not in candidates:
            candidates.append(default)

        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK | os.F_OK):
                # Add the directory to PATH so subprocess calls work
                bin_dir = os.path.dirname(candidate)
                current = os.environ.get("PATH", "")
                if bin_dir not in current.split(os.pathsep):
                    os.environ["PATH"] = bin_dir + os.pathsep + current
                return candidate
        return None

    def _disable(self, warning: str):
        self.path = None
        self.executable_name = None
        self.base_command = []
        self._init_warning = warning

    @staticmethod
    def _create_temp_file(content: str) -> str:
        temp_dir = tempfile.gettempdir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(
            temp_dir, f"{JSLUICE_TEMP_PREFIX}{timestamp}{JSLUICE_TEMP_SUFFIX}"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def _cleanup_stale_temps(self):
        """Remove jsluice temp files older than JSLUICE_TEMP_MAX_AGE."""
        temp_dir = tempfile.gettempdir()
        pattern = os.path.join(
            temp_dir, f"{JSLUICE_TEMP_PREFIX}*{JSLUICE_TEMP_SUFFIX}"
        )
        now = datetime.now().timestamp()
        for path in glob.glob(pattern):
            try:
                age = now - os.path.getmtime(path)
                if age > self._temp_max_age:
                    os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def _format_output(stdout: str, mode: str) -> str:
        """Parse JSON-line output and group by category."""
        lines = stdout.strip().splitlines()
        categorized: Dict[str, set] = {}
        unparsed: List[str] = []
        parsed_any_json = False

        for line in lines:
            try:
                data = json.loads(line)
                parsed_any_json = True

                category = None
                value = None

                if mode == "urls":
                    url = data.get("url")
                    if url:
                        category, value = "URLs", url
                elif mode == "secrets":
                    kind = data.get("kind")
                    match = data.get("match")
                    if kind and match:
                        category, value = "Secrets", f"{kind}: {match}"
                elif mode == "query":
                    category, value = "Query Results", json.dumps(data)

                if category is None:
                    category, value = "Other JSON Data", json.dumps(data)

                if value is not None:
                    categorized.setdefault(category, set()).add(value)

            except json.JSONDecodeError:
                if line.strip():
                    unparsed.append(line)

        # Build output string
        parts: List[str] = []
        if categorized:
            for cat, items in sorted(categorized.items()):
                parts.append(f"--- {cat} ---")
                for item in sorted(items):
                    parts.append(item)
                parts.append("")
        elif not parsed_any_json and stdout.strip():
            parts.append(f"--- Raw Output ({mode.capitalize()} Mode) ---")
            parts.append(stdout)
            parts.append("")

        if parsed_any_json and unparsed:
            parts.append("--- Unparsed Lines / Non-JSON Data ---")
            parts.extend(unparsed)

        return "\n".join(parts)
