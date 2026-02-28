"""
jsluice_installer.py - Automated cross-platform jsluice installation.

Handles detection of Go, installation of Go if missing,
compilation of jsluice from source via ``go install``, and
PATH management.

Supported platforms:
  - macOS (Darwin): Homebrew → official tarball
  - Linux: apt-get → dnf/yum → pacman → snap → official tarball
  - Windows: Chocolatey → Scoop → Winget → official .zip
"""

import glob
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.error
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .constants import (
    GO_INSTALL_TIMEOUT,
    JSLUICE_INSTALL_PACKAGE,
    JSLUICE_INSTALL_TIMEOUT,
)

_IS_WINDOWS = platform.system() == "Windows"
_EXE = ".exe" if _IS_WINDOWS else ""


class JsluiceInstaller:
    """Handles Go detection, Go installation, and jsluice compilation.

    All public methods are safe to call from any platform.
    """

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def find_go() -> Optional[str]:
        """Locate the Go binary on any platform.

        Checks ``shutil.which`` first, then probes well-known
        installation directories per-OS.
        """
        go = shutil.which("go")
        if go:
            return go

        home = str(Path.home())

        if _IS_WINDOWS:
            candidates = [
                os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                             "Go", "bin", "go.exe"),
                r"C:\Go\bin\go.exe",
                os.path.join(home, "go", "bin", "go.exe"),
                os.path.join(home, "sdk", "go", "bin", "go.exe"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""),
                             "Programs", "Go", "bin", "go.exe"),
            ]
            # Scoop installs
            scoop_go = glob.glob(
                os.path.join(home, "scoop", "apps", "go", "*", "bin", "go.exe")
            )
            if scoop_go:
                candidates.insert(0, sorted(scoop_go)[-1])

            # Chocolatey installs
            choco_go = glob.glob(
                os.path.join(os.environ.get("ChocolateyInstall",
                             r"C:\ProgramData\chocolatey"),
                             "lib", "golang", "tools", "go*", "bin", "go.exe")
            )
            if choco_go:
                candidates.insert(0, sorted(choco_go)[-1])

        else:
            # macOS / Linux
            candidates = [
                "/usr/local/go/bin/go",          # Official installer
                "/opt/homebrew/bin/go",           # Homebrew (Apple Silicon)
                "/usr/local/bin/go",              # Homebrew (Intel) / Linux
                "/usr/bin/go",                    # apt/dnf/pacman
                "/snap/bin/go",                   # Snap
                os.path.join(home, ".local", "go", "bin", "go"),
            ]
            # Homebrew cellar
            brew_go = glob.glob("/opt/homebrew/Cellar/go/*/bin/go")
            if brew_go:
                candidates.insert(0, sorted(brew_go)[-1])

        # User-managed Go SDKs (all platforms)
        for pattern in [
            os.path.join(home, "sdk", "go*", "bin", "go" + _EXE),
        ]:
            matches = glob.glob(pattern)
            if matches:
                candidates.insert(0, sorted(matches)[-1])

        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK | os.F_OK):
                return c

        return None

    @staticmethod
    def find_jsluice() -> Optional[str]:
        """Locate the jsluice binary on any platform."""
        name = "jsluice" + _EXE
        js = shutil.which("jsluice")
        if js:
            return js

        for d in JsluiceInstaller._gobin_candidates():
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK | os.F_OK):
                return candidate

        return None

    @staticmethod
    def get_gopath_bin() -> str:
        """Return the effective GOPATH/bin directory."""
        gobin = os.environ.get("GOBIN")
        if gobin:
            return gobin
        gopath = os.environ.get("GOPATH", os.path.join(str(Path.home()), "go"))
        return os.path.join(gopath, "bin")

    # ------------------------------------------------------------------
    # Installation — public entry points
    # ------------------------------------------------------------------

    def install_go(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Install Go via package manager or direct download.

        Strategy per platform:
          - macOS:   Homebrew → official tarball
          - Linux:   apt-get → dnf/yum → pacman → snap → official tarball
          - Windows: Chocolatey → Scoop → Winget → official .zip

        Returns ``{success: bool, message: str, go_path: str|None}``.
        """
        system = platform.system()

        if system == "Darwin":
            return self._install_go_darwin(progress)
        elif system == "Linux":
            return self._install_go_linux(progress)
        elif system == "Windows":
            return self._install_go_windows(progress)
        else:
            return {
                "success": False,
                "message": (
                    f"Auto-install not supported on {system}.\n"
                    "Install Go manually from: https://go.dev/dl/\n"
                    "Then restart the application."
                ),
                "go_path": None,
            }

    def install_jsluice(
        self,
        go_path: str,
        progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Compile jsluice from source using ``go install``.

        Works identically on all platforms — Go handles the
        cross-compilation natively.
        """
        progress("Building jsluice from source (this may take 1-2 minutes)...")

        gopath_bin = self.get_gopath_bin()
        env = os.environ.copy()
        env.setdefault("GOPATH", os.path.join(str(Path.home()), "go"))
        env["PATH"] = (
            os.path.dirname(go_path)
            + os.pathsep + gopath_bin
            + os.pathsep + env.get("PATH", "")
        )

        result = self._run_cmd(
            [go_path, "install", JSLUICE_INSTALL_PACKAGE],
            timeout=JSLUICE_INSTALL_TIMEOUT,
            env=env,
        )

        if not result["success"]:
            stderr = result.get("stderr", "")
            return {
                "success": False,
                "message": (
                    f"jsluice compilation failed:\n{stderr}\n\n"
                    f"Try manually: {go_path} install {JSLUICE_INSTALL_PACKAGE}"
                ),
                "jsluice_path": None,
            }

        progress("Verifying jsluice installation...")
        jsluice_path = self.find_jsluice()
        if jsluice_path:
            progress(f"jsluice installed at: {jsluice_path}")
            return {
                "success": True,
                "message": "jsluice installed successfully.",
                "jsluice_path": jsluice_path,
            }

        return {
            "success": False,
            "message": (
                "go install succeeded but jsluice binary not found.\n"
                f"Expected location: {os.path.join(gopath_bin, 'jsluice' + _EXE)}\n"
                "Check GOPATH/GOBIN configuration."
            ),
            "jsluice_path": None,
        }

    def full_install(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Orchestrate the complete jsluice installation.

        1. Check if jsluice already exists.
        2. Find or install Go.
        3. Compile jsluice from source.
        4. Verify and return.
        """
        # Step 1: Check if already installed
        progress("Checking for existing jsluice installation...")
        existing = self.find_jsluice()
        if existing:
            self.augment_path_with_gobin()
            progress(f"jsluice already installed at: {existing}")
            return {
                "success": True,
                "message": f"jsluice already installed at: {existing}",
                "jsluice_path": existing,
            }

        # Step 2: Find or install Go
        progress("Looking for Go compiler...")
        go_path = self.find_go()

        if go_path:
            progress(f"Go found at: {go_path}")
        else:
            progress("Go not found. Attempting to install Go...")
            go_result = self.install_go(progress)
            if not go_result["success"]:
                return {
                    "success": False,
                    "message": (
                        "Cannot install jsluice — Go is required.\n\n"
                        + go_result["message"]
                    ),
                    "jsluice_path": None,
                }
            go_path = go_result["go_path"]
            progress(f"Go installed at: {go_path}")

        # Step 3: Compile jsluice
        js_result = self.install_jsluice(go_path, progress)
        if js_result["success"]:
            self.augment_path_with_gobin()

        return js_result

    # ------------------------------------------------------------------
    # PATH management
    # ------------------------------------------------------------------

    def augment_path_with_gobin(self) -> None:
        """Add GOPATH/bin to ``os.environ['PATH']`` for the current process."""
        gopath_bin = self.get_gopath_bin()
        current_path = os.environ.get("PATH", "")
        if gopath_bin not in current_path.split(os.pathsep):
            os.environ["PATH"] = gopath_bin + os.pathsep + current_path

    # ==================================================================
    # Platform-specific Go installation
    # ==================================================================

    # --- macOS (Darwin) -----------------------------------------------

    def _install_go_darwin(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """macOS: Homebrew → official tarball."""
        brew = shutil.which("brew")
        if not brew:
            for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
                if os.path.isfile(p):
                    brew = p
                    break

        if brew:
            progress("Installing Go via Homebrew (this may take a few minutes)...")
            result = self._run_cmd(
                [brew, "install", "go"], timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via Homebrew.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via Homebrew.",
                        "go_path": go_path,
                    }
            progress("Homebrew install failed, trying direct download...")

        return self._install_go_tarball(progress)

    # --- Linux --------------------------------------------------------

    def _install_go_linux(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Linux: apt-get → dnf/yum → pacman → snap → official tarball."""
        # 1. apt-get (Debian / Ubuntu)
        apt = shutil.which("apt-get")
        if apt:
            progress("Installing Go via apt-get...")
            result = self._run_cmd(
                ["sudo", apt, "install", "-y", "golang-go"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via apt-get.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via apt-get.",
                        "go_path": go_path,
                    }
                progress("apt install succeeded but Go binary not found, continuing...")

        # 2. dnf (Fedora / RHEL 8+ / CentOS Stream)
        dnf = shutil.which("dnf")
        if dnf:
            progress("Installing Go via dnf...")
            result = self._run_cmd(
                ["sudo", dnf, "install", "-y", "golang"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via dnf.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via dnf.",
                        "go_path": go_path,
                    }

        # 3. yum (RHEL 7 / CentOS 7 / older)
        if not dnf:
            yum = shutil.which("yum")
            if yum:
                progress("Installing Go via yum...")
                result = self._run_cmd(
                    ["sudo", yum, "install", "-y", "golang"],
                    timeout=GO_INSTALL_TIMEOUT,
                )
                if result["success"]:
                    progress("Go installed via yum.")
                    go_path = self.find_go()
                    if go_path:
                        return {
                            "success": True,
                            "message": "Go installed via yum.",
                            "go_path": go_path,
                        }

        # 4. pacman (Arch / Manjaro)
        pacman = shutil.which("pacman")
        if pacman:
            progress("Installing Go via pacman...")
            result = self._run_cmd(
                ["sudo", pacman, "-S", "--noconfirm", "go"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via pacman.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via pacman.",
                        "go_path": go_path,
                    }

        # 5. snap
        snap = shutil.which("snap")
        if snap:
            progress("Installing Go via snap...")
            result = self._run_cmd(
                ["sudo", snap, "install", "go", "--classic"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via snap.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via snap.",
                        "go_path": go_path,
                    }

        # 6. Fallback — direct tarball from go.dev
        progress("Package managers failed or unavailable, trying direct download...")
        return self._install_go_tarball(progress)

    # --- Windows ------------------------------------------------------

    def _install_go_windows(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Windows: Chocolatey → Scoop → Winget → official .zip."""
        # 1. Chocolatey
        choco = shutil.which("choco")
        if choco:
            progress("Installing Go via Chocolatey...")
            result = self._run_cmd(
                [choco, "install", "golang", "-y"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via Chocolatey.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via Chocolatey.",
                        "go_path": go_path,
                    }
                progress("Chocolatey install succeeded but Go not found, continuing...")

        # 2. Scoop
        scoop = shutil.which("scoop")
        if scoop:
            progress("Installing Go via Scoop...")
            result = self._run_cmd(
                [scoop, "install", "go"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via Scoop.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via Scoop.",
                        "go_path": go_path,
                    }

        # 3. Winget
        winget = shutil.which("winget")
        if winget:
            progress("Installing Go via Winget...")
            result = self._run_cmd(
                [winget, "install", "--id", "GoLang.Go",
                 "--accept-source-agreements", "--accept-package-agreements"],
                timeout=GO_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("Go installed via Winget.")
                go_path = self.find_go()
                if go_path:
                    return {
                        "success": True,
                        "message": "Go installed via Winget.",
                        "go_path": go_path,
                    }

        # 4. Fallback — direct .zip download from go.dev
        progress("Package managers failed or unavailable, trying direct download...")
        return self._install_go_zip_windows(progress)

    # ==================================================================
    # Direct download installers (no package manager needed)
    # ==================================================================

    def _install_go_tarball(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Download and extract the official Go tarball (macOS / Linux).

        Installs to ``/usr/local/go`` (with sudo) or ``~/.local/go``
        (without sudo) and adds the ``bin`` directory to PATH.
        """
        system = platform.system().lower()   # "darwin" or "linux"
        machine = platform.machine().lower()
        goarch = self._resolve_goarch(machine)
        if not goarch:
            return self._unsupported_arch(machine)

        version = self._fetch_go_version(progress)
        if not version:
            return self._version_fetch_failed()

        filename = f"{version}.{system}-{goarch}.tar.gz"
        url = f"https://go.dev/dl/{filename}"
        progress(f"Downloading {filename}...")

        tmp_dir = tempfile.mkdtemp(prefix="go_install_")
        archive_path = os.path.join(tmp_dir, filename)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except (urllib.error.URLError, OSError) as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return self._download_failed(url, exc)

        # Choose install location
        install_dir = "/usr/local"
        go_root = os.path.join(install_dir, "go")

        progress(f"Extracting Go to {go_root}...")
        try:
            if os.access(install_dir, os.W_OK):
                # Writable — extract directly
                if os.path.exists(go_root):
                    shutil.rmtree(go_root, ignore_errors=True)
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=install_dir)
            else:
                # Need sudo
                self._run_cmd(["sudo", "rm", "-rf", go_root], timeout=30)
                result = self._run_cmd(
                    ["sudo", "tar", "-C", install_dir, "-xzf", archive_path],
                    timeout=120,
                )
                if not result["success"]:
                    # Sudo failed — fall back to user-local
                    progress("sudo failed, installing to ~/.local/go instead...")
                    install_dir = os.path.join(str(Path.home()), ".local")
                    go_root = os.path.join(install_dir, "go")
                    os.makedirs(install_dir, exist_ok=True)
                    if os.path.exists(go_root):
                        shutil.rmtree(go_root, ignore_errors=True)
                    with tarfile.open(archive_path, "r:gz") as tar:
                        tar.extractall(path=install_dir)
        except Exception as exc:
            return {
                "success": False,
                "message": (
                    f"Extraction failed: {exc}\n"
                    "Install Go manually from: https://go.dev/dl/"
                ),
                "go_path": None,
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return self._verify_go_install(go_root, version, progress)

    def _install_go_zip_windows(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Download and extract the official Go .zip (Windows).

        Installs to ``C:\\Go`` (if writable) or ``%LOCALAPPDATA%\\Go``
        and adds the ``bin`` directory to PATH.
        """
        machine = platform.machine().lower()
        goarch = self._resolve_goarch(machine)
        if not goarch:
            return self._unsupported_arch(machine)

        version = self._fetch_go_version(progress)
        if not version:
            return self._version_fetch_failed()

        filename = f"{version}.windows-{goarch}.zip"
        url = f"https://go.dev/dl/{filename}"
        progress(f"Downloading {filename}...")

        tmp_dir = tempfile.mkdtemp(prefix="go_install_")
        archive_path = os.path.join(tmp_dir, filename)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except (urllib.error.URLError, OSError) as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return self._download_failed(url, exc)

        # Choose install location
        # Try C:\Go first, then %LOCALAPPDATA%\Go
        install_dir = r"C:\\"
        go_root = os.path.join(install_dir, "Go")

        if not os.access(install_dir, os.W_OK):
            install_dir = os.path.join(
                os.environ.get("LOCALAPPDATA",
                               os.path.join(str(Path.home()), "AppData", "Local")),
            )
            go_root = os.path.join(install_dir, "Go")

        progress(f"Extracting Go to {go_root}...")
        try:
            if os.path.exists(go_root):
                shutil.rmtree(go_root, ignore_errors=True)

            with zipfile.ZipFile(archive_path, "r") as zf:
                # The zip contains a top-level "go/" directory
                zf.extractall(path=install_dir)

            # The zip extracts to install_dir/go — rename to Go if needed
            extracted = os.path.join(install_dir, "go")
            if os.path.isdir(extracted) and extracted != go_root:
                if os.path.exists(go_root):
                    shutil.rmtree(go_root, ignore_errors=True)
                os.rename(extracted, go_root)

        except Exception as exc:
            return {
                "success": False,
                "message": (
                    f"Extraction failed: {exc}\n"
                    "Install Go manually from: https://go.dev/dl/"
                ),
                "go_path": None,
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return self._verify_go_install(go_root, version, progress)

    # ==================================================================
    # Shared helpers
    # ==================================================================

    @staticmethod
    def _resolve_goarch(machine: str) -> Optional[str]:
        """Map platform.machine() to Go's GOARCH value."""
        return {
            "x86_64": "amd64",
            "amd64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
            "x86": "386",
            "i386": "386",
            "i686": "386",
        }.get(machine)

    @staticmethod
    def _unsupported_arch(machine: str) -> Dict[str, object]:
        return {
            "success": False,
            "message": (
                f"Unsupported architecture: {machine}\n"
                "Install Go manually from: https://go.dev/dl/"
            ),
            "go_path": None,
        }

    @staticmethod
    def _version_fetch_failed() -> Dict[str, object]:
        return {
            "success": False,
            "message": (
                "Could not determine latest Go version.\n"
                "Check your internet connection or install manually:\n"
                "  https://go.dev/dl/"
            ),
            "go_path": None,
        }

    @staticmethod
    def _download_failed(url: str, exc: Exception) -> Dict[str, object]:
        return {
            "success": False,
            "message": (
                f"Download failed: {exc}\n"
                f"URL: {url}\n"
                "Install Go manually from: https://go.dev/dl/"
            ),
            "go_path": None,
        }

    def _verify_go_install(
        self, go_root: str, version: str,
        progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Verify Go binary exists after extraction and add to PATH."""
        go_bin = os.path.join(go_root, "bin", "go" + _EXE)
        if not os.path.isfile(go_bin):
            return {
                "success": False,
                "message": (
                    f"Go binary not found at {go_bin} after extraction.\n"
                    "Install Go manually from: https://go.dev/dl/"
                ),
                "go_path": None,
            }

        go_bin_dir = os.path.join(go_root, "bin")
        current_path = os.environ.get("PATH", "")
        if go_bin_dir not in current_path.split(os.pathsep):
            os.environ["PATH"] = go_bin_dir + os.pathsep + current_path

        progress(f"Go {version} installed at: {go_root}")
        return {"success": True, "message": "Go installed.", "go_path": go_bin}

    def _fetch_go_version(
        self, progress: Callable[[str], None],
    ) -> Optional[str]:
        """Fetch the latest stable Go version string from go.dev."""
        progress("Fetching latest Go version...")
        return self._get_latest_go_version()

    @staticmethod
    def _get_latest_go_version() -> Optional[str]:
        """Query go.dev for the latest stable Go version string.

        Returns e.g. ``"go1.23.4"`` or *None* on failure.
        """
        try:
            req = urllib.request.Request(
                "https://go.dev/dl/?mode=json",
                headers={"User-Agent": "IOC-Extractor-GUI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data and isinstance(data, list):
                    return data[0].get("version")
        except Exception:
            pass

        # Fallback: simple text endpoint
        try:
            req = urllib.request.Request(
                "https://go.dev/VERSION?m=text",
                headers={"User-Agent": "IOC-Extractor-GUI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8").strip()
                version = text.splitlines()[0].strip()
                if version.startswith("go"):
                    return version
        except Exception:
            pass

        return None

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _gobin_candidates() -> List[str]:
        """Return directories where Go installs binaries."""
        dirs: List[str] = []
        gobin = os.environ.get("GOBIN")
        if gobin:
            dirs.append(gobin)

        home = str(Path.home())
        gopath = os.environ.get("GOPATH", os.path.join(home, "go"))
        gopath_bin = os.path.join(gopath, "bin")
        if gopath_bin not in dirs:
            dirs.append(gopath_bin)

        default = os.path.join(home, "go", "bin")
        if default not in dirs:
            dirs.append(default)

        return dirs

    @staticmethod
    def _run_cmd(
        cmd: list,
        timeout: int = 120,
        env: Optional[dict] = None,
    ) -> Dict[str, object]:
        """Run a subprocess command and return a structured result dict."""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
            )
            return {
                "success": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "return_code": -1,
            }
        except FileNotFoundError as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command not found: {exc}",
                "return_code": -1,
            }
        except Exception as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"{type(exc).__name__}: {exc}",
                "return_code": -1,
            }
