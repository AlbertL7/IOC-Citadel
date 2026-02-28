"""
nmap_installer.py - Automated cross-platform nmap installation.

Handles detection of nmap and installation via package managers or
official downloads for all three major platforms.

Supported platforms:
  - macOS (Darwin): Homebrew → official .dmg installer
  - Linux: apt-get → dnf/yum → pacman → snap → official RPM/DEB
  - Windows: Chocolatey → Scoop → Winget → official installer download
"""

import glob
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .constants import NMAP_INSTALL_TIMEOUT

_IS_WINDOWS = platform.system() == "Windows"
_IS_MACOS = platform.system() == "Darwin"
_EXE = ".exe" if _IS_WINDOWS else ""


class NmapInstaller:
    """Handles nmap detection and cross-platform installation.

    All public methods are safe to call from any platform.
    """

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def find_nmap() -> Optional[str]:
        """Locate the nmap binary on any platform.

        Checks ``shutil.which`` first, then probes well-known
        installation directories per-OS.
        """
        nmap = shutil.which("nmap")
        if nmap:
            return nmap

        if _IS_WINDOWS:
            candidates = [
                os.path.join(
                    os.environ.get("ProgramFiles", r"C:\Program Files"),
                    "Nmap", "nmap.exe",
                ),
                os.path.join(
                    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                    "Nmap", "nmap.exe",
                ),
                r"C:\Nmap\nmap.exe",
                os.path.join(str(Path.home()), "Nmap", "nmap.exe"),
            ]
            # Scoop installs
            scoop_nmap = glob.glob(
                os.path.join(
                    str(Path.home()), "scoop", "apps", "nmap", "*", "nmap.exe"
                )
            )
            if scoop_nmap:
                candidates.insert(0, sorted(scoop_nmap)[-1])

            # Chocolatey installs
            choco_nmap = glob.glob(
                os.path.join(
                    os.environ.get("ChocolateyInstall", r"C:\ProgramData\chocolatey"),
                    "lib", "nmap", "tools", "nmap.exe",
                )
            )
            if choco_nmap:
                candidates.insert(0, sorted(choco_nmap)[-1])

        elif _IS_MACOS:
            candidates = [
                "/opt/homebrew/bin/nmap",       # Homebrew (Apple Silicon)
                "/usr/local/bin/nmap",          # Homebrew (Intel) / manual install
                "/opt/local/bin/nmap",          # MacPorts
            ]
            # Homebrew cellar
            brew_nmap = glob.glob("/opt/homebrew/Cellar/nmap/*/bin/nmap")
            if brew_nmap:
                candidates.insert(0, sorted(brew_nmap)[-1])

        else:
            # Linux
            candidates = [
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/snap/bin/nmap",
                os.path.join(str(Path.home()), ".local", "bin", "nmap"),
            ]

        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK | os.F_OK):
                return c

        return None

    @staticmethod
    def get_nmap_version(nmap_path: str) -> Optional[str]:
        """Get the installed nmap version string."""
        try:
            result = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                # First line is like "Nmap version 7.95 ( https://nmap.org )"
                for line in result.stdout.splitlines():
                    if "nmap version" in line.lower():
                        return line.strip()
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Installation — public entry points
    # ------------------------------------------------------------------

    def install_nmap(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Install nmap via package manager or direct download.

        Strategy per platform:
          - macOS:   Homebrew → MacPorts → manual instructions
          - Linux:   apt-get → dnf/yum → pacman → snap → zypper
          - Windows: Chocolatey → Scoop → Winget → direct download

        Returns ``{success: bool, message: str, nmap_path: str|None}``.
        """
        system = platform.system()

        if system == "Darwin":
            return self._install_nmap_darwin(progress)
        elif system == "Linux":
            return self._install_nmap_linux(progress)
        elif system == "Windows":
            return self._install_nmap_windows(progress)
        else:
            return {
                "success": False,
                "message": (
                    f"Auto-install not supported on {system}.\n"
                    "Install nmap manually from: https://nmap.org/download\n"
                    "Then restart the application."
                ),
                "nmap_path": None,
            }

    def full_install(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Orchestrate the complete nmap installation.

        1. Check if nmap already exists.
        2. Install nmap via platform-appropriate method.
        3. Verify and return.
        """
        # Step 1: Check if already installed
        progress("Checking for existing nmap installation...")
        existing = self.find_nmap()
        if existing:
            version = self.get_nmap_version(existing) or "unknown version"
            progress(f"nmap already installed: {version}")
            return {
                "success": True,
                "message": f"nmap already installed at: {existing}\n{version}",
                "nmap_path": existing,
            }

        # Step 2: Install nmap
        progress("nmap not found. Attempting to install...")
        result = self.install_nmap(progress)

        # Step 3: Verify
        if result["success"]:
            nmap_path = result.get("nmap_path") or self.find_nmap()
            if nmap_path:
                version = self.get_nmap_version(nmap_path) or ""
                if version:
                    progress(f"Installed: {version}")
                result["nmap_path"] = nmap_path

        return result

    # ==================================================================
    # Platform-specific nmap installation
    # ==================================================================

    # --- macOS (Darwin) -----------------------------------------------

    def _install_nmap_darwin(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """macOS: Homebrew → MacPorts → manual instructions."""
        # 1. Homebrew
        brew = shutil.which("brew")
        if not brew:
            for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
                if os.path.isfile(p):
                    brew = p
                    break

        if brew:
            progress("Installing nmap via Homebrew (this may take a few minutes)...")
            result = self._run_cmd(
                [brew, "install", "nmap"], timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via Homebrew.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via Homebrew.",
                        "nmap_path": nmap_path,
                    }
            progress("Homebrew install failed, trying MacPorts...")

        # 2. MacPorts
        port = shutil.which("port")
        if not port:
            if os.path.isfile("/opt/local/bin/port"):
                port = "/opt/local/bin/port"

        if port:
            progress("Installing nmap via MacPorts...")
            result = self._run_cmd(
                ["sudo", port, "install", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via MacPorts.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via MacPorts.",
                        "nmap_path": nmap_path,
                    }
            progress("MacPorts install failed...")

        # 3. Manual instructions
        return {
            "success": False,
            "message": (
                "Could not install nmap automatically on macOS.\n\n"
                "Please install manually using one of these methods:\n"
                "  1. Install Homebrew (https://brew.sh) then run:\n"
                "       brew install nmap\n"
                "  2. Download the official installer from:\n"
                "       https://nmap.org/download#macosx\n\n"
                "After installing, restart the application."
            ),
            "nmap_path": None,
        }

    # --- Linux --------------------------------------------------------

    def _install_nmap_linux(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Linux: apt-get → dnf/yum → pacman → snap → zypper → apk."""
        # 1. apt-get (Debian / Ubuntu / Kali)
        apt = shutil.which("apt-get")
        if apt:
            progress("Installing nmap via apt-get...")
            # Update package list first
            self._run_cmd(
                ["sudo", apt, "update", "-y"], timeout=60,
            )
            result = self._run_cmd(
                ["sudo", apt, "install", "-y", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via apt-get.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via apt-get.",
                        "nmap_path": nmap_path,
                    }
                progress("apt install succeeded but nmap binary not found, continuing...")

        # 2. dnf (Fedora / RHEL 8+ / CentOS Stream)
        dnf = shutil.which("dnf")
        if dnf:
            progress("Installing nmap via dnf...")
            result = self._run_cmd(
                ["sudo", dnf, "install", "-y", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via dnf.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via dnf.",
                        "nmap_path": nmap_path,
                    }

        # 3. yum (RHEL 7 / CentOS 7 / older)
        if not dnf:
            yum = shutil.which("yum")
            if yum:
                progress("Installing nmap via yum...")
                result = self._run_cmd(
                    ["sudo", yum, "install", "-y", "nmap"],
                    timeout=NMAP_INSTALL_TIMEOUT,
                )
                if result["success"]:
                    progress("nmap installed via yum.")
                    nmap_path = self.find_nmap()
                    if nmap_path:
                        return {
                            "success": True,
                            "message": "nmap installed via yum.",
                            "nmap_path": nmap_path,
                        }

        # 4. pacman (Arch / Manjaro)
        pacman = shutil.which("pacman")
        if pacman:
            progress("Installing nmap via pacman...")
            result = self._run_cmd(
                ["sudo", pacman, "-S", "--noconfirm", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via pacman.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via pacman.",
                        "nmap_path": nmap_path,
                    }

        # 5. snap
        snap = shutil.which("snap")
        if snap:
            progress("Installing nmap via snap...")
            result = self._run_cmd(
                ["sudo", snap, "install", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via snap.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via snap.",
                        "nmap_path": nmap_path,
                    }

        # 6. zypper (openSUSE)
        zypper = shutil.which("zypper")
        if zypper:
            progress("Installing nmap via zypper...")
            result = self._run_cmd(
                ["sudo", zypper, "--non-interactive", "install", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via zypper.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via zypper.",
                        "nmap_path": nmap_path,
                    }

        # 7. apk (Alpine Linux)
        apk = shutil.which("apk")
        if apk:
            progress("Installing nmap via apk...")
            result = self._run_cmd(
                ["sudo", apk, "add", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via apk.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via apk.",
                        "nmap_path": nmap_path,
                    }

        # Fallback
        return {
            "success": False,
            "message": (
                "Could not install nmap automatically on Linux.\n\n"
                "Please install manually using your package manager:\n"
                "  Debian/Ubuntu/Kali:  sudo apt install nmap\n"
                "  Fedora/RHEL:         sudo dnf install nmap\n"
                "  Arch/Manjaro:        sudo pacman -S nmap\n"
                "  openSUSE:            sudo zypper install nmap\n"
                "  Alpine:              sudo apk add nmap\n\n"
                "Or download from: https://nmap.org/download\n"
                "After installing, restart the application."
            ),
            "nmap_path": None,
        }

    # --- Windows ------------------------------------------------------

    def _install_nmap_windows(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Windows: Chocolatey → Scoop → Winget → direct download."""
        # 1. Chocolatey
        choco = shutil.which("choco")
        if choco:
            progress("Installing nmap via Chocolatey...")
            result = self._run_cmd(
                [choco, "install", "nmap", "-y"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via Chocolatey.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via Chocolatey.",
                        "nmap_path": nmap_path,
                    }
                progress("Chocolatey install succeeded but nmap not found, continuing...")

        # 2. Scoop
        scoop = shutil.which("scoop")
        if scoop:
            progress("Installing nmap via Scoop...")
            # nmap is in the extras bucket
            self._run_cmd([scoop, "bucket", "add", "extras"], timeout=60)
            result = self._run_cmd(
                [scoop, "install", "nmap"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via Scoop.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via Scoop.",
                        "nmap_path": nmap_path,
                    }

        # 3. Winget
        winget = shutil.which("winget")
        if winget:
            progress("Installing nmap via Winget...")
            result = self._run_cmd(
                [winget, "install", "--id", "Insecure.Nmap",
                 "--accept-source-agreements", "--accept-package-agreements"],
                timeout=NMAP_INSTALL_TIMEOUT,
            )
            if result["success"]:
                progress("nmap installed via Winget.")
                nmap_path = self.find_nmap()
                if nmap_path:
                    return {
                        "success": True,
                        "message": "nmap installed via Winget.",
                        "nmap_path": nmap_path,
                    }

        # 4. Direct download
        progress("Package managers failed or unavailable, trying direct download...")
        return self._install_nmap_windows_direct(progress)

    def _install_nmap_windows_direct(
        self, progress: Callable[[str], None],
    ) -> Dict[str, object]:
        """Download the official nmap Windows zip and extract it.

        Falls back to portable zip installation at
        %LOCALAPPDATA%\\Nmap or C:\\Nmap.
        """
        machine = platform.machine().lower()

        # Nmap provides a single Windows zip that works on both x86 and x64
        # Try to fetch the latest version from the download page
        zip_url = self._get_nmap_windows_zip_url(progress)
        if not zip_url:
            return {
                "success": False,
                "message": (
                    "Could not determine nmap download URL.\n\n"
                    "Please install manually from:\n"
                    "  https://nmap.org/download#windows\n\n"
                    "After installing, restart the application."
                ),
                "nmap_path": None,
            }

        filename = zip_url.rsplit("/", 1)[-1]
        progress(f"Downloading {filename}...")

        tmp_dir = tempfile.mkdtemp(prefix="nmap_install_")
        archive_path = os.path.join(tmp_dir, filename)
        try:
            req = urllib.request.Request(
                zip_url,
                headers={"User-Agent": "IOC-Extractor-GUI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(archive_path, "wb") as f:
                    f.write(resp.read())
        except (urllib.error.URLError, OSError) as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return {
                "success": False,
                "message": (
                    f"Download failed: {exc}\n"
                    f"URL: {zip_url}\n\n"
                    "Install nmap manually from: https://nmap.org/download"
                ),
                "nmap_path": None,
            }

        # Choose install location
        install_dir = os.path.join(
            os.environ.get("LOCALAPPDATA",
                           os.path.join(str(Path.home()), "AppData", "Local")),
            "Nmap",
        )

        progress(f"Extracting to {install_dir}...")
        try:
            os.makedirs(install_dir, exist_ok=True)

            with zipfile.ZipFile(archive_path, "r") as zf:
                # The zip typically contains a top-level nmap-X.XX/ directory
                top_dirs = {n.split("/")[0] for n in zf.namelist() if "/" in n}
                zf.extractall(path=tmp_dir)

            # Find the extracted nmap directory
            extracted_dir = None
            for d in sorted(top_dirs):
                candidate = os.path.join(tmp_dir, d)
                if os.path.isdir(candidate) and os.path.isfile(
                    os.path.join(candidate, "nmap.exe")
                ):
                    extracted_dir = candidate
                    break

            if not extracted_dir:
                # Maybe files are at the root of the zip
                if os.path.isfile(os.path.join(tmp_dir, "nmap.exe")):
                    extracted_dir = tmp_dir

            if not extracted_dir:
                return {
                    "success": False,
                    "message": (
                        "Extraction succeeded but nmap.exe not found in archive.\n"
                        "Install nmap manually from: https://nmap.org/download"
                    ),
                    "nmap_path": None,
                }

            # Copy contents to install_dir
            for item in os.listdir(extracted_dir):
                src = os.path.join(extracted_dir, item)
                dst = os.path.join(install_dir, item)
                if os.path.exists(dst):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst, ignore_errors=True)
                    else:
                        os.remove(dst)
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)

        except Exception as exc:
            return {
                "success": False,
                "message": (
                    f"Extraction failed: {exc}\n"
                    "Install nmap manually from: https://nmap.org/download"
                ),
                "nmap_path": None,
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Add to PATH for this process
        nmap_exe = os.path.join(install_dir, "nmap.exe")
        if os.path.isfile(nmap_exe):
            current_path = os.environ.get("PATH", "")
            if install_dir not in current_path.split(os.pathsep):
                os.environ["PATH"] = install_dir + os.pathsep + current_path

            progress(f"nmap installed at: {install_dir}")
            return {
                "success": True,
                "message": (
                    f"nmap installed to: {install_dir}\n\n"
                    "Note: To make nmap available system-wide, add this\n"
                    f"directory to your PATH: {install_dir}"
                ),
                "nmap_path": nmap_exe,
            }

        return {
            "success": False,
            "message": (
                f"nmap.exe not found at {nmap_exe} after extraction.\n"
                "Install nmap manually from: https://nmap.org/download"
            ),
            "nmap_path": None,
        }

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _get_nmap_windows_zip_url(
        progress: Callable[[str], None],
    ) -> Optional[str]:
        """Determine the download URL for the latest nmap Windows zip.

        Scrapes the nmap download page for the latest portable zip link.
        Falls back to a known-good version if scraping fails.
        """
        progress("Checking latest nmap version...")
        try:
            req = urllib.request.Request(
                "https://nmap.org/dist/",
                headers={"User-Agent": "IOC-Extractor-GUI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            # Look for the latest nmap-X.XX-setup.zip or nmap-X.XX-win32.zip
            import re
            # Match patterns like nmap-7.95-win32.zip
            matches = re.findall(
                r'href="(nmap-[\d.]+(?:-win32)?\.zip)"', html
            )
            if matches:
                latest = sorted(matches)[-1]
                return f"https://nmap.org/dist/{latest}"

        except Exception:
            pass

        # Fallback: try a known pattern for the latest stable
        try:
            req = urllib.request.Request(
                "https://nmap.org/download",
                headers={"User-Agent": "IOC-Extractor-GUI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            import re
            # Look for direct zip link on download page
            matches = re.findall(
                r'href="(https://nmap\.org/dist/nmap-[\d.]+-win32\.zip)"', html
            )
            if matches:
                return matches[0]

            # Also try setup.zip pattern
            matches = re.findall(
                r'href="(https://nmap\.org/dist/nmap-[\d.]+(?:-setup)?\.zip)"', html
            )
            if matches:
                return matches[0]

        except Exception:
            pass

        return None

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
