"""
nmap_handler.py - Nmap execution and XML output parsing.

Provides a handler class that builds nmap commands from user parameters,
runs them with timeout protection, and parses the XML output (-oX -)
into structured data (hosts, ports, services, OS detection).

sudo handling:
  - On macOS, ``sudo`` in a subprocess without a TTY cannot prompt for
    a password.  We use ``osascript`` to invoke the system password
    dialog which grants an authenticated sudo ticket.  Subsequent
    ``sudo`` calls within the ticket window then succeed silently.
  - On Linux / Windows, ``sudo`` is passed through directly
    (assumes the user has passwordless sudo or a cached ticket).
"""

import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

from .constants import NMAP_TIMEOUT

_IS_MACOS = platform.system() == "Darwin"
_IS_WINDOWS = os.name == "nt"


def _popen_group_kwargs() -> dict:
    """Launch nmap in a distinct process group/session so stop/timeout can kill children."""
    if _IS_WINDOWS:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return {"creationflags": flags} if flags else {}
    return {"start_new_session": True}


def _kill_process_tree(process: Optional[subprocess.Popen]) -> None:
    """Best-effort kill of subprocess and its process group."""
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


class NmapHandler:
    """Manages nmap command execution and result parsing."""

    def __init__(self):
        self._nmap_path = shutil.which("nmap")
        self._process: Optional[subprocess.Popen] = None  # for stop

    def stop(self):
        """Kill the currently running nmap process, if any."""
        proc = self._process
        if proc and proc.poll() is None:
            try:
                _kill_process_tree(proc)
            except Exception:
                pass
            self._process = None

    @property
    def available(self) -> bool:
        """True if nmap is found in PATH."""
        return self._nmap_path is not None

    @staticmethod
    def acquire_sudo() -> bool:
        """
        Ensure a sudo credential ticket is cached so that the next
        ``sudo`` call succeeds without a TTY prompt.

        On macOS this uses ``osascript`` to show the system password
        dialog.  On other platforms we attempt ``sudo -v`` which will
        succeed if the user already has a cached ticket.

        Returns True if sudo credentials are now available.
        """
        if _IS_MACOS:
            # Use osascript to show the native macOS password prompt.
            # "do shell script ... with administrator privileges"
            # caches a sudo ticket for the calling user.
            try:
                result = subprocess.run(
                    [
                        "osascript", "-e",
                        'do shell script "sudo -v" with administrator privileges',
                    ],
                    capture_output=True, text=True, timeout=120,
                )
                return result.returncode == 0
            except Exception:
                return False
        else:
            # On Linux, sudo -v refreshes the ticket if cached
            try:
                result = subprocess.run(
                    ["sudo", "-v"],
                    capture_output=True, text=True, timeout=10,
                )
                return result.returncode == 0
            except Exception:
                return False

    @staticmethod
    def check_sudo_cached() -> bool:
        """Check if sudo credentials are currently cached (non-interactive)."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def build_command(
        self,
        target: str,
        scan_type_flag: str = "",
        flags: list[str] | None = None,
        extra_args: str = "",
        use_sudo: bool = False,
        xml_output: str | None = "-",
    ) -> str:
        """
        Build an nmap command string.

        Parameters
        ----------
        target : str
            IP address, hostname, or CIDR range.
        scan_type_flag : str
            e.g. "-sS", "-sT", "-sV"
        flags : list[str]
            Additional flags like ["-Pn", "-T4"]
        extra_args : str
            Free-form extra arguments from the user.
        use_sudo : bool
            If True, prepend ``sudo`` to the command. Required for
            scan types like SYN (-sS), UDP (-sU), OS (-O), Aggressive (-A).

        Returns
        -------
        str
            Complete nmap command string.
        """
        parts = []
        if use_sudo:
            parts.append("sudo")
        parts.append("nmap")
        if scan_type_flag:
            parts.append(scan_type_flag)
        if flags:
            parts.extend(flags)
        # Optional XML output for structured parsing
        if xml_output is not None:
            parts.extend(["-oX", xml_output])
        if extra_args:
            parts.append(extra_args)
        parts.append(target)
        return " ".join(parts)

    def run(
        self,
        target: str,
        scan_type_flag: str = "",
        flags: list[str] | None = None,
        extra_args: str = "",
        use_sudo: bool = False,
        timeout: int = NMAP_TIMEOUT,
    ) -> dict:
        """
        Execute an nmap scan and return results.

        Parameters
        ----------
        use_sudo : bool
            If True, run nmap via ``sudo``. Required for privileged
            scan types (-sS, -sU, -O, -A).

        Returns
        -------
        dict with keys:
            - success : bool
            - command : str (the command that was run)
            - stdout : str (raw terminal output including ANSI)
            - stderr : str
            - xml_data : str (raw XML output, if parseable)
            - structured : dict | None (parsed scan results)
            - return_code : int
            - timed_out : bool
        """
        if not self.available:
            return {
                "success": False,
                "command": "",
                "stdout": "",
                "stderr": "nmap is not installed or not found in PATH.",
                "xml_data": "",
                "structured": None,
                "return_code": -1,
                "timed_out": False,
            }

        # Build user-visible command (no XML output flag shown)
        display_cmd = self.build_command(
            target,
            scan_type_flag,
            flags,
            extra_args,
            use_sudo=use_sudo,
            xml_output=None,
        )

        self._process = None
        timed_out = False
        stdout = ""
        stderr = ""
        return_code = -1
        xml_data = ""
        structured = None
        xml_path: str | None = None

        try:
            # Capture XML to a temp file while preserving normal stdout output.
            with tempfile.NamedTemporaryFile(
                prefix="ioc_nmap_",
                suffix=".xml",
                delete=False,
            ) as tmp_xml:
                xml_path = tmp_xml.name

            run_cmd = self.build_command(
                target,
                scan_type_flag,
                flags,
                extra_args,
                use_sudo=use_sudo,
                xml_output=shlex.quote(xml_path),
            )

            proc = subprocess.Popen(
                run_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **_popen_group_kwargs(),
            )
            self._process = proc

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                return_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except Exception:
                    pass
                return_code = proc.returncode if proc.returncode is not None else -9

        except Exception as exc:
            stderr = f"{type(exc).__name__}: {exc}"
            proc = self._process
            if proc and proc.poll() is None:
                try:
                    _kill_process_tree(proc)
                except Exception:
                    pass
        finally:
            self._process = None
            if xml_path:
                try:
                    if os.path.exists(xml_path):
                        with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
                            xml_data = fh.read()
                except Exception:
                    xml_data = ""
                finally:
                    try:
                        if os.path.exists(xml_path):
                            os.unlink(xml_path)
                    except OSError:
                        pass

        # Prefer XML-backed structured parsing; fall back to text parsing.
        if xml_data.strip():
            parsed = self.parse_xml(xml_data)
            if parsed.get("hosts"):
                structured = parsed

        if structured is None and return_code == 0 and not timed_out:
            structured = self._parse_text_output(stdout)

        return {
            "success": return_code == 0 and not timed_out,
            "command": display_cmd,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "xml_data": xml_data,
            "structured": structured,
            "return_code": return_code,
            "timed_out": timed_out,
        }

    def run_xml(
        self,
        target: str,
        scan_type_flag: str = "",
        flags: list[str] | None = None,
        extra_args: str = "",
        timeout: int = NMAP_TIMEOUT,
    ) -> dict | None:
        """
        Run nmap with XML output and parse results.

        Returns parsed structured data dict, or None on failure.
        """
        if not self.available:
            return None
        result = self.run(
            target=target,
            scan_type_flag=scan_type_flag,
            flags=flags,
            extra_args=extra_args,
            timeout=timeout,
        )
        xml_data = str(result.get("xml_data") or "")
        if xml_data.strip():
            parsed = self.parse_xml(xml_data)
            if parsed.get("hosts") or parsed.get("scan_info"):
                return parsed
        structured = result.get("structured")
        return structured if isinstance(structured, dict) else None

    def parse_xml(self, xml_string: str) -> dict:
        """
        Parse nmap XML output into structured data.

        Parameters
        ----------
        xml_string : str
            Raw XML output from nmap -oX.

        Returns
        -------
        dict with:
            - hosts : list of host dicts
            - scan_info : dict with scan metadata
        """
        result = {"hosts": [], "scan_info": {}}

        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError:
            return result

        # Scan info
        run_elem = root
        if run_elem is not None:
            result["scan_info"] = {
                "scanner": run_elem.get("scanner", "nmap"),
                "args": run_elem.get("args", ""),
                "start_str": run_elem.get("startstr", ""),
            }

        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                result["scan_info"]["elapsed"] = finished.get("elapsed", "")
                result["scan_info"]["exit"] = finished.get("exit", "")
            hosts_elem = runstats.find("hosts")
            if hosts_elem is not None:
                result["scan_info"]["hosts_up"] = hosts_elem.get("up", "0")
                result["scan_info"]["hosts_down"] = hosts_elem.get("down", "0")
                result["scan_info"]["hosts_total"] = hosts_elem.get("total", "0")

        # Hosts
        for host_elem in root.findall("host"):
            host = {
                "address": "",
                "hostname": "",
                "status": "",
                "ports": [],
                "os": [],
            }

            # Status
            status = host_elem.find("status")
            if status is not None:
                host["status"] = status.get("state", "unknown")

            # Address
            addr = host_elem.find("address")
            if addr is not None:
                host["address"] = addr.get("addr", "")

            # Hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host["hostname"] = hn.get("name", "")

            # Ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port = {
                        "port": int(port_elem.get("portid", "0")),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "state": "",
                        "service": "",
                        "version": "",
                    }
                    state_elem = port_elem.find("state")
                    if state_elem is not None:
                        port["state"] = state_elem.get("state", "")
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        port["service"] = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        if product:
                            port["version"] = f"{product} {version}".strip()
                    host["ports"].append(port)

            # OS detection
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for osmatch in os_elem.findall("osmatch"):
                    host["os"].append({
                        "name": osmatch.get("name", ""),
                        "accuracy": int(osmatch.get("accuracy", "0")),
                    })

            result["hosts"].append(host)

        return result

    def _parse_text_output(self, text: str) -> dict | None:
        """
        Parse nmap's normal text output for basic structured data.

        This is a fallback when XML parsing isn't available. Extracts
        open ports and basic host info from standard nmap output.
        """
        if not text:
            return None

        result = {"hosts": [], "scan_info": {}}
        current_host = None
        in_port_table = False

        for line in text.splitlines():
            stripped = line.strip()

            # Nmap scan report header
            if stripped.startswith("Nmap scan report for"):
                if current_host:
                    result["hosts"].append(current_host)
                current_host = {
                    "address": "",
                    "hostname": "",
                    "status": "up",
                    "ports": [],
                    "os": [],
                }
                # Parse "Nmap scan report for hostname (ip)" or just "... for ip"
                rest = stripped[len("Nmap scan report for "):]
                if "(" in rest and ")" in rest:
                    hostname = rest[:rest.index("(")].strip()
                    ip = rest[rest.index("(") + 1:rest.index(")")].strip()
                    current_host["hostname"] = hostname
                    current_host["address"] = ip
                else:
                    current_host["address"] = rest.strip()
                in_port_table = False

            # Host is up
            elif stripped.startswith("Host is up"):
                if current_host:
                    current_host["status"] = "up"

            # PORT STATE SERVICE VERSION header
            elif stripped.startswith("PORT") and "STATE" in stripped:
                in_port_table = True

            # Port line: "22/tcp open ssh OpenSSH 8.9"
            elif in_port_table and current_host and "/" in stripped[:10]:
                parts = stripped.split(None, 3)
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    if len(port_proto) == 2:
                        try:
                            port_num = int(port_proto[0])
                        except ValueError:
                            continue
                        port = {
                            "port": port_num,
                            "protocol": port_proto[1],
                            "state": parts[1],
                            "service": parts[2] if len(parts) > 2 else "",
                            "version": parts[3] if len(parts) > 3 else "",
                        }
                        current_host["ports"].append(port)

            # Blank line ends port table
            elif not stripped and in_port_table:
                in_port_table = False

            # Scan timing
            elif stripped.startswith("Nmap done:"):
                # "Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds"
                if "scanned in" in stripped:
                    try:
                        elapsed = stripped.split("scanned in")[1].strip().split()[0]
                        result["scan_info"]["elapsed"] = elapsed
                    except (IndexError, ValueError):
                        pass

        if current_host:
            result["hosts"].append(current_host)

        return result if result["hosts"] else None

    def format_structured(self, structured: dict) -> str:
        """
        Format structured scan results for display in the structured
        data pane.  Each port is displayed as a vertical card with
        labelled fields on separate lines for easy scanning.

        Returns a human-readable formatted string.
        """
        if not structured:
            return "No structured data available."

        lines: list[str] = []

        # Scan info
        info = structured.get("scan_info", {})
        if info.get("elapsed"):
            lines.append(f"Scan completed in {info['elapsed']} seconds")
        if info.get("hosts_up"):
            lines.append(
                f"Hosts: {info.get('hosts_up', '?')} up, "
                f"{info.get('hosts_down', '?')} down "
                f"({info.get('hosts_total', '?')} total)"
            )
        if lines:
            lines.append("")

        # Hosts
        for host in structured.get("hosts", []):
            addr = host.get("address", "unknown")
            hostname = host.get("hostname", "")
            status = host.get("status", "unknown")

            header = f"Host: {addr}"
            if hostname:
                header += f" ({hostname})"
            header += f" — {status.upper()}"
            lines.append(header)
            lines.append("=" * len(header))

            # Ports — vertical card layout
            ports = host.get("ports", [])
            if ports:
                for i, p in enumerate(ports):
                    port_str = f"{p['port']}/{p['protocol']}"
                    lines.append(f"  Port:     {port_str}")
                    lines.append(f"  State:    {p['state']}")
                    lines.append(f"  Service:  {p['service']}")
                    version = p.get("version", "")
                    if version:
                        lines.append(f"  Version:  {version}")
                    # Separator between port cards (not after last)
                    if i < len(ports) - 1:
                        lines.append("  ---")
            else:
                lines.append("  No open ports detected.")

            # OS
            os_matches = host.get("os", [])
            if os_matches:
                lines.append("")
                lines.append("  OS Detection:")
                for os_info in os_matches:
                    lines.append(
                        f"    {os_info['name']} "
                        f"(accuracy: {os_info['accuracy']}%)"
                    )

            lines.append("")

        return "\n".join(lines)

    def structured_to_json(self, structured: dict) -> str:
        """Serialize structured scan results to JSON."""
        return json.dumps(structured, indent=2)
