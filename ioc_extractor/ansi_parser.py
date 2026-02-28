"""
ansi_parser.py - ANSI escape code → tkinter text tag mapper.

Parses ANSI SGR (Select Graphic Rendition) escape sequences from
command output and converts them into tkinter text widget tag
operations, rendering colored terminal output in the GUI.

Usage:
    from .ansi_parser import setup_ansi_tags, insert_ansi_text

    setup_ansi_tags(text_widget)        # call once after widget creation
    insert_ansi_text(text_widget, raw)  # insert ANSI-colored text
"""

import re
import tkinter as tk

from .constants import ANSI_COLORS, FONTS, NMAP_COLORS

# Regex matching any ANSI CSI SGR sequence: ESC [ <params> m
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

# Standard ANSI foreground codes → tag names
_FG_MAP = {
    30: "ansi_black",   31: "ansi_red",     32: "ansi_green",
    33: "ansi_yellow",  34: "ansi_blue",    35: "ansi_magenta",
    36: "ansi_cyan",    37: "ansi_white",
    90: "ansi_bright_black",  91: "ansi_bright_red",
    92: "ansi_bright_green",  93: "ansi_bright_yellow",
    94: "ansi_bright_blue",   95: "ansi_bright_magenta",
    96: "ansi_bright_cyan",   97: "ansi_bright_white",
}

# Standard ANSI background codes → tag names
_BG_MAP = {
    40: "ansi_bg_black",   41: "ansi_bg_red",     42: "ansi_bg_green",
    43: "ansi_bg_yellow",  44: "ansi_bg_blue",    45: "ansi_bg_magenta",
    46: "ansi_bg_cyan",    47: "ansi_bg_white",
    100: "ansi_bg_bright_black",  101: "ansi_bg_bright_red",
    102: "ansi_bg_bright_green",  103: "ansi_bg_bright_yellow",
    104: "ansi_bg_bright_blue",   105: "ansi_bg_bright_magenta",
    106: "ansi_bg_bright_cyan",   107: "ansi_bg_bright_white",
}

# Map background code → corresponding foreground color key for reuse
_BG_COLOR_MAP = {
    40: "ansi_black",   41: "ansi_red",     42: "ansi_green",
    43: "ansi_yellow",  44: "ansi_blue",    45: "ansi_magenta",
    46: "ansi_cyan",    47: "ansi_white",
    100: "ansi_bright_black",  101: "ansi_bright_red",
    102: "ansi_bright_green",  103: "ansi_bright_yellow",
    104: "ansi_bright_blue",   105: "ansi_bright_magenta",
    106: "ansi_bright_cyan",   107: "ansi_bright_white",
}


def setup_ansi_tags(widget):
    """
    Configure ANSI color tags on a tkinter Text widget.

    Must be called once after widget creation, before using
    insert_ansi_text().
    """
    # Foreground color tags
    for tag_name, color in ANSI_COLORS.items():
        widget.tag_configure(tag_name, foreground=color)

    # Background color tags
    for code, tag_name in _BG_MAP.items():
        fg_key = _BG_COLOR_MAP[code]
        color = ANSI_COLORS.get(fg_key, "#ffffff")
        widget.tag_configure(tag_name, background=color)

    # Bold tag
    widget.tag_configure("ansi_bold", font=FONTS.get("category_header", FONTS["mono"]))

    # Underline tag
    widget.tag_configure("ansi_underline", underline=True)

    # Dim / faint tag
    widget.tag_configure("ansi_dim", foreground=ANSI_COLORS.get("ansi_bright_black", "#6b7280"))


def insert_ansi_text(widget, text, base_tag=None):
    """
    Insert text into a tkinter Text widget, converting ANSI escape
    codes into colored tag regions.

    Parameters
    ----------
    widget : tk.Text or ScrolledText
        The target text widget (must have had setup_ansi_tags() called).
    text : str
        Raw text potentially containing ANSI escape sequences.
    base_tag : str, optional
        A base tag to apply to all inserted text in addition to ANSI tags.
    """
    if not text:
        return

    # Current active tags derived from ANSI state
    active_fg = None
    active_bg = None
    active_attrs = set()  # "ansi_bold", "ansi_underline", "ansi_dim"

    pos = 0
    for match in _ANSI_RE.finditer(text):
        # Insert text before this escape sequence
        before = text[pos:match.start()]
        if before:
            tags = _build_tags(active_fg, active_bg, active_attrs, base_tag)
            widget.insert(tk.END, before, tags if tags else "")

        # Parse the SGR parameters
        params_str = match.group(1)
        if not params_str:
            # ESC[m is equivalent to ESC[0m (reset)
            active_fg = None
            active_bg = None
            active_attrs.clear()
        else:
            codes = [int(c) for c in params_str.split(";") if c]
            i = 0
            while i < len(codes):
                code = codes[i]

                if code == 0:
                    # Reset
                    active_fg = None
                    active_bg = None
                    active_attrs.clear()
                elif code == 1:
                    active_attrs.add("ansi_bold")
                elif code == 2:
                    active_attrs.add("ansi_dim")
                elif code == 4:
                    active_attrs.add("ansi_underline")
                elif code == 22:
                    active_attrs.discard("ansi_bold")
                    active_attrs.discard("ansi_dim")
                elif code == 24:
                    active_attrs.discard("ansi_underline")
                elif code in _FG_MAP:
                    active_fg = _FG_MAP[code]
                elif code in _BG_MAP:
                    active_bg = _BG_MAP[code]
                elif code == 39:
                    active_fg = None  # Default fg
                elif code == 49:
                    active_bg = None  # Default bg
                elif code == 38:
                    # Extended foreground: 38;5;N or 38;2;R;G;B
                    active_fg, i = _parse_extended_color(codes, i, is_fg=True)
                elif code == 48:
                    # Extended background: 48;5;N or 48;2;R;G;B
                    active_bg, i = _parse_extended_color(codes, i, is_fg=False)

                i += 1

        pos = match.end()

    # Insert remaining text after last escape sequence
    remaining = text[pos:]
    if remaining:
        tags = _build_tags(active_fg, active_bg, active_attrs, base_tag)
        widget.insert(tk.END, remaining, tags if tags else "")


def strip_ansi(text: str) -> str:
    """Remove all ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


# ==================================================================
# Nmap syntax highlighting (nmap produces plain text, no ANSI codes)
# ==================================================================

# Regex to split a port line into segments:
#   22/tcp   open  ssh        OpenSSH 8.9
_PORT_LINE_RE = re.compile(
    r"^(\d+)/(tcp|udp|sctp)"
    r"(\s+)"
    r"(open\|filtered|open|closed|filtered|unfiltered)"
    r"(\s+)"
    r"(\S+)"
    r"(.*)",
    re.IGNORECASE,
)

# State string → tag name
_STATE_TAG = {
    "open": "nmap_open",
    "closed": "nmap_closed",
    "filtered": "nmap_filtered",
    "open|filtered": "nmap_open_filtered",
    "unfiltered": "nmap_filtered",
}

# NSE script output: |  or |_  lines  →  "|_http-title: Apache"
_SCRIPT_LINE_RE = re.compile(
    r"^(\|[_\s]?)"              # pipe prefix
    r"(\s*)"                    # optional space
    r"([a-zA-Z][\w\-]*:)?"     # optional script-name: label
    r"(.*)",                    # data
)

# Traceroute hop line:  "1   0.45 ms  192.168.1.1"
_TRACEROUTE_HOP_RE = re.compile(
    r"^(\d{1,3})"              # hop number
    r"(\s+)"
    r"([\d.]+\s*ms)"           # RTT
    r"(\s+)"
    r"(.*)",                   # host / IP
)

# Host-is-up with latency:  "Host is up (0.015s latency)."
_HOST_UP_LATENCY_RE = re.compile(
    r"^(Host is up\s*)"
    r"(\([\d.]+s? latency\))"
    r"(.*)",
)

# Nmap scan report with hostname + IP
_SCAN_REPORT_RE = re.compile(
    r"^(Nmap scan report for\s+)"
    r"(\S+)"                    # hostname or IP
    r"(\s*\([\d.]+\))?"         # optional (IP)
    r"(.*)",
)

# MAC Address line with vendor
_MAC_RE = re.compile(
    r"^(MAC Address:\s+)"
    r"([0-9A-Fa-f:]+)"          # MAC
    r"(\s*\(.*\))?"             # optional (vendor)
    r"(.*)",
)

# Nmap done summary
_DONE_RE = re.compile(
    r"^(Nmap done:\s+)"
    r"(.*)",
)


def setup_nmap_tags(widget):
    """Configure nmap-specific color tags on a tkinter Text widget."""
    for tag_name, color in NMAP_COLORS.items():
        if tag_name in ("nmap_header", "nmap_traceroute_hdr"):
            widget.tag_configure(
                tag_name, foreground=color,
                font=FONTS.get("category_header", FONTS["mono"]),
            )
        else:
            widget.tag_configure(tag_name, foreground=color)


def _insert_port_card(widget, port, proto, state, service, version):
    """Insert a single port as a vertical card block."""
    widget.insert(tk.END, "  ")
    widget.insert(tk.END, "Port:     ", ("nmap_struct_label",))
    widget.insert(tk.END, port, ("nmap_port",))
    widget.insert(tk.END, "/")
    widget.insert(tk.END, proto, ("nmap_protocol",))
    widget.insert(tk.END, "\n")

    widget.insert(tk.END, "  ")
    widget.insert(tk.END, "State:    ", ("nmap_struct_label",))
    state_tag = _STATE_TAG.get(state.lower(), "nmap_filtered")
    widget.insert(tk.END, state, (state_tag,))
    widget.insert(tk.END, "\n")

    widget.insert(tk.END, "  ")
    widget.insert(tk.END, "Service:  ", ("nmap_struct_label",))
    widget.insert(tk.END, service, ("nmap_service",))
    widget.insert(tk.END, "\n")

    if version:
        widget.insert(tk.END, "  ")
        widget.insert(tk.END, "Version:  ", ("nmap_struct_label",))
        widget.insert(tk.END, version, ("nmap_version",))
        widget.insert(tk.END, "\n")


def _insert_script_line(widget, raw_line):
    """Insert an NSE script output line with pipe / name / data coloring."""
    # Separate trailing newline
    has_nl = raw_line.endswith("\n")
    line_content = raw_line.rstrip("\n")
    stripped = line_content.lstrip()
    leading = line_content[:len(line_content) - len(stripped)]

    m = _SCRIPT_LINE_RE.match(stripped)
    if not m:
        widget.insert(tk.END, line_content, ("nmap_script_data",))
        if has_nl:
            widget.insert(tk.END, "\n")
        return

    pipe, space, name, data = m.groups()

    if leading:
        widget.insert(tk.END, leading)
    widget.insert(tk.END, pipe, ("nmap_script_pipe",))
    if space:
        widget.insert(tk.END, space)
    if name:
        widget.insert(tk.END, name, ("nmap_script_name",))
    if data:
        widget.insert(tk.END, data, ("nmap_script_data",))
    if has_nl:
        widget.insert(tk.END, "\n")


def insert_nmap_highlighted(widget, text, base_tag=None):
    """
    Insert nmap output with comprehensive per-segment syntax
    highlighting.  Port lines are reformatted into vertical cards.
    Script output, traceroute hops, latency, MAC addresses, OS
    details, and all other nmap output types are colorized.
    """
    if not text:
        return
    if "\x1b[" in text:
        insert_ansi_text(widget, text, base_tag)
        return

    lines = text.splitlines(keepends=True)
    idx = 0
    port_count = 0
    in_traceroute = False

    while idx < len(lines):
        raw_line = lines[idx]
        stripped = raw_line.lstrip()
        bare = stripped.rstrip("\n")

        # ----- PORT table header — skip (cards replace it) -----
        if re.match(r"^PORT\s+STATE\s+SERVICE", bare, re.IGNORECASE):
            idx += 1
            if idx < len(lines) and re.match(r"^[\s\-]+$", lines[idx]):
                idx += 1
            port_count = 0
            in_traceroute = False
            continue

        # ----- Port line → vertical card -----
        m = _PORT_LINE_RE.match(bare)
        if m:
            in_traceroute = False
            port, proto, _, state, _, service, version = m.groups()
            version = version.strip()
            if port_count > 0:
                widget.insert(tk.END, "  ---\n", ("nmap_struct_sep",))
            _insert_port_card(widget, port, proto, state, service, version)

            # Collect any following |  script lines belonging to this port
            idx += 1
            while idx < len(lines):
                nxt = lines[idx].lstrip()
                if nxt.startswith("|") or nxt.startswith("| "):
                    widget.insert(tk.END, "  ")
                    _insert_script_line(widget, lines[idx])
                    idx += 1
                else:
                    break
            port_count += 1
            continue

        # Flush port card spacing
        if port_count > 0:
            widget.insert(tk.END, "\n")
            port_count = 0

        # ----- Nmap scan report for … -----
        rm = _SCAN_REPORT_RE.match(bare)
        if rm:
            in_traceroute = False
            prefix, host, ip_part, rest = rm.groups()
            widget.insert(tk.END, prefix, ("nmap_info",))
            widget.insert(tk.END, host, ("nmap_host",))
            if ip_part:
                widget.insert(tk.END, ip_part, ("nmap_host",))
            if rest:
                widget.insert(tk.END, rest, ("nmap_info",))
            widget.insert(tk.END, "\n")
            idx += 1
            continue

        # ----- Host is up (latency) -----
        hm = _HOST_UP_LATENCY_RE.match(bare)
        if hm:
            in_traceroute = False
            up_text, latency, rest = hm.groups()
            widget.insert(tk.END, up_text, ("nmap_host_up",))
            widget.insert(tk.END, latency, ("nmap_latency",))
            if rest:
                widget.insert(tk.END, rest, ("nmap_host_up",))
            widget.insert(tk.END, "\n")
            idx += 1
            continue

        # ----- Host is down -----
        if re.match(r"^Host (seems|is) down\b", bare):
            widget.insert(tk.END, raw_line, ("nmap_host_down",))
            idx += 1
            continue

        # ----- MAC Address -----
        mm = _MAC_RE.match(bare)
        if mm:
            in_traceroute = False
            label, mac, vendor, rest = mm.groups()
            widget.insert(tk.END, label, ("nmap_struct_label",))
            widget.insert(tk.END, mac, ("nmap_mac",))
            if vendor:
                widget.insert(tk.END, vendor, ("nmap_version",))
            if rest:
                widget.insert(tk.END, rest)
            widget.insert(tk.END, "\n")
            idx += 1
            continue

        # ----- OS detection lines -----
        if re.match(r"^(Running|OS details|Aggressive OS guesses|OS CPE|Device type):?\s", bare):
            in_traceroute = False
            widget.insert(tk.END, raw_line, ("nmap_os",))
            idx += 1
            continue

        # ----- Service Info -----
        if bare.startswith("Service Info:"):
            in_traceroute = False
            widget.insert(tk.END, raw_line, ("nmap_svc_info",))
            idx += 1
            continue

        # ----- TRACEROUTE header -----
        if re.match(r"^TRACEROUTE", bare):
            in_traceroute = True
            widget.insert(tk.END, raw_line, ("nmap_traceroute_hdr",))
            idx += 1
            # Skip HOP RTT ADDRESS header if present
            if idx < len(lines) and re.match(r"^HOP\s+RTT\s+ADDRESS", lines[idx].strip()):
                widget.insert(tk.END, lines[idx], ("nmap_header",))
                idx += 1
            continue

        # ----- Traceroute hop lines -----
        if in_traceroute:
            thm = _TRACEROUTE_HOP_RE.match(bare)
            if thm:
                hop, sp1, rtt, sp2, host_str = thm.groups()
                leading = raw_line[:len(raw_line) - len(stripped)]
                if leading:
                    widget.insert(tk.END, leading)
                widget.insert(tk.END, hop, ("nmap_traceroute_hop",))
                widget.insert(tk.END, sp1)
                widget.insert(tk.END, rtt, ("nmap_traceroute_rtt",))
                widget.insert(tk.END, sp2)
                widget.insert(tk.END, host_str.rstrip("\n"), ("nmap_traceroute_host",))
                widget.insert(tk.END, "\n")
                idx += 1
                continue
            elif bare.strip() == "":
                in_traceroute = False

        # ----- NSE script output (standalone, not after a port) -----
        if bare.startswith("|"):
            _insert_script_line(widget, raw_line)
            idx += 1
            continue

        # ----- Starting Nmap / Nmap done -----
        dm = _DONE_RE.match(bare)
        if dm:
            label, summary = dm.groups()
            widget.insert(tk.END, label, ("nmap_info",))
            widget.insert(tk.END, summary.rstrip("\n"), ("nmap_dim",))
            widget.insert(tk.END, "\n")
            idx += 1
            continue
        if re.match(r"^Starting Nmap\b", bare):
            widget.insert(tk.END, raw_line, ("nmap_info",))
            idx += 1
            continue

        # ----- Not shown -----
        if re.match(r"^Not shown:", bare):
            widget.insert(tk.END, raw_line, ("nmap_dim",))
            idx += 1
            continue

        # ----- Warnings -----
        if re.match(r"^(Warning|NOTE):", bare, re.IGNORECASE):
            widget.insert(tk.END, raw_line, ("nmap_warning",))
            idx += 1
            continue

        # ----- Network Distance -----
        if re.match(r"^Network Distance:", bare):
            widget.insert(tk.END, raw_line, ("nmap_info",))
            idx += 1
            continue

        # ----- Default: plain text -----
        widget.insert(tk.END, raw_line)
        idx += 1


def insert_nmap_structured_highlighted(widget, text):
    """
    Insert structured nmap data (vertical card format from
    NmapHandler.format_structured()) with color coding.
    """
    if not text:
        return

    _CARD_LINE_RE = re.compile(r"^(\s+)(Port|State|Service|Version):([ ]+)(.*)")

    for raw_line in text.splitlines(keepends=True):
        stripped = raw_line.strip()

        # Separator lines (===, ---)
        if stripped and all(c in "=-" for c in stripped):
            widget.insert(tk.END, raw_line, ("nmap_struct_sep",))
            continue

        # Host header:  "Host: 1.2.3.4 (name) — UP"
        if stripped.startswith("Host:") and ("\u2014" in stripped or "—" in stripped):
            widget.insert(tk.END, raw_line, ("nmap_struct_header",))
            continue

        # Scan info
        if stripped.startswith("Scan completed") or stripped.startswith("Hosts:"):
            widget.insert(tk.END, raw_line, ("nmap_info",))
            continue

        # OS Detection
        if stripped.startswith("OS Detection:") or "accuracy:" in stripped:
            widget.insert(tk.END, raw_line, ("nmap_os",))
            continue

        # Card field lines
        m = _CARD_LINE_RE.match(raw_line)
        if m:
            ws, label, spacing, value = m.groups()
            nl = ""
            if value.endswith("\n"):
                value = value[:-1]
                nl = "\n"

            widget.insert(tk.END, ws)
            widget.insert(tk.END, f"{label}:", ("nmap_struct_label",))
            widget.insert(tk.END, spacing)

            if label == "Port":
                port_m = re.match(r"(\d+)/(tcp|udp|sctp)(.*)", value)
                if port_m:
                    pnum, proto, rest = port_m.groups()
                    widget.insert(tk.END, pnum, ("nmap_port",))
                    widget.insert(tk.END, "/")
                    widget.insert(tk.END, proto, ("nmap_protocol",))
                    if rest:
                        widget.insert(tk.END, rest)
                else:
                    widget.insert(tk.END, value, ("nmap_port",))
            elif label == "State":
                state_tag = _STATE_TAG.get(value.lower().strip(), "nmap_filtered")
                widget.insert(tk.END, value, (state_tag,))
            elif label == "Service":
                widget.insert(tk.END, value, ("nmap_service",))
            elif label == "Version":
                widget.insert(tk.END, value, ("nmap_version",))
            else:
                widget.insert(tk.END, value)

            if nl:
                widget.insert(tk.END, nl)
            continue

        # "No open ports detected."
        if "No open ports" in stripped:
            widget.insert(tk.END, raw_line, ("nmap_dim",))
            continue

        widget.insert(tk.END, raw_line)


def _build_tags(fg, bg, attrs, base_tag):
    """Assemble the tuple of tag names for the current ANSI state."""
    tags = []
    if base_tag:
        tags.append(base_tag)
    if fg:
        tags.append(fg)
    if bg:
        tags.append(bg)
    tags.extend(sorted(attrs))
    return tuple(tags) if tags else ()


def _parse_extended_color(codes, i, is_fg):
    """
    Parse 256-color (5;N) or truecolor (2;R;G;B) extended color sequences.

    Returns (tag_name_or_None, new_index).
    """
    if i + 1 >= len(codes):
        return None, i

    mode = codes[i + 1]

    if mode == 5 and i + 2 < len(codes):
        # 256-color: map to nearest standard ANSI color
        n = codes[i + 2]
        tag = _map_256_to_standard(n, is_fg)
        return tag, i + 2

    elif mode == 2 and i + 4 < len(codes):
        # Truecolor: map to nearest standard ANSI color
        r, g, b = codes[i + 2], codes[i + 3], codes[i + 4]
        tag = _map_rgb_to_standard(r, g, b, is_fg)
        return tag, i + 4

    return None, i


def _map_256_to_standard(n, is_fg):
    """Map a 256-color index to the nearest standard ANSI tag."""
    if n < 8:
        code = (30 if is_fg else 40) + n
        return _FG_MAP.get(code) if is_fg else _BG_MAP.get(code)
    elif n < 16:
        code = (90 if is_fg else 100) + (n - 8)
        return _FG_MAP.get(code) if is_fg else _BG_MAP.get(code)
    else:
        # 216-color cube (16-231) and grayscale (232-255)
        # Map to nearest standard color by approximate hue
        if n >= 232:
            # Grayscale: dark = black/bright_black, light = white
            level = (n - 232) * 10 + 8
            if level < 64:
                return "ansi_black" if is_fg else "ansi_bg_black"
            elif level < 128:
                return "ansi_bright_black" if is_fg else "ansi_bg_bright_black"
            elif level < 192:
                return "ansi_white" if is_fg else "ansi_bg_white"
            else:
                return "ansi_bright_white" if is_fg else "ansi_bg_bright_white"
        else:
            # 6x6x6 color cube
            n -= 16
            b = n % 6
            g = (n // 6) % 6
            r = n // 36
            return _map_rgb_to_standard(r * 51, g * 51, b * 51, is_fg)


def _map_rgb_to_standard(r, g, b, is_fg):
    """Map an RGB color to the nearest standard ANSI tag."""
    # Simple heuristic based on dominant channel
    mx = max(r, g, b)
    mn = min(r, g, b)

    if mx < 50:
        return "ansi_black" if is_fg else "ansi_bg_black"

    bright = mx > 170

    if mx - mn < 30:
        # Gray
        if mx < 100:
            return ("ansi_bright_black" if is_fg else "ansi_bg_bright_black")
        elif bright:
            return ("ansi_bright_white" if is_fg else "ansi_bg_bright_white")
        else:
            return "ansi_white" if is_fg else "ansi_bg_white"

    # Dominant color
    if r >= g and r >= b:
        if g > b and g > 100:
            tag = "yellow"
        elif b > g and b > 100:
            tag = "magenta"
        else:
            tag = "red"
    elif g >= r and g >= b:
        if b > r and b > 100:
            tag = "cyan"
        else:
            tag = "green"
    else:
        if r > g and r > 100:
            tag = "magenta"
        else:
            tag = "blue"

    prefix = "ansi_bright_" if bright else "ansi_"
    suffix = f"bg_{prefix[5:]}" if not is_fg else ""

    if is_fg:
        return f"{prefix}{tag}"
    else:
        return f"ansi_bg_{'bright_' if bright else ''}{tag}"
