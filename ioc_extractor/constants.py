"""
constants.py - Application-wide constants and configuration values.

Centralizes magic strings, default values, and configuration that were
previously scattered throughout the monolithic ioc_extractor.py.
"""

# Application metadata
APP_TITLE = "IOC Citadel"
APP_BRAND = "Bulwark Black LLC"
APP_FULL_NAME = f"{APP_TITLE} by {APP_BRAND}"
APP_GEOMETRY = "1600x900"
APP_MIN_WIDTH = 900
APP_MIN_HEIGHT = 600

# Input placeholder
INPUT_PLACEHOLDER = "Paste or type text containing IOCs here..."

# Shell command timeout (seconds)
SHELL_COMMAND_TIMEOUT = 30

# Nmap configuration
NMAP_TIMEOUT = 300  # 5 minutes — scans can be slow
NMAP_INSTALL_TIMEOUT = 300  # seconds — package manager install

NMAP_SCAN_TYPES = [
    ("TCP Connect (-sT)", "-sT"),
    ("TCP SYN (-sS)", "-sS"),
    ("UDP (-sU)", "-sU"),
    ("Service Version (-sV)", "-sV"),
    ("OS Detection (-O)", "-O"),
    ("Aggressive (-A)", "-A"),
    ("Ping Scan (-sn)", "-sn"),
    ("Quick (-F)", "-F"),
    ("ACK Scan (-sA)", "-sA"),
    ("Window Scan (-sW)", "-sW"),
    ("FIN Scan (-sF)", "-sF"),
    ("Xmas Scan (-sX)", "-sX"),
    ("Null Scan (-sN)", "-sN"),
    ("IP Protocol (-sO)", "-sO"),
    ("SCTP INIT (-sY)", "-sY"),
]

# Timing templates for nmap
NMAP_TIMING_TEMPLATES = [
    ("Default", ""),
    ("T0 - Paranoid", "-T0"),
    ("T1 - Sneaky", "-T1"),
    ("T2 - Polite", "-T2"),
    ("T3 - Normal", "-T3"),
    ("T4 - Aggressive", "-T4"),
    ("T5 - Insane", "-T5"),
]

# Scan types that require root/sudo privileges
NMAP_SUDO_SCAN_FLAGS = {"-sS", "-sU", "-O", "-A", "-sA", "-sW", "-sF", "-sX", "-sN", "-sO", "-sY"}

NMAP_COMMON_FLAGS = [
    ("-Pn", "Skip host discovery"),
    ("-p-", "All 65535 ports"),
    ("-T4", "Aggressive timing"),
    ("--top-ports 1000", "Top 1000 ports"),
    ("-v", "Verbose output"),
    ("-sC", "Default scripts"),
    ("--open", "Only open ports"),
    ("-n", "No DNS resolution"),
    ("--traceroute", "Traceroute"),
]

# VirusTotal API endpoints
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_GUI_BASE = "https://www.virustotal.com/gui"
VT_URL_ENDPOINT = f"{VT_API_BASE}/urls"
VT_FILES_ENDPOINT = f"{VT_API_BASE}/files"
VT_IP_ENDPOINT = f"{VT_API_BASE}/ip_addresses"
VT_DOMAIN_ENDPOINT = f"{VT_API_BASE}/domains"
VT_REQUEST_TIMEOUT = 20
VT_MITRE_REQUEST_TIMEOUT = 30

# VT rate limiting (free tier: 4 requests per minute)
VT_RATE_LIMIT_REQUESTS = 4
VT_RATE_LIMIT_WINDOW = 60  # seconds

# Jsluice configuration
JSLUICE_MODES = ["urls", "secrets", "tree", "query", "format"]
JSLUICE_TEMP_PREFIX = "jsluice_input_"
JSLUICE_TEMP_SUFFIX = ".js"
JSLUICE_TEMP_MAX_AGE = 3600  # seconds (1 hour) before cleanup

# Jsluice auto-installer
JSLUICE_INSTALL_PACKAGE = "github.com/BishopFox/jsluice/cmd/jsluice@latest"
JSLUICE_INSTALL_TIMEOUT = 180   # seconds — Go compilation from source
GO_INSTALL_TIMEOUT = 300        # seconds — Go package manager install

# IOC pattern groups — drives the "Parse IOCs" dropdown filter menu.
# Keys are group labels, values are lists of pattern names matching
# the keys in patterns.IOC_PATTERNS.
IOC_PATTERN_GROUPS = {
    "Network": [
        "IPv4", "IPv4 (defanged)", "IPv4:Port", "CIDR", "ASN",
        "Domains", "Sub Domains",
        "Domains (defanged [dot])", "Domains (defanged (dot))",
        "Domains (defanged (.))",
    ],
    "URLs": [
        "URLs", "IP URL", "Defanged URLs",
    ],
    "Hashes & Fingerprints": [
        "md5", "sha1", "sha256", "sha512", "SS-Deep",
        "JARM", "JA3/JA3S", "JA4+", "IMPHASH",
    ],
    "Identifiers": [
        "CVEs", "MITRE ATT&CK", "Threat Group IDs",
        "STIX IDs", "Snort/Suricata SIDs",
    ],
    "Files": [
        "File Names",
        "Windows File Paths", "UNC Paths",
        "PDB Paths", "Named Pipes",
    ],
    "Identity": [
        "Email Addresses",
    ],
    "Registry": [
        "Registry", "Registry (Long Form)",
    ],
    "Hardware": [
        "Mac Address",
    ],
    "Crypto": [
        "Bitcoin Addresses", "Bitcoin Bech32",
        "Ethereum Addresses", "Monero Addresses",
        "Monero Integrated Addresses",
    ],
    "Dark Web": [
        "Dark Web",
    ],
    "Rules": [
        "Yara Rules",
        "Sigma Rules",
        "Sigma Rule IDs",
        "Snort/Suricata Rules",
        "ModSecurity Rules",
    ],
    "Malware Behavior": [
        "Mutex Names", "User-Agent Strings",
        "Scheduled Tasks", "Windows Service Commands",
        "PowerShell Encoded Commands",
    ],
    "Infrastructure": [
        "Google Analytics IDs", "Adsense Publisher IDs",
        "AWS S3 References", "Abuse.ch References",
    ],
}

# ---------------------------------------------------------------------------
# Professional Dark Theme - Color Palette
# ---------------------------------------------------------------------------
# Primary:  Black backgrounds
# Green:    IOC parsing actions
# Blue:     VirusTotal actions
# Orange:   Jsluice actions
# Purple:   Shell / terminal actions
# ---------------------------------------------------------------------------

COLORS = {
    # --- Backgrounds ---
    "bg_primary": "#1a1a2e",       # Deep navy-black (main window)
    "bg_secondary": "#16213e",     # Slightly lighter panel bg
    "bg_input": "#0f0f1a",         # Near-black for text input areas
    "bg_output": "#0d1117",        # GitHub-dark for output areas
    "bg_toolbar": "#16213e",       # Toolbar / header bar
    "bg_button_bar": "#111827",    # Bottom button bar strips
    "bg_entry": "#1e293b",         # Entry field backgrounds
    "bg_sash": "#2d3748",          # Pane sash color
    "bg_statusbar": "#0f172a",     # Status bar background
    "bg_tab_actionbar": "#161b22",  # Tab-local action bar background

    # --- Foreground / text ---
    "fg_primary": "#e2e8f0",       # Light grey text (main)
    "fg_secondary": "#94a3b8",     # Muted text (labels, hints)
    "fg_placeholder": "#4a5568",   # Placeholder text
    "fg_heading": "#f1f5f9",       # Bright white for headings

    # --- Accent colors (category coding) ---
    "green": "#22c55e",            # IOC parsing
    "green_hover": "#16a34a",
    "green_dim": "#166534",        # Subtle green bg for IOC tab accent
    "green_fg": "#bbf7d0",         # Green text in output

    "blue": "#3b82f6",             # VirusTotal
    "blue_hover": "#2563eb",
    "blue_dim": "#1e3a5f",
    "blue_fg": "#bfdbfe",

    "orange": "#f97316",           # Jsluice
    "orange_hover": "#ea580c",
    "orange_dim": "#7c2d12",
    "orange_fg": "#fed7aa",

    "purple": "#a855f7",           # Shell / Terminal
    "purple_hover": "#9333ea",
    "purple_dim": "#581c87",
    "purple_fg": "#e9d5ff",

    "teal": "#14b8a6",             # Nmap
    "teal_hover": "#0d9488",
    "teal_dim": "#134e4a",
    "teal_fg": "#99f6e4",

    "slate": "#334155",            # Neutral secondary actions
    "slate_hover": "#475569",
    "slate_dim": "#1f2937",
    "slate_fg": "#cbd5e1",

    # --- Utility ---
    "red": "#ef4444",              # Errors / destructive
    "red_hover": "#dc2626",
    "red_dim": "#7f1d1d",
    "yellow": "#eab308",           # Warnings
    "highlight_find": "#365314",   # Find highlight (dark green bg)
    "highlight_ioc": "#854d0e",    # IOC highlight (dark amber bg)
    "highlight_find_fg": "#a3e635",
    "highlight_ioc_fg": "#fbbf24",
    "border": "#2d3748",           # Subtle borders
    "separator": "#374151",        # Visual separators

    # --- Button text ---
    "btn_fg": "#ffffff",           # White text on colored buttons
    "btn_fg_dark": "#1a1a2e",      # Dark text if needed

    # --- Link colors ---
    "link": "#60a5fa",             # Clickable hyperlink
    "link_hover": "#93bbfc",       # Hovered hyperlink
}

# Nmap-specific syntax highlighting colors — distinct per column
NMAP_COLORS = {
    # --- Port table columns ---
    "nmap_port": "#60a5fa",         # Blue — port numbers (22, 80, 443)
    "nmap_protocol": "#a78bfa",     # Purple — protocol (tcp, udp)
    "nmap_open": "#4ade80",         # Green — state: open
    "nmap_closed": "#f87171",       # Red — state: closed
    "nmap_filtered": "#fbbf24",     # Amber — state: filtered
    "nmap_open_filtered": "#22d3ee",# Cyan — state: open|filtered
    "nmap_service": "#f9a8d4",      # Pink — service name (ssh, http)
    "nmap_version": "#dc2626",      # Dark red — version info (stands out)

    # --- Context lines ---
    "nmap_header": "#e2e8f0",       # White bold — section headers
    "nmap_host": "#67e8f9",         # Bright cyan — host report line
    "nmap_host_up": "#4ade80",      # Green — host is up
    "nmap_host_down": "#f87171",    # Red — host is down
    "nmap_info": "#93c5fd",         # Light blue — nmap meta (start/done)
    "nmap_os": "#c084fc",           # Violet — OS detection
    "nmap_mac": "#f0abfc",          # Light violet — MAC address
    "nmap_svc_info": "#fde047",     # Yellow — Service Info
    "nmap_warning": "#fbbf24",      # Amber — warnings
    "nmap_dim": "#6b7280",          # Gray — Not shown, etc.

    # --- NSE script output ---
    "nmap_script_name": "#f9a8d4",  # Pink — script name (|_http-title:)
    "nmap_script_data": "#d1d5db",  # Light gray — script data values
    "nmap_script_pipe": "#475569",  # Dark slate — the | prefix

    # --- Traceroute ---
    "nmap_traceroute_hdr": "#e2e8f0",  # White bold — TRACEROUTE header
    "nmap_traceroute_hop": "#93c5fd",  # Light blue — hop number
    "nmap_traceroute_rtt": "#a78bfa",  # Purple — RTT values
    "nmap_traceroute_host": "#67e8f9", # Cyan — hop hostname/IP

    # --- Latency / timing ---
    "nmap_latency": "#a78bfa",      # Purple — latency values in parens

    # --- Structured data pane ---
    "nmap_struct_label": "#94a3b8", # Slate — field labels (Port:, State:)
    "nmap_struct_value": "#e2e8f0", # White — generic values
    "nmap_struct_header": "#67e8f9",# Cyan — host headers
    "nmap_struct_sep": "#475569",   # Dark slate — separator lines
}

# ANSI escape code → dark-theme color map (used by ansi_parser.py)
ANSI_COLORS = {
    "ansi_black": "#4a5568",
    "ansi_red": "#ef4444",
    "ansi_green": "#22c55e",
    "ansi_yellow": "#eab308",
    "ansi_blue": "#60a5fa",
    "ansi_magenta": "#c084fc",
    "ansi_cyan": "#22d3ee",
    "ansi_white": "#e2e8f0",
    "ansi_bright_black": "#6b7280",
    "ansi_bright_red": "#f87171",
    "ansi_bright_green": "#4ade80",
    "ansi_bright_yellow": "#fde047",
    "ansi_bright_blue": "#93c5fd",
    "ansi_bright_magenta": "#d8b4fe",
    "ansi_bright_cyan": "#67e8f9",
    "ansi_bright_white": "#f8fafc",
}

# Fonts — platform-aware monospace selection
import platform as _platform
_SYS = _platform.system()

if _SYS == "Darwin":
    _MONO = "Menlo"
    _SANS = "Helvetica"
elif _SYS == "Windows":
    _MONO = "Consolas"
    _SANS = "Segoe UI"
else:  # Linux / other
    _MONO = "DejaVu Sans Mono"
    _SANS = "Helvetica"

FONTS = {
    "heading": (_SANS, 11, "bold"),
    "body": (_SANS, 10),
    "mono": (_MONO, 11),
    "mono_small": (_MONO, 10),
    "button": (_SANS, 10, "bold"),
    "label": (_SANS, 9),
    "tab": (_SANS, 10, "bold"),
    "category_header": (_MONO, 11, "bold"),
    "statusbar": (_SANS, 9),
    "link": (_MONO, 11, "underline"),
    "toolbar": (_SANS, 10, "bold"),
    "menu": (_SANS, 10),
}

# Default help / instruction texts
IOC_REVIEW_HELP = (
    "Parse text to populate extracted IOCs here.\n\n"
    "Quick start:\n"
    "  1. Paste text above\n"
    "  2. Click 'Parse IOCs'\n"
    "  3. Select IOC lines and run VT/Jsluice actions from the toolbar\n"
    "  4. Use 'Save / Export' below when ready\n\n"
    "Tip: Use Find & Replace (Ctrl+H) to clean noisy input before parsing."
)

VT_HELP = """Select IOC lines in the IOC Review tab, then run a VirusTotal action.

Quick start:
  1. Parse IOCs
  2. Select lines in IOC Review
  3. Click a VT action in the toolbar
  4. Enter your API key when prompted

VT Check supports IPs, domains, URLs, and hashes."""

JSLUICE_HELP = """Run jsluice from the toolbar to analyze the input text.

Quick start:
  1. Choose a jsluice mode in the toolbar
  2. Click 'Run Jsluice'
  3. (Optional) Add custom options in this tab

Tip: The temp file path is shown above results for reuse in the Shell tab."""

JSLUICE_OPTIONS_HELP = """
Common Jsluice Options (enter in the box):

Mode 'urls':
  -I : Ignore matches from string literals
  -S : Include source code where URL was found
  -R <url> : Resolve relative paths using base URL

Mode 'secrets':
  -p <file> : JSON file with custom patterns

Mode 'query':
  -q <query> : Tree-sitter query (e.g., '(string) @m')
  -r : Raw query output (don't JSON-encode)

(Refer to jsluice documentation for all options) https://github.com/BishopFox/jsluice
"""

SHELL_HELP = (
    "Enter a shell command and press Enter or click Run.\n"
    "Supports pipes/redirection; ANSI colors are rendered.\n"
    "Commands use the configured shell timeout."
)

NMAP_HELP = """Configure a target and click 'Run Nmap' to start a scan.

Quick start:
  1. Enter a target IP/hostname/CIDR
  2. Pick a scan type and optional flags
  3. Click 'Run Nmap'

Raw output appears above; XML-backed structured results appear below."""

# Keyboard shortcuts (display names)
KEYBOARD_SHORTCUTS = {
    "parse": ("Ctrl+P", "<Control-p>"),
    "defang": ("Ctrl+D", "<Control-d>"),
    "find_replace": ("Ctrl+H", "<Control-h>"),
    "save_input": ("Ctrl+S", "<Control-s>"),
    "clear_input": ("Ctrl+Shift+X", "<Control-Shift-X>"),
    "run_jsluice": ("Ctrl+J", "<Control-j>"),
    "run_shell": ("Ctrl+Return", "<Control-Return>"),
    "tab_ioc": ("Ctrl+1", "<Control-Key-1>"),
    "tab_vt": ("Ctrl+2", "<Control-Key-2>"),
    "tab_jsluice": ("Ctrl+3", "<Control-Key-3>"),
    "tab_shell": ("Ctrl+4", "<Control-Key-4>"),
    "tab_nmap": ("Ctrl+5", "<Control-Key-5>"),
    "run_nmap": ("Ctrl+N", "<Control-n>"),
}
