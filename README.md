# IOC Citadel by Bulwark Black LLC

This Desktop folder is a **consolidated Tkinter-only copy** of IOC Citadel.

It is intentionally simplified:
- `No PySide6 / Qt GUI files`
- `No duplicate legacy/regular app folders`
- `One GUI launcher path only` (`main.py` -> `ioc_extractor/gui/app.py`)

## Quick Start (Tk GUI)

### Launch (Terminal)
```bash
cd ~/Desktop/IOC_citadel
python3 main.py
```

### Launch (Finder)
Double-click:
- `~/Desktop/IOC_citadel/IOC Citadel by Bulwark Black LLC.command`

## Install Dependencies

From the `IOC_citadel` folder:

```bash
cd ~/Desktop/IOC_citadel
python3 -m pip install --user --break-system-packages -r requirements.txt
```

Notes:
- Tkinter is built into Python on macOS in most setups.
- `requirements.txt` mainly covers REST API / HTTP-related dependencies.
- Some features use optional external tools (listed below).

## What Is In This Folder (and what each file is for)

### Root Files
- `main.py`
  - Main Tkinter launcher for this copy (Tk-only).
- `IOC Citadel by Bulwark Black LLC.command`
  - Double-click launcher for macOS Finder (runs `main.py`).
- `IOC_Citadel_by_Bulwark_Black_LLC.py`
  - Alternate branded Python launcher (also runs `main.py`).
- `requirements.txt`
  - Python dependency list used by the app/API.
- `README.md`
  - This file.

### Main Package: `ioc_extractor/`

This folder contains the application logic and the Tk GUI.

#### Tk GUI (the actual GUI used in this Desktop copy)
- `ioc_extractor/gui/app.py`
  - Main Tkinter window, tabs, actions, threading, event handlers.
- `ioc_extractor/gui/widgets.py`
  - Tk widget builders, themed controls, layout helpers.
- `ioc_extractor/gui/__init__.py`
  - Tk GUI package init.

#### Core IOC / Parsing / Formatting
- `ioc_extractor/ioc_parser.py`
  - IOC regex parsing, defang/refang logic.
- `ioc_extractor/patterns.py`
  - IOC regex pattern definitions.
- `ioc_extractor/ansi_parser.py`
  - ANSI/terminal output parsing and highlighting helpers.
- `ioc_extractor/file_operations.py`
  - Export/save helpers (text/CSV/JSON/per-category).
- `ioc_extractor/constants.py`
  - App title, UI constants, theme colors, help text.

#### IOC History / Database / Intel Features
- `ioc_extractor/ioc_history_db.py`
  - SQLite database for saved IOC collections, cache, analytics, aliases, webhooks.
- `ioc_extractor/app_settings.py`
  - Persistent app settings (JSON file in user home).
- `ioc_extractor/enrichment.py`
  - Enrichment provider integrations (AbuseIPDB, GreyNoise, urlscan, OTX, WHOIS/RDAP, passive DNS).
- `ioc_extractor/tree_sitter_ingest.py`
  - Optional Tree-sitter code-aware extraction helpers for Bulk Ingest (regex parsing remains intact).

#### External Tool Integrations
- `ioc_extractor/virustotal.py`
  - VirusTotal API workflows and rate limiting.
- `ioc_extractor/keychain.py`
  - Secure API key storage helpers (keyring/macOS keychain integration when available).
- `ioc_extractor/jsluice_handler.py`
  - Jsluice execution and output handling.
- `ioc_extractor/jsluice_installer.py`
  - Jsluice installer helper.
- `ioc_extractor/nmap_handler.py`
  - Nmap execution, XML parsing, structured/raw result handling.
- `ioc_extractor/nmap_installer.py`
  - Nmap installer helper.
- `ioc_extractor/shell_runner.py`
  - Shell command execution helper with timeout handling.

#### Optional Local REST API (still included in this copy)
- `ioc_extractor/api/server.py`
  - FastAPI server routes and auth.
- `ioc_extractor/api/service.py`
  - Shared backend service layer used by API.
- `ioc_extractor/api/__main__.py`
  - CLI entrypoint for `python -m ioc_extractor.api`.
- `ioc_extractor/api/__init__.py`
  - API package exports.

#### Package Marker
- `ioc_extractor/__init__.py`
  - Package version/metadata.

## How To Use The App (Tk GUI)

### 1) Parse IOCs from Text
1. Launch the app.
2. Paste CTI text, article text, email headers, logs, or code into the main input box.
3. Click `Parse IOCs`.
4. Review results in:
   - IOC table/tree (bottom-left)
   - Review text (bottom-right)

### 2) Defang / Refang
- Use `Defang` to safely display/share IOCs.
- Use `Refang` before submitting indicators to VirusTotal.
- The app auto-refangs for VT submissions in newer flows, but it is still good practice to know the current display state.

### 3) Save / Export
Use the `Export` controls in the IOC Review tab to save:
- grouped text
- JSON
- CSV
- per-category exports

### 4) Save to History (SQLite)
- Use `Save to History` in the IOC Review tab to save a named collection.
- Then use the `IOC History` tab to search and reload past collections.

### 5) VirusTotal
- Store your VT API key when prompted (or via settings/API controls if exposed in your build).
- Select IOCs and run VT actions (`VT Check`, URL submit, hash details, etc.).

### 6) Jsluice / Nmap / Shell (optional tools)
These tabs/features require the tools to be installed locally.
- Jsluice: `jsluice` binary in `PATH`
- Nmap: `nmap` binary in `PATH`
- Shell tab: runs local shell commands (use with care)

## Bulk Ingest (Important)

Bulk Ingest can combine multiple sources into one parse run:
- pasted text
- URLs
- files
- folders (recursive)
- PDFs (optional `pypdf`)
- email files/headers

### Optional Tree-sitter code-aware extraction
Bulk Ingest includes an optional checkbox for Tree-sitter code-aware extraction.

What it does:
- extracts additional strings/comments from supported code files (Python/JS/TS/Bash, PowerShell support when grammar is available)
- appends those extracted strings/comments into the ingest text
- then the normal regex IOC parser runs as usual

It does **not** replace regex parsing.

Optional install:
```bash
python3 -m pip install --user --break-system-packages tree_sitter tree_sitter_languages
```
Optional PowerShell-specific grammar fallback:
```bash
python3 -m pip install --user --break-system-packages tree_sitter_powershell
```

Optional PDF support:
```bash
python3 -m pip install --user --break-system-packages pypdf
```

## Local REST API (Optional)

This Tk-only copy still includes the local REST API for integrations/automation.

### Start API
```bash
cd ~/Desktop/IOC_citadel
python3 -m ioc_extractor.api --host 127.0.0.1 --port 8765
```

### Basic API Notes
- Local-first (localhost) design
- Bearer token auth supported
- Sessions, parsing, exports, history, jobs, enrichment, and intel views are available via REST

## External Programs / Features You May Need Installed

### Python (required)
- Python 3.10+ recommended

### Optional binaries
- `nmap` (for Nmap tab)
- `jsluice` (for Jsluice tab)

### Optional Python packages
- `pypdf` (PDF extraction in Bulk Ingest)
- `tree_sitter`, `tree_sitter_languages` (code-aware Bulk Ingest supplements)
- `tree_sitter_powershell` (PowerShell Tree-sitter fallback support)
- `keyring` (secure key storage, depending on your environment)

## Troubleshooting

### App does not launch
- Run from Terminal to see the error:
```bash
cd ~/Desktop/IOC_citadel
python3 main.py
```

### Finder `.command` does nothing
- Make sure the file is executable (already set in this copy, but if needed):
```bash
chmod +x "~/Desktop/IOC_citadel/IOC Citadel by Bulwark Black LLC.command"
```

### Missing tool features (Jsluice/Nmap)
- Those tabs depend on local tools in `PATH`. Install the tools, then restart the app.

### Bulk Ingest is slow on huge text dumps
- Use targeted parsing selections (if enabled in your UI build)
- Use `Fast Parse` mode for very large inputs
- Build highlights/provenance after parse only when needed

## Summary (this Desktop copy)

This `IOC_citadel` folder is now a **single consolidated Tkinter application copy** with:
- one GUI path (`ioc_extractor/gui`)
- one main launcher (`main.py`)
- no Qt UI files
- no duplicate legacy app folder structures

