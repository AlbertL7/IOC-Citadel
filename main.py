#!/usr/bin/env python3
"""
IOC Citadel by Bulwark Black LLC - Tkinter launcher.

Run this file to launch the application:
    python3 main.py
"""

from __future__ import annotations

from ioc_extractor.gui.app import IOCExtractorApp


def main() -> int:
    app = IOCExtractorApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
