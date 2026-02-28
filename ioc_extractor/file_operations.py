"""
file_operations.py - File save/export utilities.

Supports multiple export formats:
  - Plain text (.txt)
  - JSON (.json) - structured IOC export
  - CSV (.csv) - spreadsheet-compatible IOC export
  - Category-separated files (one .txt per IOC type)

No GUI dependencies — file path selection is handled by
the caller (GUI layer).
"""

import csv
import io
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Tuple


def save_text_to_file(text: str, file_path: str) -> None:
    """
    Write *text* to *file_path* (UTF-8).

    Raises
    ------
    IOError
        If the write fails.
    """
    with open(file_path, "w", encoding="utf-8") as fh:
        fh.write(text)


def save_iocs_by_category(
    iocs: Dict[str, List[str]],
    folder: str,
) -> Tuple[int, List[str]]:
    """
    Save each IOC category to a separate file inside *folder*.

    Returns
    -------
    (saved_count, error_messages)
    """
    saved = 0
    errors: List[str] = []

    for category, items in iocs.items():
        if not items:
            continue

        # Build a safe file name from the category
        safe_name = "".join(
            c for c in category if c.isalnum() or c in (" ", "_", "-")
        ).rstrip()
        safe_name = re.sub(r"\s+", "_", safe_name) or "unknown_category"
        path = os.path.join(folder, f"{safe_name}.txt")

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(items) + "\n")
            saved += 1
        except Exception as exc:
            errors.append(f"Failed to save '{category}': {exc}")

    return saved, errors


def export_iocs_as_json(
    iocs: Dict[str, List[str]],
    file_path: str,
    include_metadata: bool = True,
) -> None:
    """
    Export IOCs as a structured JSON file.

    Output structure:
    {
        "metadata": { "exported_at": "...", "total_iocs": N },
        "iocs": { "category": ["ioc1", "ioc2", ...], ... }
    }
    """
    output = {}

    if include_metadata:
        total = sum(len(v) for v in iocs.values())
        output["metadata"] = {
            "exported_at": datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "total_iocs": total,
            "categories": len(iocs),
        }

    output["iocs"] = {k: sorted(v) for k, v in iocs.items() if v}

    with open(file_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)


def export_iocs_as_csv(
    iocs: Dict[str, List[str]],
    file_path: str,
) -> None:
    """
    Export IOCs as a CSV file with columns: Category, IOC.

    Suitable for import into spreadsheets, SIEMs, etc.
    """
    with open(file_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Category", "IOC"])
        for category, items in sorted(iocs.items()):
            for ioc in sorted(items):
                writer.writerow([category, ioc])


def format_ioc_summary(iocs: Dict[str, List[str]]) -> str:
    """
    Build a concise one-line summary of IOC counts.

    Example: "Found: 5 IPv4, 3 URLs, 2 sha256  (10 total)"
    """
    if not iocs:
        return "No IOCs found"

    parts = []
    total = 0
    for name, items in iocs.items():
        count = len(items)
        total += count
        parts.append(f"{count} {name}")

    summary = ", ".join(parts)
    return f"Found: {summary}  ({total} total)"
