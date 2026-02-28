"""
ioc_parser.py - Core IOC extraction and transformation logic.

Pure functions that operate on text strings — no GUI dependencies.
This makes the parsing logic testable and reusable outside of tkinter.
"""

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .patterns import IOC_PATTERNS


def extract_iocs(
    text: str,
    selected_patterns: Optional[Set[str]] = None,
    collect_spans: bool = True,
) -> Tuple[Dict[str, List[str]], List[Tuple[int, int, str]]]:
    """
    Extract all IOCs from *text*.

    Parameters
    ----------
    text : str
        The input text to scan.
    selected_patterns : set of str, optional
        Pattern names to run.  When *None* (default) all patterns
        are executed.  Pass a subset to limit extraction.
    collect_spans : bool, optional
        When True (default), record ``(start, end, category)`` match spans
        for input highlighting/provenance. Set False for faster parsing when
        span-based features are not needed.

    Returns
    -------
    found_iocs : dict
        ``{category_name: [sorted unique matches]}``
    match_spans : list of (start, end, category_name)
        Character offsets for every match, used for highlighting.
    """
    found_iocs: Dict[str, List[str]] = {}
    match_spans: List[Tuple[int, int, str]] = []

    for name, pattern in IOC_PATTERNS.items():
        if selected_patterns is not None and name not in selected_patterns:
            continue
        unique_matches: set = set()
        try:
            if not hasattr(pattern, "finditer"):
                raise TypeError(f"'{name}' is not a compiled regex pattern.")

            for match in pattern.finditer(text):
                match_str = match.group(0).strip()
                if match_str:
                    unique_matches.add(match_str)
                    if collect_spans:
                        match_spans.append((match.start(), match.end(), name))

            if unique_matches:
                found_iocs[name] = sorted(unique_matches)

        except re.error as exc:
            # Store the error so the caller can display it
            found_iocs[f"__error__{name}"] = [f"Invalid pattern - {exc}"]
        except Exception as exc:
            found_iocs[f"__error__{name}"] = [str(exc)]

    return found_iocs, match_spans


def defang_text(text: str) -> str:
    """Convert live IOCs to defanged format."""
    return (
        text
        .replace(".", "[.]")
        .replace("http", "hxxp")
        .replace("ftp", "fxp")
    )


def refang_text(text: str) -> str:
    """Reverse defanging — restore live IOC format."""
    return (
        text
        .replace("[.]", ".")
        .replace("hxxp", "http")
        .replace("fxp", "ftp")
    )


def transform_ioc_map(
    iocs: Dict[str, List[str]],
    transform: Callable[[str], str],
) -> Dict[str, List[str]]:
    """
    Apply *transform* to IOC values only (not headings/rendered text).

    Returns a new dict with per-category unique, sorted values.
    Error sentinel categories (``__error__*``) are preserved as-is.
    """
    transformed: Dict[str, List[str]] = {}
    for category, items in iocs.items():
        if category.startswith("__error__"):
            transformed[category] = list(items)
            continue
        unique_items = set()
        for item in items:
            try:
                unique_items.add(transform(item))
            except Exception:
                unique_items.add(item)
        transformed[category] = sorted(unique_items)
    return transformed


def defang_ioc_map(iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Defang each IOC value in a structured IOC map."""
    return transform_ioc_map(iocs, defang_text)


def refang_ioc_map(iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Refang each IOC value in a structured IOC map."""
    return transform_ioc_map(iocs, refang_text)
