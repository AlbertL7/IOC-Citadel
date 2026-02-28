"""
Optional Tree-sitter helpers for code-aware bulk ingest.

This module is intentionally optional. If tree-sitter dependencies are not
installed, callers should degrade gracefully and keep regex parsing behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


SUPPORTED_LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
}

# Common node types seen across grammars. We intentionally keep this broad and
# dedupe results to maximize portability across optional grammar bundles.
_STRING_NODE_HINTS = (
    "string",
    "template",
    "heredoc",
)
_STRING_CONTENT_TYPES = {
    "string_content",
    "string_fragment",
    "template_string",
    "template_substitution",
    "interpreted_string_literal",
    "raw_string_literal",
    "heredoc_body",
    "heredoc_content",
}


def _try_get_parser(language: str):
    # Primary optional package with bundled grammars.
    try:
        from tree_sitter_languages import get_parser  # type: ignore

        return get_parser(language), "tree_sitter_languages"
    except Exception as first_exc:
        # Fallback: dedicated grammar packages (useful when users only install a
        # single grammar such as PowerShell).
        parser = _try_get_parser_from_language_package(language)
        if parser is not None:
            return parser, f"language-package:{language}"
        raise RuntimeError(
            "Tree-sitter support not available (install optional deps: tree_sitter tree_sitter_languages "
            "or a dedicated grammar package such as tree_sitter_powershell)"
        ) from first_exc


def _try_get_parser_from_language_package(language: str):
    if str(language or "").strip().lower() != "powershell":
        return None
    module_names = (
        "tree_sitter_powershell",
        "tree_sitter_powerShell",
    )
    try:
        from tree_sitter import Language, Parser  # type: ignore
    except Exception:
        return None
    for mod_name in module_names:
        try:
            mod = __import__(mod_name)
            lang_factory = getattr(mod, "language", None)
            if not callable(lang_factory):
                continue
            raw_lang = lang_factory()
            try:
                lang = Language(raw_lang)  # newer tree-sitter Python bindings
            except Exception:
                lang = raw_lang  # older bindings may already return Language
            parser = Parser()
            try:
                parser.set_language(lang)  # older API
            except Exception:
                try:
                    parser.language = lang  # newer API
                except Exception:
                    continue
            return parser
        except Exception:
            continue
    return None


def availability_info() -> dict[str, Any]:
    # Probe a common language and PowerShell so users can see whether a dedicated
    # PowerShell grammar package is available even if the bundled grammar set is not.
    loaders: dict[str, str] = {}
    errors: dict[str, str] = {}
    for lang in ("python", "powershell"):
        try:
            _parser, loader = _try_get_parser(lang)
            loaders[lang] = str(loader)
        except Exception as exc:
            errors[lang] = str(exc)
    return {
        "available": bool(loaders),
        "languages": loaders,
        "errors": errors,
    }


def _node_text(source_bytes: bytes, node: Any) -> str:
    try:
        return source_bytes[int(node.start_byte) : int(node.end_byte)].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _walk_nodes(root: Any, *, max_nodes: int = 5000):
    stack = [root]
    seen = 0
    while stack and seen < max_nodes:
        node = stack.pop()
        seen += 1
        yield node
        try:
            children = list(node.children or [])
        except Exception:
            children = []
        for child in reversed(children):
            stack.append(child)


def _collect_nodes(source_bytes: bytes, root: Any) -> tuple[list[str], list[str]]:
    comments: list[str] = []
    strings: list[str] = []
    seen_comments: set[str] = set()
    seen_strings: set[str] = set()
    for node in _walk_nodes(root):
        ntype = str(getattr(node, "type", "") or "")
        if not ntype:
            continue
        low = ntype.lower()
        if "comment" in low:
            raw = _node_text(source_bytes, node).strip()
            if raw and raw not in seen_comments:
                seen_comments.add(raw)
                comments.append(raw)
            continue
        if low in _STRING_CONTENT_TYPES or any(h in low for h in _STRING_NODE_HINTS):
            raw = _node_text(source_bytes, node).strip()
            if not raw:
                continue
            # Skip oversized literals to avoid ballooning bulk-ingest payloads.
            if len(raw) > 5000:
                raw = raw[:5000]
            if raw not in seen_strings:
                seen_strings.add(raw)
                strings.append(raw)
    return comments, strings


def build_code_aware_supplement(
    path: Path,
    text: str,
    *,
    max_nodes: int = 5000,
    max_lines_per_section: int = 800,
    max_output_chars: int = 200_000,
) -> dict[str, Any]:
    suffix = str(path.suffix or "").lower()
    language = SUPPORTED_LANGUAGE_BY_SUFFIX.get(suffix)
    if not language:
        return {
            "supported": False,
            "available": None,
            "language": None,
            "supplement_text": "",
            "error": "",
        }
    try:
        parser, loader = _try_get_parser(language)
    except Exception as exc:
        return {
            "supported": True,
            "available": False,
            "language": language,
            "supplement_text": "",
            "loader": None,
            "error": str(exc),
        }

    source_bytes = str(text or "").encode("utf-8", errors="ignore")
    try:
        tree = parser.parse(source_bytes)
    except Exception as exc:
        return {
            "supported": True,
            "available": True,
            "language": language,
            "loader": loader,
            "supplement_text": "",
            "error": f"parse failed: {exc}",
        }

    root = getattr(tree, "root_node", None)
    if root is None:
        return {
            "supported": True,
            "available": True,
            "language": language,
            "loader": loader,
            "supplement_text": "",
            "error": "parser returned no root node",
        }

    comments, strings = _collect_nodes(source_bytes, root)
    comments = comments[:max_lines_per_section]
    strings = strings[:max_lines_per_section]

    lines: list[str] = []
    lines.append(f"[Tree-sitter code-aware extraction | language={language}]")
    if comments:
        lines.append("")
        lines.append("[comments]")
        lines.extend(comments)
    if strings:
        lines.append("")
        lines.append("[strings]")
        lines.extend(strings)
    supplement = "\n".join(lines).strip() if (comments or strings) else ""
    if len(supplement) > max_output_chars:
        supplement = supplement[:max_output_chars].rstrip() + "\n...[truncated]"

    return {
        "supported": True,
        "available": True,
        "language": language,
        "loader": loader,
        "supplement_text": supplement,
        "error": "",
        "stats": {
            "comments": len(comments),
            "strings": len(strings),
            "chars": len(supplement),
        },
    }
