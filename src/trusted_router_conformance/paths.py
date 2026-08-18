"""Resolve repository or wheel-bundled harness assets."""

from __future__ import annotations

from pathlib import Path


def repository_root() -> Path:
    """Return the directory containing drivers and scenarios."""

    source_root = Path(__file__).resolve().parents[2]
    if (source_root / "drivers").is_dir() and (source_root / "scenarios").is_dir():
        return source_root
    # Wheels carry the language adapters and scenarios beside the Python
    # package. Editable installs continue to use the repository tree so
    # contributors always execute their live files.
    packaged_root = Path(__file__).resolve().parent / "_data"
    if (packaged_root / "drivers").is_dir() and (packaged_root / "scenarios").is_dir():
        return packaged_root
    return source_root
