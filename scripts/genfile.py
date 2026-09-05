#!/usr/bin/env python3
"""genfile.py — Atomic file writer for generated paper assets.

Guarantees content is completely formed before touching disk and atomically
replaces the target file to avoid half-written or zero-byte assets.
"""

from __future__ import annotations
import os
import tempfile


def write_generated(path: str, text: str, note: str = "") -> str:
    """Atomically write `text` to `path`. Raises rather than emit an empty asset."""
    if not text or not text.strip():
        raise ValueError(f"refusing to write an empty generated file: {path}")
    if not text.endswith("\n"):
        text += "\n"
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".gen-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)          # atomic within a filesystem
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f"[+] {path}{(' ' + note) if note else ''}")
    return path
