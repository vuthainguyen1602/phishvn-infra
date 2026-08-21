#!/usr/bin/env python3
"""
genfile.py — write a generated paper asset, or leave the previous one untouched.

WHY THIS EXISTS. `open(path, "w").write(build())` truncates the file BEFORE build() runs, so any
exception inside the generator leaves the committed asset at zero bytes. That happened here: an
import error emptied a generated .tex holding one of a manuscript's stated conclusions, LaTeX
built without complaint, and the sentence simply left the paper. In a repository whose entire
discipline is that generated files cannot go stale, silently emptying one is worse than
staleness -- a stale number looks wrong to a reader who checks, and a missing sentence looks
like nothing at all.

The same shape has a second exposure that no amount of care at the call site fixes: a run killed
partway (a timeout, a Ctrl-C) leaves a half-written file that is valid enough to compile.

So, two properties:
  * content first, file last  -- the target is not opened until the text exists;
  * atomic replace           -- the file a reader sees is always a complete previous or complete
                                new version, never a partial one.

An empty or whitespace-only body is refused rather than written. No generator in this repository
has a reason to emit one, and it is precisely the state that hides the failure above.
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
