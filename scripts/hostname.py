#!/usr/bin/env python3
"""hostname.py — one definition of "this value cannot be a hostname", shared by the collector
that refuses to enrich such a value and by the tooling that must not ship one.

WHY IT IS SHARED, and not a check written twice. host_infra.csv row 47,571 is
domain='nginx/1.20.1"'. A run of a different collector died mid-row on 2026-09-04, the next
append landed on the same line, csv.DictReader shifted the columns, and the watcher enriched the
server header as if it were a name. Auditing that row found 43 more of the same kind from other
causes: 40 URL-shaped values written into vn_phishing_live's domain column by the 2026-07-20
backfill, and 3 copies of 'truongchinhtri. baria-vungtau.gov.vn', a name split with a space in
it. 44 rows in 57,261, and every one of them recorded zero A records, so none of them ever
carried infrastructure data. The collector now refuses them; the deposit must drop the ones
already written, and both have to mean the same thing by "hostname" or the article's row count
and the file it describes drift apart. registrable() in psl.py was moved here for the same
reason and says so.

WHAT IT IS NOT. It does not validate what a hostname SHOULD look like. IDN (xn--), deep
subdomain chains, free-hosting tenants and long names are all legitimate, and observing odd names
is what the arm exists for. It rejects what a hostname cannot contain at all.
"""
from __future__ import annotations

import csv
import re

_NOT_IN_A_HOSTNAME = re.compile(r'[\s/\\@:;,"\'()\[\]{}<>|*?!#$%^&=+~`]')


def looks_like_hostname(d: str) -> bool:
    """False for a value that cannot be a hostname, whatever else it may be."""
    if not d or len(d) > 253 or "." not in d:
        return False
    if _NOT_IN_A_HOSTNAME.search(d):
        return False
    return not (d.startswith(".") or d.endswith(".") or ".." in d)


def filter_capture_rows(src: str, dst: str | None = None) -> tuple[int, list[tuple[int, str]]]:
    """Count (and optionally write) the capture rows whose domain is a possible hostname.

    Returns (kept, dropped) where dropped is [(line number in src, the offending value)].
    With dst given, writes the kept rows there with the header intact; without it, counts only,
    so the article's table and the staged file can be produced from one pass each and still
    agree."""
    kept, dropped = 0, []
    with open(src, newline="", encoding="utf-8", errors="replace") as fh:
        rd = csv.DictReader(fh)
        out = wr = None
        if dst:
            out = open(dst, "w", newline="", encoding="utf-8")
            wr = csv.DictWriter(out, fieldnames=rd.fieldnames)
            wr.writeheader()
        try:
            for i, row in enumerate(rd, 2):
                if looks_like_hostname((row.get("domain") or "").strip().lower()):
                    kept += 1
                    if wr:
                        wr.writerow(row)
                else:
                    dropped.append((i, (row.get("domain") or "")[:60]))
        finally:
            if out:
                out.close()
    return kept, dropped
