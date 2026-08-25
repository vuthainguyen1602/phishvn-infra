#!/usr/bin/env python3
"""
vn_filter.py — Shared Vietnamese-targeting detection for phishing domains and page content.

Two signals, used across the collection scripts (watch_chongluadao.py, fetch_phishing_feeds.py,
build_content_manifest.py):
  * is_vn_target(domain): the domain is .vn OR its NAME contains a Vietnamese unaccented token
    (vietcombank247, 247-napas, giaohang..., chinhphu, dichvucong, ...). Catches VN phishing on
    international TLDs, which the .vn filter alone misses.
  * is_vietnamese_text(text): the rendered page text carries Vietnamese diacritics above a small
    density threshold — used after crawling to confirm the content is actually Vietnamese.

is_vn_target() additionally matches brand tokens generated from the Tin Nhiem Mang
trusted-org registry (data/processed/brand_tokens.json, built by build_brand_tokens.py)
when that file exists; VN_TOKENS stays as the hand-curated base.
"""
from __future__ import annotations
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

BRAND_TOKENS_PATH = Path(ROOT) / "data" / "processed" / "brand_tokens.json"

VN_TOKENS = re.compile(
    r"(vietcom|vcb|techcom|\btcb\b|agribank|sacombank|mbbank|vpbank|tpbank|bidv|\bacb\b|\bocb\b|"
    r"hdbank|shinhan|eximbank|seabank|lpbank|baoviet|fecredit|vietinbank|"  # VN-only brands the registry
    # extension never supplied. Global lenders with a VN branch (Home Credit, Mirae Asset) stay out
    # by the same rule the registry guard uses: they attract worldwide, not VN-targeting, phishing.
    r"napas|momo|zalopay|vnpay|viettelpay|nganhang|taikhoan|thanhtoan|"
    r"chuyentien|nhantien|naptien|ruttien|vaytien|tietkiem|tindung|chinhphu|congan|\bthue\b|"
    r"thuedientu|\bgdt\b|"  # e-tax portal thuedientu.gdt.gov.vn — top impersonation target; \bthue\b alone misses the fused form
    r"baohiem|bhxh|bhyt|dichvucong|vneid|cccd|canhcuoc|shopee|lazada|sendo|tiktokshop|muahang|"
    r"khuyenmai|trungthuong|nhanqua|tichdiem|giaohang|vanchuyen|buukien|donhang|ghtk|\bghn\b|"
    r"vietnampost|viettel|vinaphone|mobifone|\bvnpt\b|napthe|muathe|thecao|khachhang|dangnhap|"
    r"dangky|xacminh|xacnhan|capnhat|kichhoat|baomat|the-visa|thevisa|luadao|vietnam|\bvn-|-vn\b)",
    re.I)

VN_CHARS = set("ăâđêôơưàảãáạằẳẵắặầẩẫấậèẻẽéẹềểễếệìỉĩíịòỏõóọồổỗốộờởỡớợùủũúụừửữứựỳỷỹýỵ")

# The single-tone vowels above are shared with French, Portuguese, Spanish and Italian, so density
# over VN_CHARS alone does not identify Vietnamese. It fired on the dotPH registry parking page
# whenever that page rendered its category list in a Romance language ("Éducation", "Notícias e
# Política"), and on Chrome's own error pages in those locales. Vietnamese text of any length also
# carries the letters below, which none of those languages use.
SHARED_LATIN_DIACRITICS = set("àáâèéêìíòóôùúýãõ")
VN_ONLY_CHARS = VN_CHARS - SHARED_LATIN_DIACRITICS

# Even VN_ONLY_CHARS is not Vietnamese-only: `ă` is Romanian, `đ` Croatian and Serbian, and the
# dot-below vowels `ẹ ọ ị ụ` are Yoruba and Igbo. A localised Chrome error screen in any of those
# would pass exactly as the French one did. What no other language does is STACK a base modifier
# (breve, circumflex, horn) under a tone mark, so these letters carry the language on their own.
# Cost on the 2026-08-18 captures: 5 of 2,631 accepted pages lack one, and all five are the same
# "Website này đã đóng" closure notice -- a non-page the quality gate wants gone anyway.
VN_STACKED_CHARS = set("ằẳẵắặầẩẫấậềểễếệồổỗốộờởỡớợừửữứự")

# The second route, for Vietnamese that happens to use none of the stacked letters -- short lures
# especially: "Cảnh báo: tài khoản của bạn sẽ bị khóa" carries five VN-exclusive letters and not
# one stacked. The threshold comes from the confusable languages' own inventories, not from taste:
# Romanian reaches 1 of these letters, Croatian 1, Yoruba 2, Igbo 3, because none of them has
# `ă đ ơ ư` together with the hook and dot-below vowels. Four is the first count they cannot reach.
VN_ONLY_DISTINCT_MIN = 4


def load_brand_regex(path: Path = BRAND_TOKENS_PATH) -> re.Pattern | None:
    """Compile the registry-generated brand tokens; None if the file is absent/invalid.

    Losing this file is not small: it carries 1,798 tokens and its absence removes ~6% of the
    admissions on a Vietnamese-targeting feed. The public mirror ships this module but excludes
    data/processed/, so it runs at None and reproduces a different filter than the paper
    describes -- which is why the fallback now says so on stderr instead of being silent. The
    comprehension moved inside the guard as well: an entry missing "mode" used to raise at import
    time and take every collector down with it.
    """
    try:
        entries = json.loads(Path(path).read_text(encoding="utf-8"))["tokens"]
        parts = [re.escape(e["token"]) if e["mode"] == "substring"
                 else rf"\b{re.escape(e['token'])}\b" for e in entries if e.get("token")]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"[!] vn_filter: brand tokens unavailable ({type(exc).__name__}: {path}); "
              f"is_vn_target falls back to the hand-curated core alone", file=sys.stderr)
        return None
    if not parts:
        print(f"[!] vn_filter: brand token file {path} compiled to nothing", file=sys.stderr)
        return None
    return re.compile("(" + "|".join(parts) + ")", re.I)


BRAND_TOKENS = load_brand_regex()


def host_of(url: str) -> str:
    """URL -> bare host. The leading www. is dropped: feeds list both forms of the same site (16,779
    of the 34,350 ChongLuaDao entries are a www./bare pair), and keeping them apart spent roughly
    half of that arm's urlscan quota re-capturing pages it already held."""
    h = re.sub(r"^(?:[a-z][a-z0-9+.-]*:)?//", "", (url or "").strip().lower())   # scheme, or bare //
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.rsplit("@", 1)[-1]                       # drop any user:password@
    if h.startswith("["):                          # IPv6 literal keeps its brackets
        h = h.split("]")[0] + "]"
    else:
        h = h.split(":")[0]                        # otherwise strip the port
    h = h.strip(".")
    return h[4:] if h.startswith("www.") else h


def _match_tokens(d: str) -> bool:
    return bool(VN_TOKENS.search(d)) or bool(BRAND_TOKENS and BRAND_TOKENS.search(d))


# A match on the separator-stripped spelling counts only when it is whole segments glued
# together: it must START where a segment starts, END where one ends, and be at least this long.
# Restricted to the hand-curated core -- the registry tier's audited precision is 0.10 on the raw
# name already, and a fused spelling multiplies its surface (app-net -> appnet).
# The 9-real/0-junk measurement behind the floor of 6, and the correction to an earlier and wrong
# justification for it: docs/decisions/vn-filter-aligned-min-token.md
ALIGNED_MIN_TOKEN = 6


def name_segments(domain: str) -> list[list[str]]:
    """The domain's own word split, kept per label: each label is punycode-decoded and stripped of
    diacritics, then cut on hyphens and underscores.

    The nesting matters. Flattening the labels into one list lets a label's tail fuse with the TLD,
    which is how `dmg-tech.com` came to match `techcom` -- `tech` and `com` are adjacent segments
    and the join between them is a dot, not a hyphen. A dot is never crossed.
    """
    out = []
    for label in (domain or "").lower().split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        label = unicodedata.normalize("NFD", label)
        label = "".join(c for c in label if not unicodedata.combining(c)).replace("\u0111", "d")
        segs = [seg for seg in re.split(r"[-_]+", label) if seg]
        if segs:
            out.append(segs)
    return out


def _match_fused(domain: str) -> bool:
    for segs in name_segments(domain):
        fused = "".join(segs)
        starts, ends, pos = set(), set(), 0
        for seg in segs:
            starts.add(pos)
            pos += len(seg)
            ends.add(pos)
        for m in VN_TOKENS.finditer(fused):
            if len(m.group(0)) >= ALIGNED_MIN_TOKEN and m.start() in starts and m.end() in ends:
                return True
    return False


def is_vn_target(domain: str) -> bool:
    """The raw host is tested first, so hyphen-dependent patterns (-vn\b, \bvn-) keep matching and
    the fused spelling is a pure addition on top, never a replacement."""
    # A float NaN reaching here is ordinary -- it is what an empty pandas cell becomes -- and it
    # used to raise AttributeError inside .lower(), crashing whatever loop was scanning a CSV.
    if not isinstance(domain, str):
        return False
    d = domain.lower()
    return d.endswith(".vn") or _match_tokens(d) or _match_fused(d)


def visible_text(html: str) -> str:
    """Rendered text of a captured page: script/style/noscript dropped, tags stripped.

    is_vietnamese_text must be given THIS, not the raw file. Markup dilutes diacritic density by
    roughly 30x -- a real Vietnamese page scores ~0.14 on its visible text and ~0.004 on its HTML,
    and the 0.008 threshold sits inside the diluted range, so scoring the raw file measures how
    much markup surrounds the text rather than what language it is in. A label audit did that
    while documenting the gate as shared with the capture manifest; the two disagreed on 73 domains.
    """
    t = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html or "")
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", t)).strip()


def is_vietnamese_text(text: str, threshold: float = 0.008) -> bool:
    """Diacritic density above `threshold`, AND at least one Vietnamese-exclusive letter.

    The exclusivity requirement is what separates Vietnamese from other diacritic-bearing Latin
    text. It is a presence test rather than a second density, because the two populations do not
    overlap: measured over the 2026-08-18 captures, junk pages that passed on shared diacritics
    alone carry zero VN-exclusive letters, while real Vietnamese pages sit at a median density of
    0.12. Every threshold in [0, 0.002] therefore separates them identically.
    """
    # NFC first. Vietnamese written with combining marks decomposes to bare Latin plus combining
    # codepoints, none of which are in either set, so a decomposed page scored as not Vietnamese.
    low = unicodedata.normalize("NFC", text or "").lower()
    if not low:
        return False
    if not (any(c in VN_STACKED_CHARS for c in low)
            or len({c for c in low if c in VN_ONLY_CHARS}) >= VN_ONLY_DISTINCT_MIN):
        return False
    return sum(1 for c in low if c in VN_CHARS) / len(low) > threshold
