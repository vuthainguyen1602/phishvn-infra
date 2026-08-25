# `vn_filter`: the alignment rule and `ALIGNED_MIN_TOKEN = 6`

**Applies to:** `scripts/vn_filter.py`.

A match on the separator-stripped spelling counts only when it is whole segments glued together:
it must start where a segment starts, end where one ends, and be at least `ALIGNED_MIN_TOKEN`
long.

## Why the alignment rule

Removing separators fuses the fragments on either side, so without the rule a token lands inside
the join constantly:

| fused spelling | source | what it hits |
|---|---|---|
| `raghul-designer` → `ldesign` | global feed | the generic English suffix the URL corpus's own token audit flags |
| `0q00vc-bq` → `vcb` | global feed | a bank token |
| a UUID's `-bccc-` → `cccd` | global feed | an ID token |

The length floor then clears the residue that is aligned but still accidental (`c-ccd` → `cccd`).

Matching the fused spelling is restricted to the hand-curated core: the registry-generated tier's
audited precision is 0.10 on the raw name already, and a fused spelling multiplies its surface
(`app-net` → `appnet`).

## Measured 2026-08-18

Against both populations that matter — 23 domains the live collector admitted from the global
feeds in one hour, and the ChongLuaDao mirror, which is Vietnamese-targeting by provenance:

| rule | real | junk |
|---|---|---|
| no rule at all | 9 | 23 (33 admissions that hour) |
| aligned + floor 6 | 9 | **0** |

Validating against ChongLuaDao alone hides all of this: a corpus where every entry is
Vietnamese-targeting cannot exhibit a false positive.

## What the rule is worth, measured rather than argued

5 marginal admissions on the ChongLuaDao mirror (`vietin-bank`, `ngan-hang-he-thong`,
`khach-hang-ca-nhan`, `nang-cap-khach-hang`, `cong-thanh-toan-the24h`) and 3 on the global feeds,
all via `tiktokshop`.

**A correction worth keeping.** An earlier version of this rationale justified the rule by the
`mb-bank` / `tp-bank` / `sea-bank` class. Those four strings were invented for the tests and
appear in neither feed. The only real hyphen-split bank name in either corpus is `my-acb-bank.com`,
and the raw path catches it through `\bacb\b` without this rule.
