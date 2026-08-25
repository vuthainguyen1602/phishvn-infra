# CT benign arm: why certificate age is rotated, and why these six targets

**Applies to:** `scripts/ops/ct_benign_run.sh` (matched arm), `scripts/ops/ct_benign_vn_run.sh`
(`.vn` supplement). Both wrappers carry the traps inline; this file holds the evidence.

## Why rotate at all

A constant `--age-days` would hand the benign arm a constant certificate age, and the detection study would then be
comparing "3 days old" against whatever ages the phishing arm happens to carry — a result decided
by the wrapper rather than by the data. On the `.vn` arm the same constant would make certificate
age a label marker in the one registry group the endpoint is read on. Cycling the target across
the hour of the day gives the arm an age spread the protocol can match against.

## Two traps, both already hit in production

**It requires an hourly cron line.** The rotation reads the hour mod 6, so it only visits all six
strata if every hour occurs. On the `*/2` cadence the other collectors use, the hour is always
even and half the targets would never be reached — the constant-age artefact this rotation exists
to prevent, reintroduced by the schedule instead of by the flag. Schedule `N * * * *`, not
`N */2 * * *`. 24 is divisible by 6, so each target gets four ticks a day.

Deployed on a `*/4` line until 2026-08-16, which pinned `AGE=1` for every run — 62/63 ticks.

**`date +%H` emits a leading zero.** Hours 08 and 09 crashed outright because bash arithmetic
reads that as octal. Hence the `10#` base prefix in both wrappers. Keep it.

## Widened 2026-08-24, from 1/3/7/14 (PREREG amendment of that date)

The spread is not the quantity that matters. The matching cells are
(suffix × **quartile** of the phishing arm's certificate age), and all four old targets fell
inside one quartile of those.

Measured 2026-08-24 against that day's edges `[0.96, 15.28, 37.74]` days:

- **Matched arm:** short 129 of its 435 wanted cells, 47 of them in the youngest quartile alone,
  while the quartile the old rotation oversupplied had rows to spare.
- **`.vn` arm:** bin 1 held 26 rows against a demand of 12 — 14 collected and unusable — while
  bin 0 held 1 against 18, bin 3 held 4 against 21, and the no-certificate cell held 0 against 9.

Collecting faster could not fix either; only collecting elsewhere on the age axis can. The current
targets straddle all four quartiles, weighted towards the two starved ends.

**The edges are quantiles and move as the phishing arm grows — re-measure before treating these
targets as fixed.**

## Why 0.4 and 0.8 rather than 0

`--age-days 0` reads the log HEAD, which the sampler's own docstring warns manufactures "benign
has newer certs". Twelve hours is inside the first quartile without being the head.
