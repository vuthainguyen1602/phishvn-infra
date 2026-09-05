# Data

The corpus is **not stored in this Git repository**. Version 1.0.0 will be archived on Mendeley
Data under CC BY 4.0 (DOI pending; see `README.md`, "Deposit").

The collectors write to `data/raw/<source>/` relative to the repository root; the population
build reads `data/raw/host_infra/host_infra.csv` and writes `data/processed/`. To reproduce the
deposit's derived tables, place TWO of the deposited files and run `make population`:

    data/host_infra.csv   ->  data/raw/host_infra/host_infra.csv
    data/content_map.csv  ->  data/interim/content_map.csv

The second is easy to skip and the result is quietly smaller: without it the label gate cannot
award `content_confirmed`, so every candidate whose only positive evidence is that it renders
Vietnamese drops out and the admitted count falls by about half. The build says so when the file
is missing rather than failing, because the other arms are still correct without it.
