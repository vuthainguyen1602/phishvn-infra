# Data

The corpus is **not stored in this Git repository**. Version 1.0.0 will be archived on Mendeley
Data under CC BY 4.0 (DOI pending; see `README.md`, "Deposit").

The collectors write to `data/raw/<source>/` relative to the repository root; the population
build reads `data/raw/host_infra/host_infra.csv` and writes `data/processed/`. To reproduce the
deposit's derived tables, place the deposited `host_infra.csv` at `data/raw/host_infra/` and run
`make population`.
