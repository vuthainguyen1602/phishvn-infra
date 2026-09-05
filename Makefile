.PHONY: install infra benign benign-vn audit population assets clean
install:      ## install python deps
	pip install -r requirements.txt
infra:        ## one tick of the infrastructure watcher (tails data/raw/*/detections.csv)
	python scripts/watch_host_infra.py
benign:       ## one tick of the CT-sampled benign arm (3-day target age)
	python scripts/watch_ct_benign.py --age-days 3 --batches 4
benign-vn:    ## one tick of the .vn supplement
	python scripts/watch_ct_benign.py --stratum vn --age-days 3 --target 10 --max-entries 20000
audit:        ## label gate over the live-stratum phishing arm
	python scripts/audit_capture_labels.py --live
population:   ## funnel + conditioned population (refuses to fit models below the registered trigger)
	python scripts/make_infra_assets.py
assets:       ## the data article's tables and figures
	python scripts/make_capture_funnel.py && python scripts/make_infra_data_assets.py
clean:
	rm -rf data/processed/p4/p4_*.csv
