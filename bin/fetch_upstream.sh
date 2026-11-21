#!/usr/bin/env bash
# Refresh the upstream datasets that build_dataset.py merges with our crawl.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
BASE=https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data
for f in hackerone_data.json bugcrowd_data.json intigriti_data.json yeswehack_data.json domains.txt; do
  curl -fsSL -o "data/$f" "$BASE/$f" && echo "updated data/$f"
done
curl -fsSL -o data/diodb.json \
  https://raw.githubusercontent.com/disclose/diodb/master/program-list.json && echo "updated data/diodb.json"
