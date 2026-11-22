#!/usr/bin/env bash
# Monthly zone sweep on the host, resumable by design.
#
# Each name that is decided (no DNS answer, no policy) is parked in a sharded set
# under $STATE, so a run that stops at its time budget picks up where it left off
# next night instead of starting over. Tier A TLDs run every month, Tier B every
# three months, the rest on the same tiering but treated as low priority.
set -uo pipefail
cd "$(dirname "$0")/.."

STATE=${STATE:-/opt/data/vdp-zone-state}
ZONES=${ZONES:-/opt/data/vdp-zones}
HITS=${HITS:-data/hits-czds.jsonl}
MINUTES=${MINUTES:-480}          # eight hours a night
TIER=${1:-A}

mkdir -p "$STATE" "$ZONES"

case "$TIER" in
  A) TLDS="com net app" ;;
  C) TLDS="${TLDS_OVERRIDE:?set TLDS_OVERRIDE}" ;;
  B) TLDS="io co org dev tech shop site studio xyz cloud ai" ;;
  *) TLDS="$(tr '\n' ' ' < data/czds_tlds.txt)" ;;
esac

set -a; . /opt/data/private/vdp-hunter.env; set +a
API=${API:-http://192.168.1.66:8118}

# the token is installed through the intake page and lives in the service, so the
# sweep asks the API for it rather than reading a file only the service can write
CZDS_TOKEN=$(curl -s -m 20 -H "X-API-Key: $VDP_ADMIN_KEY" "$API/admin/czds-token" \
  | .venv/bin/python -c "import sys,json;print((json.load(sys.stdin).get('data') or {}).get('token',''))" 2>/dev/null)
[ -z "$CZDS_TOKEN" ] && CZDS_TOKEN=$(cat /opt/data/private/czds_token.txt 2>/dev/null)

for tld in $TLDS; do
  zone="$ZONES/$tld.zone"
  names="$ZONES/$tld.names"
  if [ ! -s "$names" ]; then
    if [ ! -s "$zone" ]; then
      echo "[$(date -u +%FT%TZ)] downloading $tld"
      # the CZDS bearer token comes from a signed-in browser session; the Go client
      # only speaks the username/password API, which is not what this account uses
      code=$(curl -s -m 900 -o "$zone.gz" -w '%{http_code}' \
        -H "Authorization: Bearer $CZDS_TOKEN" \
        -H 'ngsw-bypass: true' \
        "https://czds-api.icann.org/czds/downloads/$tld.zone")
      if [ "$code" != "200" ]; then
        echo "  download failed for $tld: http $code (token expired?)"
        rm -f "$zone.gz"
        continue
      fi
      gunzip -c "$zone.gz" > "$zone" && rm -f "$zone.gz"
    fi
    ./bin/go/zonex -in "$zone" -tld "$tld" -out "$names" || continue
  fi
  echo "[$(date -u +%FT%TZ)] scanning $tld ($(wc -l < "$names") names, budget ${MINUTES}m)"
  out=$(./bin/go/scan -zone "$names" -tld "$tld" -state "$STATE" -hits "$HITS" \
      -max-minutes "$MINUTES" -dns-workers 400 -port-workers 200 -http-workers 150 \
      -dns-timeout 2s -http-timeout 3s -park-days 90 -park-clean-days 30)
  echo "$out"
  # the /scans page reads these snapshots, so a sweep is visible while it runs
  TLD="$tld" LINE="$out" .venv/bin/python - <<'PY'
import json, os, re, urllib.request
line = os.environ.get("LINE", "")
kv = dict(re.findall(r"(\w+)=([\d.]+)", line))
payload = {"tld": os.environ["TLD"], "names": int(kv.get("names", 0)),
           "checked": int(kv.get("checked", 0)), "parked": int(kv.get("parked_skip", 0)),
           "hits": int(kv.get("hits", 0)), "seconds": float(kv.get("seconds", 0)),
           "rate": float(kv.get("rate", 0)),
           "stopped_early": kv.get("shards_stopped_early", "0") not in ("0", "")}
req = urllib.request.Request("http://192.168.1.66:8118/admin/scan-status",
    data=json.dumps(payload).encode(), method="POST",
    headers={"X-API-Key": os.environ["VDP_ADMIN_KEY"],
             "Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=30).read()
except Exception as e:
    print("  status post failed:", e)
PY
  # once every name in a zone is parked the file is no longer needed
  rm -f "$zone"
done

# fold whatever was found into the live dataset
if [ -s "$HITS" ]; then
  .venv/bin/python bin/merge_hits.py --api http://192.168.1.66:8118
fi
