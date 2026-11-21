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

for tld in $TLDS; do
  zone="$ZONES/$tld.zone"
  names="$ZONES/$tld.names"
  if [ ! -s "$names" ]; then
    if [ ! -s "$zone" ]; then
      echo "[$(date -u +%FT%TZ)] downloading $tld"
      # the CZDS bearer token comes from a signed-in browser session; the Go client
      # only speaks the username/password API, which is not what this account uses
      code=$(curl -s -m 900 -o "$zone.gz" -w '%{http_code}' \
        -H "Authorization: Bearer $(cat /opt/data/private/czds_token.txt)" \
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
  ./bin/go/scan -zone "$names" -tld "$tld" -state "$STATE" -hits "$HITS" \
      -max-minutes "$MINUTES" -dns-workers 400 -port-workers 200 -http-workers 150 \
      -dns-timeout 2s -http-timeout 3s -park-days 90 -park-clean-days 30
  # once every name in a zone is parked the file is no longer needed
  rm -f "$zone"
done

# fold whatever was found into the live dataset
if [ -s "$HITS" ]; then
  .venv/bin/python bin/merge_hits.py --api http://192.168.1.66:8118
fi
