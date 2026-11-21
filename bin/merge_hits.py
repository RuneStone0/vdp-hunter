"""Fold probe hits into the live dataset.

Reads data/hits-czds.jsonl (written by probe, one JSON object per security.txt
found), overlays them on the rows the API serves, writes data/programs.json and
posts it to /admin/reload. Nothing is pruned: a hit only ever adds.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

from build_dataset import registrable  # noqa: E402

DATA = Path(os.environ.get("VDP_DATA", ROOT / "data"))


def fetch_rows(api: str, key: str) -> list[dict]:
    out, offset = [], 0
    while True:
        req = urllib.request.Request(f"{api}/v1/programs?limit=1000&offset={offset}",
                                     headers={"X-API-Key": key})
        with urllib.request.urlopen(req, timeout=180) as r:
            body = json.load(r)
        rows = body.get("data") or []
        out.extend(rows)
        offset += len(rows)
        if not rows or offset >= body["meta"]["total"]:
            return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://192.168.1.66:8118")
    ap.add_argument("--key", default=os.environ.get("VDP_ADMIN_KEY", ""))
    ap.add_argument("--hits", default=str(DATA / "hits-czds.jsonl"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.key:
        sys.exit("VDP_ADMIN_KEY not set")

    hits_path = Path(args.hits)
    if not hits_path.exists():
        print("no hits file")
        return 0
    best: dict[str, dict] = {}
    for line in hits_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = registrable(str(hit.get("domain") or "").lower())
        if not key or "." not in key:
            continue
        best[key] = hit  # last write wins: the file is append-only, newest last

    rows = {r["domain"]: r for r in fetch_rows(args.api, args.key)}
    added = merged = 0
    for key, hit in best.items():
        row = rows.get(key)
        if row is None:
            row = rows[key] = {
                "domain": key, "name": key, "sources": [], "platforms": [], "policy": None,
                "emails": [], "contact_urls": [], "expires_on": None, "expiry": None,
                "offers_bounty": None, "safe_harbor": None, "securitytxt_url": None,
                "tls_verified": None, "in_scope_domains": [], "out_of_scope_domains": [],
                "scope_in": [], "scope_out": [], "scopes_count": 0, "submit_access": None}
            added += 1
        else:
            merged += 1
        row["sources"] = sorted(set(row.get("sources") or []) | {"czds"})
        row["policy"] = row.get("policy") or hit.get("policy")
        row["securitytxt_url"] = row.get("securitytxt_url") or hit.get("found_at")
        row["expiry"] = hit.get("expiry") or row.get("expiry")
        row["expires_on"] = hit.get("expires_on") or row.get("expires_on")
        row["emails"] = sorted(set(row.get("emails") or []) | set(hit.get("emails") or []))
        row["contact_urls"] = sorted(set(row.get("contact_urls") or [])
                                     | set(hit.get("contact_urls") or []))
        if hit.get("tls_verified") is not None:
            row["tls_verified"] = hit["tls_verified"]

    print(json.dumps({"hits": len(best), "new_programs": added, "merged": merged,
                      "total_rows": len(rows)}))
    if args.dry_run:
        return 0
    (DATA / "programs.json").write_text(json.dumps(list(rows.values()), indent=0),
                                        encoding="utf-8")
    req = urllib.request.Request(f"{args.api}/admin/reload", method="POST",
                                 headers={"X-API-Key": args.key})
    with urllib.request.urlopen(req, timeout=900) as r:
        print("reload:", r.read(300).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
