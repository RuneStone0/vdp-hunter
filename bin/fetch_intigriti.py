"""Pull every Intigriti program the account can see, with its scope, through the
researcher API (api.intigriti.com). The API needs a personal token: this is the
source that cannot be read anonymously, so every row it yields is marked
submit_access=account_required.

Output: data/intigriti_api.json, in this repo's normalised shape.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("VDP_DATA", ROOT / "data"))
BASE = "https://api.intigriti.com/external/researcher/v1"
OUT = DATA / "intigriti_api.json"

TOKEN = os.environ.get("INTIGRITI_API_TOKEN", "")
if not TOKEN:
    env = Path("/opt/data/private/intigriti.env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("INTIGRITI_API_TOKEN="):
                TOKEN = line.split("=", 1)[1].strip()
if not TOKEN:
    sys.exit("no INTIGRITI_API_TOKEN")
if not os.environ.get("INTIGRITI_API_TOKEN"):
    os.environ["INTIGRITI_API_TOKEN"] = TOKEN  # noqa: S105


def call(path: str, attempt: int = 0):
    req = urllib.request.Request(f"{BASE}{path}", headers={
        "Authorization": f"Bearer {TOKEN}", "Accept": "application/json",
        "User-Agent": "vdp-hunter/0.1 (+dataset build)"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # 403 appears after roughly a hundred rapid detail calls: back off, do not give up
        if e.code in (403, 429, 500, 502, 503) and attempt < 4:
            time.sleep(15 + attempt * 15)
            return call(path, attempt + 1)
        raise
    except (urllib.error.URLError, TimeoutError):
        if attempt < 3:
            time.sleep(2 + attempt * 3)
            return call(path, attempt + 1)
        raise


def scope_of(detail: dict) -> tuple[list[dict], list[dict]]:
    """Intigriti publishes one flat content list; a description that says out of
    scope is the only marker, so keep those apart rather than counting them as in."""
    ins, outs = [], []
    content = ((detail.get("domains") or {}).get("content") or [])
    for item in content:
        endpoint = (item.get("endpoint") or "").strip()
        if not endpoint:
            continue
        kind = ((item.get("type") or {}).get("value") or "other")
        description = (item.get("description") or "")
        entry = {"target": endpoint[:300], "type": str(kind)[:40]}
        if "out of scope" in description.lower() or "out-of-scope" in description.lower():
            outs.append(entry)
        else:
            ins.append(entry)
    return ins, outs


def main() -> int:
    records, offset, limit = [], 0, 100
    while True:
        page = call(f"/programs?limit={limit}&offset={offset}")
        batch = page.get("records") or []
        records.extend(batch)
        offset += len(batch)
        if not batch or offset >= int(page.get("maxCount") or 0):
            break
    print(f"programs listed: {len(records)}")

    done = {}
    if OUT.exists():
        try:
            for prev in json.loads(OUT.read_text()):
                done[prev["id"]] = prev
        except json.JSONDecodeError:
            done = {}
    print(f"resuming with {len(done)} already fetched")

    out = []
    for i, rec in enumerate(records, 1):
        if rec["id"] in done:
            out.append(done[rec["id"]])
            continue
        detail = call(f"/programs/{rec['id']}")
        ins, outs = scope_of(detail)
        out.append({
            "id": rec["id"],
            "handle": rec.get("handle") or "",
            "name": rec.get("name") or rec.get("handle") or "",
            "public": (rec.get("confidentialityLevel") or {}).get("value"),
            "bounty": bool((rec.get("minBounty") or {}).get("value")),
            "safe_harbour": ((detail.get("rulesOfEngagement") or {}).get("content") or {})
                            .get("safeHarbour"),
            "scope_in": ins,
            "scope_out": outs,
            "submit_access": "account_required",
    })
        if i % 25 == 0:
            print(f"  detail {i}/{len(records)}", flush=True)
            OUT.write_text(json.dumps(out, indent=0), encoding="utf-8")
        time.sleep(0.5)

    OUT.write_text(json.dumps(out, indent=0), encoding="utf-8")
    with_scope = sum(1 for p in out if p["scope_in"] or p["scope_out"])
    print(json.dumps({"programs": len(out), "with_scope": with_scope,
                      "in_assets": sum(len(p["scope_in"]) for p in out),
                      "out_assets": sum(len(p["scope_out"]) for p in out),
                      "written": str(OUT)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
