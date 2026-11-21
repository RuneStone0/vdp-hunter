"""Add scope (in and out) and submission access to the live dataset from the
platform dumps.

The live database is the source of truth for every row; this script only attaches
what the platforms publish about scope, keyed by the same domain the row already
uses. It rewrites data/programs.json and posts it to /admin/reload.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

from build_dataset import (asset_domains, platform_domain,  # noqa: E402
                           registrable, scope_assets)

DATA = Path(os.environ.get("VDP_DATA", ROOT / "data"))
# intigriti_api.json wins over the public dump: it is the same platform read through
# the researcher API, which the dumps do not cover
PLATFORMS = {"hackerone": "hackerone_data.json", "bugcrowd": "bugcrowd_data.json",
             "intigriti": "intigriti_data.json", "yeswehack": "yeswehack_data.json",
             "intigriti_api": "intigriti_api.json"}


def fetch_rows(api: str, key: str) -> list[dict]:
    import urllib.request
    out, offset = [], 0
    while True:
        req = urllib.request.Request(f"{api}/v1/programs?limit=1000&offset={offset}",
                                     headers={"X-API-Key": key})
        with urllib.request.urlopen(req, timeout=120) as r:
            body = json.load(r)
        rows = body.get("data") or []
        out.extend(rows)
        offset += len(rows)
        if not rows or offset >= body["meta"]["total"]:
            return out


def build_index() -> tuple[dict[str, list[tuple[str, dict]]], list[tuple[str, dict, str]]]:
    """Index a platform program under every domain its own scope names.

    Bugcrowd and YesWeHack publish no handle that is a domain, so keying by handle
    misses them entirely; the scope they publish is the only reliable link between
    the program and a row in our dataset.
    """
    index: dict[str, list[tuple[str, dict]]] = {}
    entries: list[tuple[str, dict, str]] = []
    for plat, fname in PLATFORMS.items():
        path = DATA / fname
        if not path.exists():
            continue
        for prog in json.loads(path.read_text(encoding="utf-8")):
            if "scope_in" in prog:  # already normalised by fetch_intigriti.py
                ins, outs = prog["scope_in"], prog["scope_out"]
            else:
                ins, outs = scope_assets(prog)
            keys = set(asset_domains(ins)) | set(asset_domains(outs))
            primary = platform_domain(prog)
            if primary:
                keys.add(primary)
            handle = prog.get("company_handle") or prog.get("handle") or ""
            hkey = registrable(str(handle).lower())
            if hkey and "." in hkey:
                keys.add(hkey)
            for key in keys:
                index.setdefault(key, []).append((plat, prog))
            entries.append((plat, prog, primary or (sorted(keys)[0] if keys else "")))
    return index, entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://192.168.1.66:8118")
    ap.add_argument("--key", default=os.environ.get("VDP_ADMIN_KEY", ""))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.key:
        sys.exit("VDP_ADMIN_KEY not set")

    index, entries = build_index()
    # a program's own primary domain is the only place its platform label belongs;
    # do not stamp "hackerone" onto every third-party domain a scope happens to list
    primary_labels: dict[str, set[str]] = {}
    for plat, prog, primary in entries:
        if primary:
            primary_labels.setdefault(primary, set()).add(
                "intigriti" if plat == "intigriti_api" else plat)
    rows = fetch_rows(args.api, args.key)
    print(f"live rows {len(rows):,} | companies with published scope {len(index):,}")

    enriched = with_scope = 0
    for row in rows:
        entries = index.get(row["domain"], [])
        ins, outs, plat_of = [], [], set()
        for plat, prog in entries:
            i, o = scope_assets(prog)
            if not i and not o:
                continue
            plat_of.add(plat)
            ins.extend({"platform": plat, **a} for a in i)
            outs.extend({"platform": plat, **a} for a in o)
        row["scope_in"], row["scope_out"] = ins[:400], outs[:400]
        row["scopes_count"] = len(row["scope_in"]) + len(row["scope_out"])
        row["in_scope_domains"] = sorted(set(row.get("in_scope_domains") or [])
                                         | set(asset_domains(ins)))[:200]
        row["out_of_scope_domains"] = sorted(set(asset_domains(outs)))[:200]
        if row["scopes_count"]:
            with_scope += 1
        labels = primary_labels.get(row["domain"])
        if labels:
            row["platforms"] = sorted(set(row.get("platforms") or []) | labels)
            row["sources"] = sorted(set(row.get("sources") or []) | labels)
        if "yeswehack" in (row.get("platforms") or []):
            row["submit_access"] = ("invite_only" if any(
                p.get("public") is False for pl, p in entries if pl == "yeswehack")
                else "account_required")
            enriched += 1

    # a platform program whose company has no row yet is a program we are missing:
    # Bugcrowd and YesWeHack publish no handle that is a domain, so they are created
    # here from their own scope rather than silently dropped
    created = 0
    for plat, prog, primary in entries:
        if not primary or primary in rows:
            continue
        label = "intigriti" if plat == "intigriti_api" else plat
        ins, outs = ((prog["scope_in"], prog["scope_out"]) if "scope_in" in prog
                     else scope_assets(prog))
        rows[primary] = {
            "domain": primary, "name": prog.get("name") or primary, "sources": [label],
            "platforms": [label], "policy": None, "emails": [], "contact_urls": [],
            "expires_on": None, "expiry": None,
            "offers_bounty": "yes" if prog.get("bounty") or prog.get("offers_bounties") else None,
            "safe_harbor": ("full" if (prog.get("safe_harbor") is True
                                       or prog.get("safe_harbour") is True) else None),
            "securitytxt_url": None, "tls_verified": None,
            "in_scope_domains": asset_domains(ins)[:200],
            "out_of_scope_domains": asset_domains(outs)[:200],
            "scope_in": ins[:400], "scope_out": outs[:400],
            "scopes_count": len(ins) + len(outs),
            "submit_access": prog.get("submit_access"),
        }
        created += 1

    print(f"rows carrying scope {with_scope:,} | yeswehack rows marked {enriched:,} "
          f"| platform programs created {created:,}")
    if args.dry_run:
        return 0
    body = json.dumps({"programs": list(rows.values())}).encode()
    req = urllib.request.Request(f"{args.api}/admin/ingest", data=body, method="POST",
                                 headers={"X-API-Key": args.key,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as r:
        print("ingest:", r.read(300).decode())
    (DATA / "programs.json").write_text(json.dumps(rows, indent=0), encoding="utf-8")
    print(f"wrote {DATA / 'programs.json'} ({(DATA / 'programs.json').stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
