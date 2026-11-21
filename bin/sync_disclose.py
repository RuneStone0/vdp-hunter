#!/usr/bin/env python3
"""Merge directory.disclose.io into the live dataset and write a new seed file.

The live database holds crawl history that this script must not discard, so the
merge starts from the API's current rows, applies the directory, and writes
data/programs.json in the shape /admin/reload expects.

  CZDS-style env: VDP_API=http://192.168.1.66:8118, VDP_ADMIN_KEY=...

Then, on the server side: POST /admin/reload.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

from build_dataset import (base_program, fold_directory,  # noqa: E402
                           merge_disclose_directory)

DATA = Path(os.environ.get("VDP_DATA", ROOT / "data"))


def fetch_all(api: str, key: str) -> list[dict]:
    out: list[dict] = []
    offset = 0
    while True:
        url = f"{api}/v1/programs?limit=1000&offset={offset}&sort=domain"
        req = urllib.request.Request(url, headers={"X-API-Key": key})
        with urllib.request.urlopen(req, timeout=90) as resp:
            body = json.load(resp)
        rows = body["data"]
        out.extend(rows)
        if not body["meta"].get("has_more"):
            break
        offset += len(rows)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("VDP_API", "http://192.168.1.66:8118"))
    ap.add_argument("--key", default=os.environ.get("VDP_ADMIN_KEY", ""))
    ap.add_argument("--directory", default=str(DATA / "disclose_directory.json"))
    ap.add_argument("--out", default=str(DATA / "programs.json"))
    args = ap.parse_args()

    if not args.key:
        print("need VDP_ADMIN_KEY", file=sys.stderr)
        return 2

    live = fetch_all(args.api, args.key)
    programs = {}
    for row in live:
        key = row.get("domain")
        if not key:
            continue
        p = dict(base_program(key))
        p.update({k: v for k, v in row.items() if k in p or k in ("name", "first_seen")})
        p["sources"] = list(row.get("sources") or [])
        p["platforms"] = list(row.get("platforms") or [])
        # the API does not store this, but the seed file is also read by tools
        # that expect the same shape build_dataset.py produces
        p["self_managed"] = not p["platforms"] and bool(p.get("policy") or p.get("emails"))
        programs[key] = p
    before = len(programs)

    directory = json.loads(Path(args.directory).read_text(encoding="utf-8"))
    directory, fold_stats = fold_directory(directory)
    stats = merge_disclose_directory(programs, directory)

    ordered = sorted(programs.values(), key=lambda p: p["domain"])
    Path(args.out).write_text(json.dumps(ordered, indent=1, sort_keys=True), encoding="utf-8")
    Path(args.out).with_suffix(".jsonl").write_text(
        "".join(json.dumps(p, sort_keys=True) + "\n" for p in ordered), encoding="utf-8")

    with_dir = sum(1 for p in ordered if "disclose-directory" in (p.get("sources") or []))
    print(json.dumps({"live_programs": before, "after": len(ordered),
                      "new_from_directory": len(ordered) - before,
                      "directory_orgs_in": fold_stats["in"],
                      "directory_orgs_folded": fold_stats["folded"],
                      "directory_orgs_kept_apart": fold_stats["kept_apart"],
                      "directory_orgs": len(directory),
                      "merged_rows": stats["mapped"],
                      "skipped_nodomain": stats["skipped_nodomain"],
                      "skipped_shared_host": stats["skipped_shared"],
                      "programs_with_directory_source": with_dir,
                      "folded_subdomain_rows": len(stats["folded_domains"]),
                      "folded_examples": stats["folded_domains"][:5],
                      "shared_hosts": stats["shared_hosts"][:15],
                      "out": args.out}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
