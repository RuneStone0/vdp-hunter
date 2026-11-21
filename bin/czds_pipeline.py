"""Monthly CZDS pass: download the approved zone files, extract apex domains, probe
them for security.txt, and append the hits.

Probing is the wall, not parsing: a 5 GB .com zone parses in minutes but holds
~160M names, which is weeks of HTTP at any concurrency this host can sustain. So
zones larger than --sample-large are probed as a deterministic sample, a different
slice each month because the sample is seeded by the domain name.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("VDP_DATA", ROOT / "data"))
BIN = ROOT / "bin" / "go"
TOKEN_FILE = Path("/opt/data/private/czds_token.txt")
TLD_FILE = DATA / "czds_tlds.txt"
API = "https://czds-api.icann.org/czds/downloads/{tld}.zone"


def log(msg: str) -> None:
    print(msg, flush=True)


def download(tld: str, dest: Path, token: str) -> str:
    """Stream one zone file. Returns 'ok', 'cached', or 'token_expired'."""
    if dest.exists() and dest.stat().st_size > 0:
        age_days = (time.time() - dest.stat().st_mtime) / 86400
        if age_days < 25:
            return "cached"
    tmp = dest.with_suffix(".part")
    req = urllib.request.Request(API.format(tld=tld), headers={
        "Authorization": f"Bearer {token}", "ngsw-bypass": "true",
        "User-Agent": "vdp-hunter/0.1 (+dataset build)"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as fh:
            while chunk := r.read(1 << 20):
                fh.write(chunk)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "token_expired"
        raise
    tmp.replace(dest)
    return "ok"


def apex_names(tld: str, zone: Path, out: Path) -> int:
    if out.exists() and out.stat().st_size > 0:
        return sum(1 for _ in out.open())
    if not BIN.joinpath("zonex").exists():
        subprocess.run(["go", "build", "-o", str(BIN / "zonex"), "./cmd/zonex"],
                       cwd=ROOT / "go", check=True)
    subprocess.run([str(BIN / "zonex"), "-in", str(zone), "-tld", tld, "-out", str(out)],
                   check=True)
    return sum(1 for _ in out.open())


def deterministic_slice(src: Path, dest: Path, size: int, total: int) -> int:
    if dest.exists() and dest.stat().st_size > 0:
        return sum(1 for _ in dest.open())
    keep_ratio = min(1.0, size / max(1, total))
    kept = 0
    with src.open() as fh, dest.open("w") as out:
        for name in fh:
            name = name.strip()
            if not name:
                continue
            bucket = int.from_bytes(hashlib.blake2b(name.encode(), digest_size=4).digest(), "big")
            if bucket < keep_ratio * (1 << 32):
                out.write(name + "\n")
                kept += 1
    return kept


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tlds", default="", help="comma list, or empty for every approved TLD")
    ap.add_argument("--sample-large", type=int, default=150_000,
                    help="probe this many names from a zone bigger than --large")
    ap.add_argument("--large", type=int, default=3_000_000, help="zone size counted as large")
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--zones", default=str(ROOT / "zones"))
    ap.add_argument("--max-minutes", type=int, default=300)
    args = ap.parse_args()

    started = time.time()
    token = TOKEN_FILE.read_text().strip() if TOKEN_FILE.exists() else ""
    if not token:
        log(json.dumps({"status": "no_token"}))
        return 3
    tlds = ([t.strip() for t in args.tlds.split(",") if t.strip()] if args.tlds
            else [t.strip() for t in TLD_FILE.read_text().split() if t.strip()])
    zones = Path(args.zones)
    zones.mkdir(parents=True, exist_ok=True)
    hits = DATA / "hits-czds.jsonl"
    summary = {"tlds": len(tlds), "downloaded": 0, "cached": 0, "probed": 0, "hits": []}

    for tld in tlds:
        if (time.time() - started) / 60 > args.max_minutes:
            log("runtime cap reached, stopping")
            break
        zone = zones / f"{tld}.zone.gz"
        state = download(tld, zone, token)
        if state == "token_expired":
            log(json.dumps({"status": "token_expired", "tld": tld}))
            return 3
        summary["downloaded" if state == "ok" else "cached"] += 1
        names_file = DATA / f"domains-{tld}.txt"
        total = apex_names(tld, zone, names_file)
        target, count = names_file, total
        if total > args.large:
            target = DATA / f"sample-{tld}.txt"
            count = deterministic_slice(names_file, target, args.sample_large, total)
            log(f"{tld}: {total:,} names, probing a {count:,} name slice")
        else:
            log(f"{tld}: {total:,} names, probing all")
        before = sum(1 for _ in hits.open()) if hits.exists() else 0
        subprocess.run([str(BIN / "probe"), "-in", str(target), "-out", str(hits),
                        "-workers", str(args.workers), "-source", "czds"], check=True)
        after = sum(1 for _ in hits.open()) if hits.exists() else 0
        summary["probed"] += count
        summary["hits"].append({"tld": tld, "new": after - before})
        # a zone file is 5 GB; keep only the slices after the probe
        names_file.unlink(missing_ok=True)
        zone.unlink(missing_ok=True)

    summary["minutes"] = round((time.time() - started) / 60, 1)
    summary["hit_total"] = sum(1 for _ in hits.open()) if hits.exists() else 0
    log(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
