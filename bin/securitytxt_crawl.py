#!/usr/bin/env python3
"""security.txt discovery crawler (RFC 9116).

Fetches https://<domain>/.well-known/security.txt and /security.txt, parses the
policy block, and appends one JSON record per domain to a JSONL file so runs are
resumable and diffable.

Deliberately conservative: one domain at a time per worker, 2 requests max per
domain, small body cap, no retries, identifies itself in the User-Agent.

Usage:
  python3 securitytxt_crawl.py --input tranco.csv --limit 20000 --out data/hits.jsonl
"""
import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp

UA = ("securitytxt-discovery/0.1 (RFC 9116 discovery; "
      "+https://github.com/RuneStone0/vdp-hunter)")
PATHS = ("/.well-known/security.txt", "/security.txt")
MAX_BODY = 32 * 1024
FIELDS = ("contact", "expires", "policy", "hiring", "acknowledgments",
          "preferred-languages", "canonical", "encryption", "csaf",
          "permissions-policy", "bounty", "rewards")


def parse_security_txt(text):
    """Minimal RFC 9116 parser: returns dict of lowercased field -> list[str]."""
    out = {}
    last = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            last = None
            continue
        if raw[:1] in (" ", "\t") and last:
            out[last][-1] += " " + raw.strip()
            continue
        if ":" not in raw:
            continue
        name, _, value = raw.partition(":")
        name = name.strip().lower()
        if name not in FIELDS:
            last = None
            continue
        out.setdefault(name, []).append(value.strip())
        last = name
    return out


def expiry_state(values):
    for v in values or []:
        s = v.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return "expired" if dt < now else "valid", dt.date().isoformat()
    return "missing", None


def classify(fields):
    contacts = [c for c in fields.get("contact", []) if c]
    emails = sorted({c[7:].split("?")[0] for c in contacts if c.lower().startswith("mailto:")})
    urls = [c for c in contacts if c.lower().startswith(("http://", "https://"))]
    policy = (fields.get("policy") or [None])[0]
    blob = " ".join(fields.get("bounty", []) + fields.get("rewards", []))
    return {
        "emails": emails,
        "contact_urls": urls,
        "policy": policy,
        "has_bounty_field": bool(blob),
    }


async def attempt(session, url, verify):
    """One request. Returns ('hit', fields, final_url) | ('http', status) | ('err', name)."""
    try:
        async with session.get(url, allow_redirects=True,
                               ssl=None if verify else False,
                               max_redirects=5) as r:
            if r.status != 200:
                return ("http", r.status)
            body = (await r.content.read(MAX_BODY)).decode("utf-8", "replace")
            fields = parse_security_txt(body)
            if "contact" not in fields:
                return ("http", r.status)  # answered, but not a security.txt
            return ("hit", fields, str(r.url))
    except Exception as e:  # noqa: BLE001
        return ("err", type(e).__name__)


async def probe(session, domain, path, rec):
    """https verified, https unverified only on TLS failure, plain http only as a last resort."""
    url = f"https://{domain}{path}"
    kind, *rest = await attempt(session, url, True)
    if kind == "hit":
        return rest[0], rest[1], True
    if kind == "err":
        name = rest[0]
        if any(k in name for k in ("SSL", "Certificate", "Connector")):
            rec.setdefault("tls_errors", []).append(name)
            kind, *rest = await attempt(session, url, False)
            if kind == "hit":
                return rest[0], rest[1], False
        kind2, *rest2 = await attempt(session, f"http://{domain}{path}", False)
        if kind2 == "hit":
            return rest2[0], rest2[1], False
        rec.setdefault("errors", []).append(name)
        return None
    rec.setdefault("statuses", []).append(str(rest[0]))
    return None


async def fetch_one(session, domain):
    rec = {"domain": domain,
           "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    hit = await probe(session, domain, PATHS[0], rec)
    if not hit and "404" in rec.get("statuses", []):
        hit = await probe(session, domain, PATHS[1], rec)  # legacy root path
    if not hit:
        return rec
    fields, final_url, verified = hit
    state, exp = expiry_state(fields.get("expires"))
    rec.update({
        "found_at": final_url,
        "http_status": 200,
        "tls_verified": verified,
        "expiry": state,
        "expires_on": exp,
        **classify(fields),
        "fields": {k: v for k, v in fields.items()
                   if k not in ("contact", "expires", "policy")},
    })
    return rec


async def worker(queue, session, out_fh, stats, total):
    while True:
        domain = await queue.get()
        if domain is None:
            queue.task_done()
            return
        try:
            rec = await fetch_one(session, domain)
        except Exception as e:  # noqa: BLE001
            rec = {"domain": domain, "errors": [type(e).__name__]}
        if rec.get("found_at"):
            stats["hits"] += 1
            if rec.get("expiry") == "valid":
                stats["valid"] += 1
            if rec.get("has_bounty_field"):
                stats["bounty_field"] += 1
            out_fh.write(json.dumps(rec) + "\n")
            out_fh.flush()
        stats["done"] += 1
        if stats["done"] % 500 == 0:
            rate = stats["done"] / max(time.time() - stats["t0"], 1e-9)
            print(f"{stats['done']}/{total} {rate:.0f}/s hits={stats['hits']} "
                  f"valid={stats['valid']}", flush=True)
        queue.task_done()


def load_domains(path, limit, offset):
    domains = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i < offset:
                continue
            if limit and len(domains) >= limit:
                break
            parts = line.strip().split(",")
            if len(parts) < 2:
                continue
            d = parts[-1].strip().lower().removeprefix("www.")
            if d:
                domains.append(d)
    return domains


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=150)
    ap.add_argument("--out", required=True)
    ap.add_argument("--recheck", action="store_true",
                    help="re-probe domains already recorded (picks up policy changes)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    domains = load_domains(args.input, args.limit, args.offset)
    seen = set()
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as fh:
            for line in fh:
                try:
                    seen.add(json.loads(line)["domain"])
                except Exception:  # noqa: BLE001
                    pass
    if not args.recheck:
        domains = [d for d in domains if d not in seen]
    print(f"{len(domains)} domains queued, {len(seen)} already in {args.out}", flush=True)

    queue = asyncio.Queue(maxsize=args.concurrency * 4)
    stats = {"done": 0, "hits": 0, "valid": 0, "bounty_field": 0, "t0": time.time()}
    timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_read=4)
    conn = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=1)
    headers = {"User-Agent": UA, "Accept": "text/plain,*/*;q=0.5"}

    async with aiohttp.ClientSession(timeout=timeout, connector=conn, headers=headers) as session:
        with open(args.out, "a", encoding="utf-8") as out_fh:
            workers = [asyncio.create_task(worker(queue, session, out_fh, stats, len(domains)))
                       for _ in range(args.concurrency)]
            for d in domains:
                await queue.put(d)
            for _ in workers:
                await queue.put(None)
            await queue.join()
            await asyncio.gather(*workers)

    took = time.time() - stats["t0"]
    print(json.dumps({**stats, "seconds": round(took, 1),
                      "rate_per_s": round(stats["done"] / took, 1)}, default=str))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
