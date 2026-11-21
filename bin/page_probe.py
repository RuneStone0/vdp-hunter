#!/usr/bin/env python3
"""Second discovery channel: probe conventional disclosure pages on domains that
have no security.txt, and look for disclosure signals in the response.

This catches organizations that publish a policy page without the RFC 9116 file.

Usage:
  python3 page_probe.py --input tranco1m.csv --offset 20000 --limit 500 \
      --out data/page_hits.jsonl --concurrency 100
"""
import argparse
import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone

import aiohttp

UA = ("securitytxt-discovery/0.1 (VDP page discovery; "
      "+https://github.com/RuneStone0/vdp-hunter)")
PATHS = ("/security", "/security.txt", "/vulnerability-disclosure",
         "/responsible-disclosure", "/bug-bounty", "/security/report",
         "/trust/security")
KEYWORDS = ("responsible disclosure", "vulnerability disclosure",
            "report a vulnerability", "report security", "bug bounty",
            "security vulnerability", "coordinated disclosure",
            "security research")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.S | re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
MAX_BODY = 300 * 1024


def text_of(html):
    return TAG_RE.sub(" ", html)


def score_page(html, url):
    body = text_of(html).lower()
    hits = [k for k in KEYWORDS if k in body]
    emails = sorted({e.lower() for e in EMAIL_RE.findall(text_of(html))
                     if any(t in e.lower() for t in ("security", "abuse", "psirt", "vuln", "cert"))})[:5]
    title = (TITLE_RE.search(html).group(1).strip()[:120] if TITLE_RE.search(html) else "")
    if not hits or not (emails or "disclos" in body[:4000] or "bounty" in body[:4000]):
        return None
    return {"signal_url": url, "keywords": hits[:6], "emails": emails, "title": title}


async def attempt(session, url):
    try:
        async with session.get(url, allow_redirects=True, max_redirects=5) as r:
            if r.status != 200:
                return None
            ctype = r.headers.get("content-type", "")
            if "html" not in ctype and "text" not in ctype:
                return None
            body = (await r.content.read(MAX_BODY)).decode("utf-8", "replace")
            return score_page(body, str(r.url))
    except Exception:  # noqa: BLE001
        return None


async def worker(queue, session, out_fh, stats, total):
    while True:
        domain = await queue.get()
        if domain is None:
            queue.task_done()
            return
        found = None
        for path in PATHS:
            found = await attempt(session, f"https://{domain}{path}")
            if found:
                break
        stats["done"] += 1
        if found:
            found.update({"domain": domain,
                          "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            out_fh.write(json.dumps(found) + "\n")
            out_fh.flush()
            stats["hits"] += 1
        if stats["done"] % 100 == 0:
            print(f"{stats['done']}/{total} hits={stats['hits']}", flush=True)
        queue.task_done()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=100)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    domains, seen = [], set()
    with open(args.input, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i < args.offset:
                continue
            if len(domains) >= args.limit:
                break
            parts = line.strip().split(",")
            if len(parts) >= 2 and parts[-1].strip():
                domains.append(parts[-1].strip().lower().removeprefix("www."))
    if os.path.exists(args.out):
        seen = {json.loads(l)["domain"] for l in open(args.out, encoding="utf-8") if l.strip()}
    domains = [d for d in domains if d not in seen]
    print(f"{len(domains)} domains, {len(seen)} already done", flush=True)

    stats = {"done": 0, "hits": 0, "t0": time.time()}
    queue = asyncio.Queue(maxsize=args.concurrency * 4)
    timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_read=4)
    conn = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=1)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn,
                                     headers={"User-Agent": UA}) as session:
        with open(args.out, "a", encoding="utf-8") as out_fh:
            ws = [asyncio.create_task(worker(queue, session, out_fh, stats, len(domains)))
                  for _ in range(args.concurrency)]
            for d in domains:
                await queue.put(d)
            for _ in ws:
                await queue.put(None)
            await queue.join()
            await asyncio.gather(*ws)
    took = time.time() - stats["t0"]
    print(json.dumps({**stats, "seconds": round(took, 1),
                      "rate_per_s": round(stats["done"] / took, 1)}))


if __name__ == "__main__":
    asyncio.run(main())
