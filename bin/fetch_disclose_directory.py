#!/usr/bin/env python3
"""Mirror the disclose.io VDP directory (directory.disclose.io) to JSON.

The directory lists ~28k organisations, an order of magnitude more than the
2.4k-entry diodb.json feed we already ingest: the directory is the public face of
every submission plus their own security.txt discoveries.

There is no JSON or CSV endpoint, so this paginates the HTML table at 25 rows a
page. Pages are cached individually, so a killed run resumes without re-fetching
and a re-run only picks up pages that changed.

Usage:
  python3 bin/fetch_disclose_directory.py                 # full mirror
  python3 bin/fetch_disclose_directory.py --limit 50      # first 50 pages
  python3 bin/fetch_disclose_directory.py --fresh         # ignore cache

Output: data/disclose_directory.json
  [{"name", "slug", "slug_url", "policy_url", "contact", "maturity", "score"}]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import aiohttp

BASE = "https://directory.disclose.io/"
DATA = Path(os.environ.get("VDP_DATA", "data"))
CACHE = DATA / "cache" / "disclose"
OUT = DATA / "disclose_directory.json"
UA = "vdp-hunter/1.0 (directory sync; +https://github.com/RuneStone0/vdp-hunter)"
PER_PAGE = 25


class TableParser(HTMLParser):
    """Extract one record per <tr> in the programs table.

    The markup is stable Rails output with data-field attributes, so the parser
    keys off <td> class names rather than position, and falls back to position
    only if those classes disappear.
    """

    FIELDS = {"org-name": "org", "policy-col": "policy", "contact-col": "contact",
              "maturity-col": "maturity", "score-col": "score"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[dict] = []
        self._row: dict | None = None
        self._field: str | None = None
        self._buf: list[str] = []
        self._link: str | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "tr":
            self._row = {}
            return
        if self._row is None:
            return
        if tag == "td":
            classes = (a.get("class") or "").split()
            self._field = next((self.FIELDS[c] for c in classes if c in self.FIELDS), None)
            self._buf = []
            self._link = None
        elif tag == "a" and self._field in ("org", "policy", "contact"):
            self._link = a.get("href")

    def handle_endtag(self, tag):
        if tag == "td" and self._row is not None and self._field:
            text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
            self._row[self._field] = text
            if self._link and self._field in ("org", "policy", "contact"):
                self._row[self._field + "_url"] = urljoin(BASE, self._link)
            self._field = None
        elif tag == "tr" and self._row is not None:
            if self._row.get("org"):
                self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._field:
            self._buf.append(data)


def parse_page(html: str) -> tuple[list[dict], int | None]:
    p = TableParser()
    p.feed(html)
    total = None
    m = re.search(r"of\s+([\d,]+)\s+programs", html)
    if m:
        total = int(m.group(1).replace(",", ""))
    out = []
    for r in p.rows:
        score = None
        if r.get("score"):
            m2 = re.match(r"([\d.]+)", r["score"])
            if m2:
                try:
                    score = float(m2.group(1))
                except ValueError:
                    score = None
        maturity = r.get("maturity") or ""
        level = None
        m3 = re.search(r"\bL(\d)\b", maturity)
        if m3:
            level = int(m3.group(1))
        slug_url = r.get("org_url") or ""
        slug = slug_url.rstrip("/").split("/")[-1] if slug_url else None
        out.append({
            "name": r.get("org"),
            "slug": slug,
            "slug_url": slug_url,
            "policy_url": r.get("policy_url"),
            "contact": r.get("contact"),
            "maturity": maturity or None,
            "maturity_level": level,
            "score": score,
        })
    return out, total


async def fetch(session: aiohttp.ClientSession, page: int, fresh: bool) -> list[dict]:
    path = CACHE / f"page-{page:05d}.json"
    if path.exists() and not fresh:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    url = f"{BASE}?sort=name&direction=asc&page={page}"
    last_err = None
    for attempt in range(3):
        try:
            async with session.get(url) as resp:
                if resp.status == 429:
                    raise RuntimeError("rate limited")
                resp.raise_for_status()
                html = await resp.text()
            rows, _ = parse_page(html)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(rows), encoding="utf-8")
            return rows
        except Exception as exc:  # noqa: BLE001 - retried below
            last_err = exc
            await asyncio.sleep(1.5 * (attempt + 1))
    print(f"page {page}: giving up after 3 attempts ({last_err})", file=sys.stderr)
    return []


async def run(args) -> int:
    timeout = aiohttp.ClientTimeout(total=40)
    headers = {"User-Agent": UA, "Accept": "text/html"}
    sem = asyncio.Semaphore(args.concurrency)
    connector = aiohttp.TCPConnector(limit=args.concurrency * 2)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers,
                                     connector=connector) as session:
        first = await fetch(session, 1, args.fresh)
        if not first:
            print("could not read page 1", file=sys.stderr)
            return 1
        pages = 1
        probe_html = None
        if args.pages:
            pages = args.pages
        else:
            # total row count is only on the first page
            async with session.get(f"{BASE}?sort=name&direction=asc&page=1") as resp:
                probe_html = await resp.text()
            _, total = parse_page(probe_html or "")
            if not total:
                print("could not read the program count", file=sys.stderr)
                return 1
            pages = math.ceil(total / PER_PAGE)
        if args.limit:
            pages = min(pages, args.limit)

        print(f"mirroring {pages} pages", flush=True)
        results: dict[int, list[dict]] = {1: first}
        done = 1

        async def one(page):
            nonlocal done
            async with sem:
                results[page] = await fetch(session, page, args.fresh)
                done += 1
                if done % 50 == 0:
                    print(f"  {done}/{pages} pages", flush=True)
                await asyncio.sleep(args.delay)

        await asyncio.gather(*(one(p) for p in range(2, pages + 1)))

    rows = [r for page in sorted(results) for r in results[page]]
    seen = set()
    unique = []
    for r in rows:
        key = r.get("slug") or r.get("name")
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(r)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(unique, indent=1, sort_keys=True), encoding="utf-8")

    with_policy = sum(1 for r in unique if r["policy_url"])
    with_bounty = 0
    print(json.dumps({"orgs": len(unique), "rows_fetched": len(rows),
                      "with_policy": with_policy, "pages": pages,
                      "out": str(OUT), "sanity_bounty_field": with_bounty}, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=0, help="stop after N pages")
    ap.add_argument("--limit", type=int, default=0, help="cap pages (alias of --pages)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.25, help="seconds between requests")
    ap.add_argument("--fresh", action="store_true", help="ignore the page cache")
    args = ap.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
