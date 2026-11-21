"""Pull YesWeHack programs and their scope.

The program list is public, but the per-program scope is not: it needs a JWT from
POST /login, which is why this exists at all. Credentials come from
/opt/data/private/yeswehack.env (YWH_EMAIL, YWH_PASSWORD) and never from argv, so
they do not land in shell history.

Output: data/yeswehack_api.json in the same normalised shape enrich_scope.py reads
(scope_in / scope_out, submit_access).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "yeswehack_api.json"
ENV = Path("/opt/data/private/yeswehack.env")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"


def call(path: str, token: str | None = None, method: str = "GET", body: dict | None = None,
         attempt: int = 0):
    req = urllib.request.Request(
        f"https://api.yeswehack.com{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Accept": "application/json", "User-Agent": UA,
                 "Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (429, 502, 503) and attempt < 4:
            time.sleep(20 + attempt * 20)
            return call(path, token, method, body, attempt + 1)
        raise


def login(email: str, password: str) -> str:
    body = call("/login", method="POST", body={"email": email, "password": password})
    token = body.get("token") or (body.get("data") or {}).get("token")
    if not token:
        sys.exit(f"login returned no token: {json.dumps(body)[:200]}")
    return token


def assets(scope: dict) -> list[dict]:
    out = []
    for item in scope.get("items") or scope.get("scopes") or []:
        target = item.get("scope") or item.get("target") or item.get("asset")
        if not target:
            continue
        out.append({"target": str(target), "type": item.get("scope_type") or item.get("type") or ""})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--pause", type=float, default=1.0)
    args = ap.parse_args()

    email = os.environ.get("YWH_EMAIL")
    password = os.environ.get("YWH_PASSWORD")
    if (not email or not password) and ENV.exists():
        for line in ENV.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "YWH_EMAIL":
                email = v.strip()
            if k.strip() == "YWH_PASSWORD":
                password = v.strip()
    if not email or not password:
        sys.exit("no YesWeHack credentials: expected YWH_EMAIL/YWH_PASSWORD in env or yeswehack.env")

    token = login(email, password)
    print("logged in", flush=True)

    programs, page = [], 1
    while True:
        body = call(f"/programs?page={page}", token)
        items = body.get("items") or body.get("data") or []
        if not items:
            break
        programs.extend(items)
        pg = body.get("pagination") or {}
        if page >= int(pg.get("total_pages") or 1):
            break
        page += 1
        if args.limit and len(programs) >= args.limit:
            break
    print(f"programs listed: {len(programs)}", flush=True)

    done = {}
    if OUT.exists():
        try:
            for prev in json.loads(OUT.read_text()):
                done[prev["slug"]] = prev
        except (json.JSONDecodeError, KeyError):
            done = {}

    out, scoped = [], 0
    for i, prog in enumerate(programs, 1):
        slug = prog.get("slug") or prog.get("title") or ""
        if not slug:
            continue
        if slug in done:
            out.append(done[slug])
            continue
        try:
            scope = call(f"/programs/{slug}/scopes", token)
        except urllib.error.HTTPError:
            scope = {}
        ins = assets(scope) if isinstance(scope, dict) else []
        rec = {
            "slug": slug,
            "handle": slug,
            "name": prog.get("title") or prog.get("name") or slug,
            "public": prog.get("public") is not False,
            "bounty": bool(prog.get("bounty") or prog.get("rewards")),
            "safe_harbour": prog.get("safe_harbor") or prog.get("safe_harbour"),
            "scope_in": ins,
            "scope_out": [],
            "submit_access": "account_required",
        }
        if ins:
            scoped += 1
        out.append(rec)
        if i % 25 == 0:
            print(f"  scopes {i}/{len(programs)}", flush=True)
            OUT.write_text(json.dumps(out, indent=0), encoding="utf-8")
        time.sleep(args.pause)

    OUT.write_text(json.dumps(out, indent=0), encoding="utf-8")
    print(json.dumps({"programs": len(out), "with_scope": scoped, "written": str(OUT)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
