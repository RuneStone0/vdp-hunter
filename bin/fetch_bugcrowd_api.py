#!/usr/bin/env python3
"""Pull Bugcrowd program scope from the API into the vdp-hunter dataset.

Runs inside the vdp-hunter container as part of a daily sync. Read-only:
GET only, two endpoints (/engagements, /engagements/{id}/engagement_briefs).

Credential, first one that exists:
  1. env BUGCROWD_TOKEN, as "name:secret" as tracker.bugcrowd.com shows it
  2. /opt/data/.bugcrowd-api (this seat's shell, two lines or one name:secret)
  3. data/bugcrowd.env with BUGCROWD_TOKEN=...
  4. data/app.env with BUGCROWD_TOKEN=...

No credential is a skip, not a failure: exit 0 with status "no_credential", so
the daily tick stays silent until a token exists. A rejected token exits 1 so
the caller can alert.

Output: data/bugcrowd_api.json in the same row shape as the upstream
bounty-targets-data file, so build_dataset.py merges it with no special case,
plus data/bugcrowd_api_status.json for the run record.

Scope shape verified against bugcrowd.com/openapi/1.4.0 (2026-11-23):
  /engagements/{id}/engagement_briefs -> attributes.scope[]
    {name, description, in_scope, sort_order, reward_range{p1_min_cents..program_max_cents},
     targets[]{name, uri, category}}
  brief attributes also carry tagline, safe_harbor_status, coordinated_disclosure,
  targets_overview, vrt_scope_rules, resources.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://api.bugcrowd.com"


def api_base():
    """Loopback override for tests only: the token must never be sent to a host
    this service did not choose."""
    override = os.environ.get("BUGCROWD_API_BASE", "")
    if not override:
        return BASE
    host = urllib.parse.urlparse(override).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("BUGCROWD_API_BASE refused: loopback overrides only")
    return override.rstrip("/")
ACCEPT = "application/vnd.bugcrowd+json"
UA = "vdp-hunter/1.0 (read-only scope sync)"
DATA = os.environ.get("VDP_DATA", os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "data"))

OPEN_STATES = {"in_progress", "active", "open", "running", "started"}
CLOSED_STATES = {"cancelled", "canceled", "completed", "closed", "ended", "paused", "draft"}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def log(**kw):
    print(json.dumps(kw, sort_keys=True), flush=True)


def read_env_file(path, key):
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except OSError:
        return ""
    return ""


def load_cred(cred_file="/opt/data/.bugcrowd-api"):
    """Return (name, secret) or None. Never prints the value."""
    raw = os.environ.get("BUGCROWD_TOKEN", "")
    if not raw:
        path = cred_file
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh.read().splitlines() if ln.strip()]
            if len(lines) >= 2:
                return lines[0], lines[1]
            if len(lines) == 1 and ":" in lines[0]:
                raw = lines[0]
    if not raw:
        for name in ("bugcrowd.env", "app.env"):
            raw = read_env_file(os.path.join(DATA, name), "BUGCROWD_TOKEN")
            if raw:
                break
    if not raw:
        return None
    name, sep, secret = raw.partition(":")
    if not sep or not name.strip() or not secret.strip():
        raise SystemExit("BUGCROWD_TOKEN must be 'name:secret'")
    return name.strip(), secret.strip()


class Client:
    def __init__(self, name, secret, interval=1.05, budget=1200):
        self.base = api_base()
        self.auth = "Token %s:%s" % (name, secret)
        self.interval = interval
        self.budget = budget
        self.spent = 0
        self._last = 0.0

    def _pace(self):
        wait = self.interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait + random.uniform(0, 0.2))
        self._last = time.time()

    def get(self, path, params=None, tries=4):
        if not path.startswith(("/engagements", "/programs")):
            raise SystemExit("refusing non-whitelisted path %r" % path)
        if self.spent >= self.budget:
            raise BudgetExhausted("request budget %d exhausted" % self.budget)
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        delay = 4.0
        for attempt in range(1, tries + 1):
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", ACCEPT)
            req.add_header("Authorization", self.auth)
            req.add_header("User-Agent", UA)
            self._pace()
            self.spent += 1
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")[:300]
                if e.code == 429 and attempt < tries:
                    ra = e.headers.get("Retry-After", "")
                    time.sleep(float(ra) if str(ra).isdigit() else delay)
                    delay *= 2
                    continue
                if e.code in (500, 502, 503, 504) and attempt < tries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise ApiError(e.code, path, body)
            except urllib.error.URLError as e:
                if attempt < tries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise ApiError(0, path, str(e.reason)[:200])
        raise ApiError(0, path, "retries exhausted")


class ApiError(Exception):
    def __init__(self, status, path, body):
        super().__init__("%s %s: %s" % (status, path, body))
        self.status = status
        self.path = path
        self.body = body


class BudgetExhausted(Exception):
    pass


def engagement_code(row):
    url = str(row.get("url") or "")
    if "/engagements/" in url:
        return url.rstrip("/").rsplit("/engagements/", 1)[1].split("/")[0].split("?")[0]
    return ""


def brief_scope(brief):
    """Flatten a published brief into in-scope and out-of-scope target lists."""
    attrs = (brief or {}).get("attributes") or {}
    ins, outs = [], []
    for group in attrs.get("scope") or []:
        bucket = ins if group.get("in_scope") else outs
        for t in group.get("targets") or []:
            value = (t.get("uri") or t.get("name") or "").strip()
            if not value:
                continue
            bucket.append({
                "type": (t.get("category") or "other")[:40],
                "target": value[:300],
                "uri": t.get("uri") or "",
                "name": (t.get("name") or value)[:200],
                "ipAddress": "",
            })
    return ins, outs


def max_payout_cents(scope_groups):
    best = 0
    for g in scope_groups or []:
        rr = g.get("reward_range") or {}
        best = max(best, int(rr.get("program_max_cents") or 0),
                   *[int(rr.get("p%d_max_cents" % n) or 0) for n in range(1, 6)])
    return best


def to_row(engagement, briefs):
    """One API engagement -> one bounty-targets-data shaped row."""
    eattrs = engagement.get("attributes") or {}
    code = eattrs.get("code") or ""
    briefs = [b for b in briefs if not (b.get("attributes") or {}).get("redacted")]
    brief = briefs[0] if briefs else {}
    battrs = brief.get("attributes") or {}
    ins, outs = brief_scope(brief)
    groups = battrs.get("scope") or []
    cents = max_payout_cents(groups)
    state = str(eattrs.get("state") or "").lower()
    row = {
        "name": (battrs.get("name") or code).strip(),
        "url": "https://bugcrowd.com/engagements/%s" % code if code else "",
        "allows_disclosure": (bool(battrs["coordinated_disclosure"])
                              if battrs.get("coordinated_disclosure") is not None else None),
        "managed_by_bugcrowd": True,
        "safe_harbor": (battrs.get("safe_harbor_status") or "").lower() or None,
        "max_payout": int(cents / 100) if cents else 0,
        "offers_bounties": bool(cents),
        "state": state or None,
        "submission_state": "open" if state in OPEN_STATES else "closed",
        "targets": {"in_scope": ins, "out_of_scope": outs},
        "tagline": battrs.get("tagline"),
        "targets_overview": battrs.get("targets_overview"),
        "brief_published_at": battrs.get("published_at"),
        "vrt_scope_rules": len(battrs.get("vrt_scope_rules") or []),
        "source": "bugcrowd-api",
    }
    return row


def fetch(cx, limit, max_engagements):
    engagements, offset = [], 0
    while len(engagements) < max_engagements:
        body = cx.get("/engagements", {"page[limit]": limit, "page[offset]": offset,
                                       "fields[engagement]": "code,name,state,ends_at,starts_at"})
        page = body.get("data") or []
        engagements.extend(page)
        total = (body.get("meta") or {}).get("total_hits")
        if not page or len(page) < limit:
            break
        if isinstance(total, int) and len(engagements) >= total:
            break
        offset += limit
    return engagements[:max_engagements]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(DATA, "bugcrowd_api.json"))
    ap.add_argument("--status", default=os.path.join(DATA, "bugcrowd_api_status.json"))
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--max-engagements", type=int, default=600)
    ap.add_argument("--budget", type=int, default=1200)
    ap.add_argument("--cred-file", default="/opt/data/.bugcrowd-api")
    args = ap.parse_args()

    started = now().isoformat()
    cred = load_cred(args.cred_file)
    if not cred:
        status = {"status": "no_credential", "checked_at": started,
                  "detail": "no BUGCROWD_TOKEN in env, %s or data/*.env" % args.cred_file}
        write_status(args.status, status)
        log(**status)
        return 0

    cx = Client(cred[0], cred[1], budget=args.budget)
    try:
        engagements = fetch(cx, args.limit, args.max_engagements)
        rows, skipped, failed = [], 0, []
        for i, eng in enumerate(engagements, 1):
            eattrs = eng.get("attributes") or {}
            if str(eattrs.get("state") or "").lower() not in OPEN_STATES:
                skipped += 1
                continue
            try:
                body = cx.get("/engagements/%s/engagement_briefs" % eng["id"],
                              {"page[limit]": 5})
            except ApiError as e:
                failed.append({"id": eng["id"], "status": e.status})
                continue
            briefs = body.get("data") or []
            if not briefs:
                skipped += 1
                continue
            rows.append(to_row(eng, briefs))
            if i % 25 == 0:
                log(progress=i, rows=len(rows), skipped=skipped, requests=cx.spent)
    except ApiError as e:
        status = {"status": "auth_failed" if e.status in (401, 403) else "error",
                  "checked_at": started, "http_status": e.status,
                  "detail": str(e)[:300], "requests": cx.spent}
        write_status(args.status, status)
        log(**status)
        return 1
    except BudgetExhausted as e:
        status = {"status": "budget_exhausted", "checked_at": started,
                  "detail": str(e), "requests": cx.spent}
        write_status(args.status, status)
        log(**status)
        return 1

    # keep rows that carry a real engagement URL; the builder keys on assets
    rows = [r for r in rows if r["url"]]
    atomic_write(args.out, json.dumps(rows, indent=1, sort_keys=True) + "\n")
    status = {
        "status": "ok",
        "checked_at": started,
        "finished_at": now().isoformat(),
        "engagements_seen": len(engagements),
        "rows": len(rows),
        "skipped_closed_or_briefless": skipped,
        "failed_briefs": failed[:20],
        "requests": cx.spent,
        "with_payout": sum(1 for r in rows if r["offers_bounties"]),
        "in_scope_targets": sum(len(r["targets"]["in_scope"]) for r in rows),
        "out_of_scope_targets": sum(len(r["targets"]["out_of_scope"]) for r in rows),
    }
    write_status(args.status, status)
    log(**status)
    return 0


def atomic_write(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_status(path, payload):
    payload = dict(payload)
    payload.setdefault("pid", os.getpid())
    atomic_write(path, json.dumps(payload, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    sys.exit(main())
