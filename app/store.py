"""SQLite store for the vdp-hunter API.

One `programs` table holds the current dataset. Every ingest run diffs the new
dataset against the stored one, writes `changes` rows, and records a `runs` row,
so the API can serve both current state and history.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

FIELDS = ("name", "sources", "platforms", "policy", "emails", "contact_urls",
          "expires_on", "expiry", "offers_bounty", "safe_harbor",
          "securitytxt_url", "tls_verified", "in_scope_domains")
JSON_FIELDS = {"sources", "platforms", "emails", "contact_urls", "in_scope_domains"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    domain TEXT PRIMARY KEY,
    name TEXT, sources TEXT, platforms TEXT, policy TEXT,
    emails TEXT, contact_urls TEXT, expires_on TEXT, expiry TEXT,
    offers_bounty TEXT, safe_harbor TEXT, securitytxt_url TEXT,
    tls_verified INTEGER, in_scope_domains TEXT,
    first_seen TEXT, last_seen TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_programs_expiry ON programs(expiry);
CREATE INDEX IF NOT EXISTS idx_programs_policy ON programs(policy);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, run_id INTEGER, kind TEXT NOT NULL, domain TEXT NOT NULL,
    fields TEXT, before TEXT, after TEXT
);
CREATE INDEX IF NOT EXISTS idx_changes_ts ON changes(ts);
CREATE INDEX IF NOT EXISTS idx_changes_domain ON changes(domain);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT, finished_at TEXT, kind TEXT,
    chunk_offset INTEGER, chunk_size INTEGER, probes INTEGER, hits INTEGER,
    added INTEGER, removed INTEGER, changed INTEGER, note TEXT
);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY, tier TEXT NOT NULL, owner TEXT,
    created_at TEXT, revoked INTEGER DEFAULT 0
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---------- state ----------
    def get_state(self, key: str, default: str | None = None) -> str | None:
        with self.conn() as c:
            row = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key: str, value: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO state(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # ---------- keys ----------
    def add_key(self, key: str, tier: str, owner: str = "") -> None:
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO api_keys(key,tier,owner,created_at,revoked) "
                      "VALUES(?,?,?,?,0)", (key, tier, owner, now()))

    def key_tier(self, key: str) -> str | None:
        with self.conn() as c:
            row = c.execute("SELECT tier FROM api_keys WHERE key=? AND revoked=0",
                            (key,)).fetchone()
        return row["tier"] if row else None

    def revoke_key(self, key: str) -> bool:
        with self.conn() as c:
            cur = c.execute("UPDATE api_keys SET revoked=1 WHERE key=?", (key,))
        return cur.rowcount > 0

    # ---------- programs ----------
    def ingest(self, programs: list[dict], run_kind: str = "rebuild",
               chunk: tuple[int, int] | None = None, probes: int = 0,
               hits: int = 0, note: str = "", record_changes: bool = True,
               allow_removal: bool = False) -> dict:
        """Upsert a full dataset snapshot and record the delta against the stored state."""
        started = now()
        ts = started
        with self.conn() as c:
            prev = {r["domain"]: dict(r) for r in c.execute("SELECT * FROM programs")}
            new = {p["domain"]: p for p in programs}
            new = {d: _carry_forward(prev[d], p) if d in prev else p
                   for d, p in new.items()}

            added = sorted(set(new) - set(prev))
            removed = sorted(set(prev) - set(new))
            changed = []
            for d in sorted(set(new) & set(prev)):
                deltas = [f for f in FIELDS if _norm(prev[d].get(f)) != _norm(new[d].get(f))]
                if deltas:
                    changed.append((d, deltas))

            run_id = c.execute(
                "INSERT INTO runs(started_at,kind,chunk_offset,chunk_size,probes,hits,note) "
                "VALUES(?,?,?,?,?,?,?)",
                (started, run_kind, chunk[0] if chunk else None, chunk[1] if chunk else None,
                 probes, hits, note)).lastrowid

            if not record_changes:
                for d, p in new.items():
                    c.execute(f"INSERT OR REPLACE INTO programs(domain,{','.join(FIELDS)},"
                              "first_seen,last_seen,updated_at) VALUES(?,"
                              + ",".join("?" * len(FIELDS)) + ",?,?,?)",
                              (d, *[_dump(p.get(f)) for f in FIELDS],
                               p.get("first_seen") or ts[:10], ts[:10], ts))
                    p["first_seen"] = p.get("first_seen") or ts[:10]
                c.execute("UPDATE runs SET finished_at=?,added=?,removed=?,changed=? WHERE id=?",
                          (now(), 0, 0, 0, run_id))
                return {"run_id": run_id, "added": 0, "removed": 0, "changed": 0,
                        "seeded": len(new)}
            for d in added:
                p = new[d]
                c.execute(f"INSERT OR REPLACE INTO programs(domain,{','.join(FIELDS)},"
                          "first_seen,last_seen,updated_at) VALUES(?,"
                          + ",".join("?" * len(FIELDS)) + ",?,?,?)",
                          (d, *[_dump(p.get(f)) for f in FIELDS],
                           p.get("first_seen") or ts[:10], ts[:10], ts))
                c.execute("INSERT INTO changes(ts,run_id,kind,domain,fields,before,after) "
                          "VALUES(?,?,?,?,?,?,?)",
                          (ts, run_id, "added", d, None, None, _dumps(p)))
            # A snapshot built from a partial crawl is not evidence that a program is gone:
            # an incremental cycle only re-probes a slice, so everything outside the slice is
            # absent. Deleting on absence would erase the dataset a little more every cycle.
            if allow_removal:
                for d in removed:
                    c.execute("DELETE FROM programs WHERE domain=?", (d,))
                    c.execute("INSERT INTO changes(ts,run_id,kind,domain,fields,before,after) "
                              "VALUES(?,?,?,?,?,?,?)",
                              (ts, run_id, "removed", d, None, _dumps(prev[d]), None))
            for d, deltas in changed:
                p = new[d]
                c.execute(f"UPDATE programs SET {','.join(f'{f}=?' for f in FIELDS)},"
                          "last_seen=?,updated_at=? WHERE domain=?",
                          (*[_dump(p.get(f)) for f in FIELDS], ts[:10], ts, d))
                before = {f: _load(prev[d].get(f)) for f in deltas}
                after = {f: p.get(f) for f in deltas}
                c.execute("INSERT INTO changes(ts,run_id,kind,domain,fields,before,after) "
                          "VALUES(?,?,?,?,?,?,?)",
                          (ts, run_id, "changed", d, json.dumps(deltas),
                           json.dumps(before), json.dumps(after)))
            gone = len(removed) if allow_removal else 0
            c.execute("UPDATE runs SET finished_at=?,added=?,removed=?,changed=? WHERE id=?",
                      (now(), len(added), gone, len(changed), run_id))
        return {"run_id": run_id, "added": len(added), "removed": gone,
                "changed": len(changed), "absent": len(removed)}

    def query(self, q=None, platform=None, source=None, bounty=None, expiry=None,
              limit=100, offset=0, sort="domain"):
        where, args = [], []
        if q:
            where.append("(domain LIKE ? OR name LIKE ? OR policy LIKE ?)")
            args += [f"%{q}%"] * 3
        if platform:
            where.append("platforms LIKE ?")
            args.append(f'%"{platform}"%')
        if source:
            where.append("sources LIKE ?")
            args.append(f'%"{source}"%')
        if bounty == "yes":
            where.append("offers_bounty='yes'")
        elif bounty == "no":
            where.append("COALESCE(offers_bounty,'')!='yes'")
        if expiry:
            where.append("expiry=?")
            args.append(expiry)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sort = sort if sort in ("domain", "expiry", "expires_on", "updated_at") else "domain"
        with self.conn() as c:
            total = c.execute(f"SELECT COUNT(*) n FROM programs {clause}", args).fetchone()["n"]
            rows = c.execute(
                f"SELECT * FROM programs {clause} ORDER BY {sort} LIMIT ? OFFSET ?",
                (*args, limit, offset)).fetchall()
        return [_row(r) for r in rows], total

    def get(self, domain: str):
        with self.conn() as c:
            row = c.execute("SELECT * FROM programs WHERE domain=?", (domain,)).fetchone()
            if not row:
                return None
            hist = c.execute("SELECT * FROM changes WHERE domain=? ORDER BY id DESC LIMIT 20",
                             (domain,)).fetchall()
        p = _row(row)
        p["history"] = [_change(r) for r in hist]
        return p

    def changes(self, since=None, kinds=None, domain=None, limit=200, offset=0):
        where, args = [], []
        if since:
            where.append("ts>=?")
            args.append(since)
        if kinds:
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            args += list(kinds)
        if domain:
            where.append("domain=?")
            args.append(domain)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.conn() as c:
            total = c.execute(f"SELECT COUNT(*) n FROM changes {clause}", args).fetchone()["n"]
            rows = c.execute(f"SELECT * FROM changes {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                             (*args, limit, offset)).fetchall()
        return [_change(r) for r in rows], total

    def stats(self) -> dict:
        coverage = self.get_state("coverage_offset", "0")
        with self.conn() as c:
            def one(sql: str) -> int:
                return c.execute(sql).fetchone()[0]
            counts = {
                "programs": one("SELECT COUNT(*) FROM programs"),
                "contactable": one("SELECT COUNT(*) FROM programs WHERE policy IS NOT NULL "
                                   "OR emails != '[]'"),
                "bounty_paying": one("SELECT COUNT(*) FROM programs WHERE offers_bounty='yes'"),
                "platform_hosted": one("SELECT COUNT(*) FROM programs WHERE platforms != '[]'"),
                "self_managed": one("SELECT COUNT(*) FROM programs WHERE platforms='[]'"),
                "changes": one("SELECT COUNT(*) FROM changes"),
            }
            by_expiry = {r["expiry"] or "unknown": r["n"] for r in
                         c.execute("SELECT expiry, COUNT(*) n FROM programs GROUP BY expiry")}
            by_platform = {r["p"]: r["n"] for r in c.execute(
                "SELECT json_each.value p, COUNT(*) n FROM programs, json_each(programs.platforms) "
                "GROUP BY p")}
            last_run = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return {**counts, "by_expiry": by_expiry, "by_platform": by_platform,
                "coverage_offset": int(coverage or 0),
                "last_run": dict(last_run) if last_run else None,
                "generated_at": now()}

    def runs(self, limit: int = 20):
        with self.conn() as c:
            rows = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def _jsonok(v):
    return bool(v) and v not in ("null",)


EMPTY = (None, "", [], {})


def _carry_forward(prev_row: dict, prog: dict) -> dict:
    """A snapshot built from a partial crawl only adds knowledge, never erases it.

    A cycle re-probes a slice of domains. A domain that came back from upstream data
    with no live probe this time (or that simply did not answer) must not wipe the
    policy, expiry or contact details an earlier probe established: absence of a fresh
    probe is not evidence that the field disappeared. `sources` is unioned so provenance
    accumulates instead of flipping between datasets.
    """
    out = dict(prog)
    for f in FIELDS:
        old, new = _load(prev_row.get(f)), prog.get(f)
        if f == "sources":
            out[f] = sorted({*(old or []), *(new or [])})
            continue
        if f == "tls_verified":
            out[f] = new if new else old
            continue
        if new in EMPTY and old not in EMPTY:
            out[f] = old
    return out


def _dump(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return v


def _load(v):
    if isinstance(v, str) and v[:1] in "[{":
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    return v


def _norm(v):
    """Compare DB representation against the in-memory program dict, order-insensitively."""
    if isinstance(v, list):
        v = sorted(v, key=str)
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, (list, dict)):
        v = json.dumps(v)
    if v is None:
        return None
    if isinstance(v, str) and v[:1] in "[{":
        try:
            return json.dumps(json.loads(v), sort_keys=True)
        except json.JSONDecodeError:
            return v
    return v


def _row(r: sqlite3.Row) -> dict:
    p = {k: _load(r[k]) for k in r.keys()}
    p["tls_verified"] = bool(p.get("tls_verified")) if p.get("tls_verified") is not None else None
    for f in ("sources", "platforms"):
        if not isinstance(p.get(f), list):
            p[f] = json.loads(p[f]) if p.get(f) else []
    return p


def _change(r: sqlite3.Row) -> dict:
    return {"id": r["id"], "ts": r["ts"], "run_id": r["run_id"], "kind": r["kind"],
            "domain": r["domain"], "fields": _load(r["fields"]) if r["fields"] else None,
            "before": _load(r["before"]) if r["before"] else None,
            "after": _load(r["after"]) if r["after"] else None}


def _dumps(p: dict) -> str:
    return json.dumps({f: p.get(f) for f in FIELDS}, sort_keys=True, default=str)
