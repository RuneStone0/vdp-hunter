"""The public change feed: what the /changes page shows and what /feed.json serves.

The page is marketing, not a data tool: visitors will use the API, and the page's job is
to make the delta legible in ten rows. So this module turns a stored change row into one
human sentence plus a short field diff, and hides the values of the paid half of the
dataset behind a mask (the domain is the product; a public page that lists it daily is
the product given away). VDP_FEED_REVEAL=1 turns the mask off for local review.
"""
from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime, timezone

from .web import esc

REVEAL = os.environ.get("VDP_FEED_REVEAL", "0") == "1"
LIMIT = 10

# Ordered by how much a reader cares. "name" and "tls_verified" are last because they
# are the fields that move without meaning anything.
FIELD_ORDER = ("policy", "securitytxt_url", "emails", "contact_urls", "expires_on",
               "expiry", "platforms", "offers_bounty", "safe_harbor",
               "in_scope_domains", "out_of_scope_domains", "sources", "name",
               "tls_verified")
FIELD_LABEL = {
    "policy": "policy url", "securitytxt_url": "security.txt", "emails": "contact email",
    "contact_urls": "contact form", "expires_on": "expires on", "expiry": "expiry",
    "platforms": "platforms", "offers_bounty": "bounty", "safe_harbor": "safe harbor",
    "in_scope_domains": "in scope", "out_of_scope_domains": "out of scope",
    "sources": "sources", "name": "name", "tls_verified": "tls",
}
EXPIRY_WORD = {"valid": "valid", "expired": "expired", "missing": "no expires field",
               "unknown": "unknown", None: "unknown"}
HIDDEN_FIELDS = {"emails", "policy", "securitytxt_url", "contact_urls", "in_scope_domains",
                 "out_of_scope_domains", "name"}


def _load(v):
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v) if v else {}
    except (TypeError, ValueError):
        return {}


def _as_dict(v) -> dict:
    d = _load(v)
    return d if isinstance(d, dict) else {}


def _flat(v) -> str:
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v)
    if isinstance(v, bool):
        return "verified" if v else "unverified"
    if v in (None, "", [], {}):
        return "none"
    return str(v)


def _short(v, n: int = 88) -> str:
    s = _flat(v)
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def _slug(v) -> str:
    return re.sub(r"[^a-z0-9]", "", str(v or "").lower())


def mask_domain(domain: str) -> str:
    """Keep the shape and the TLD, hide the name: we••••••••.be."""
    parts = (domain or "").split(".")
    if len(parts) < 2:
        return domain[:2] + "\u2022" * 6
    stem, tld = parts[0], ".".join(parts[1:])
    return stem[:2] + "\u2022" * 8 + "." + tld


def _chips(kind, fields, before, after, headline_text: str = "") -> list[dict]:
    out = []
    if kind == "changed" and "sources" in fields and "security.txt discovered" not in headline_text:
        b = before.get("sources") or []
        a = after.get("sources") or []
        added = [s for s in a if s not in b]
        if "securitytxt" in added:
            out.append({"tone": "good", "label": "+security.txt"})
        elif added:
            out.append({"tone": "plat", "label": "+" + added[0]})
    if "expires_on" in fields or "expiry" in fields:
        state = after.get("expiry")
        if state == "expired":
            out.append({"tone": "bad", "label": "expired"})
        elif after.get("expires_on"):
            out.append({"tone": "neutral", "label": "expires " + str(after["expires_on"])[:10]})
        elif state:
            out.append({"tone": "neutral", "label": EXPIRY_WORD.get(state, str(state))})
    if "emails" in fields:
        b, a = set(before.get("emails") or []), set(after.get("emails") or [])
        if a - b:
            out.append({"tone": "good", "label": "new contact"})
    if before.get("policy") and "policy" in fields:
        out.append({"tone": "neutral", "label": "policy url moved"})
    if before.get("securitytxt_url") and "securitytxt_url" in fields \
            and "security.txt" not in headline_text:
        out.append({"tone": "neutral", "label": "security.txt moved"})
    if after.get("tls_verified") is True and "tls_verified" in fields:
        out.append({"tone": "neutral", "label": "tls verified"})
    # never print the headline twice
    low = headline_text.lower()
    return [c for c in out if c["label"].lower() not in low][:3]


def headline(kind: str, fields: list[str], before: dict, after: dict) -> str:
    if kind == "added":
        if after.get("platforms"):
            return "listed on " + ", ".join(after["platforms"])
        if after.get("securitytxt_url"):
            return "security.txt published"
        if after.get("policy"):
            return "disclosure policy published"
        return "program record added"
    if kind == "removed":
        if before.get("platforms"):
            return "withdrawn from " + ", ".join(before["platforms"])
        if before.get("securitytxt_url"):
            return "security.txt taken down"
        return "program record removed"
    if "sources" in fields:
        b, a = before.get("sources") or [], after.get("sources") or []
        if "securitytxt" in [s for s in a if s not in b]:
            return "security.txt discovered"
    if "platforms" in fields:
        return "platform listing changed"
    if "policy" in fields:
        return "policy url moved" if before.get("policy") else "policy url published"
    if "emails" in fields or "contact_urls" in fields:
        b, a = set(before.get("emails") or []), set(after.get("emails") or [])
        if a - b:
            return "new contact address"
        if b - a:
            return "contact address removed"
        return "contact route changed"
    if "expiry" in fields or "expires_on" in fields:
        if after.get("expiry") == "expired":
            return "policy expired"
        return "expiry date moved"
    if "safe_harbor" in fields:
        return "safe harbor status changed"
    if "in_scope_domains" in fields or "out_of_scope_domains" in fields:
        grew = (len(after.get("in_scope_domains") or []) -
                len(before.get("in_scope_domains") or []))
        if grew > 0:
            return f"scope grew by {grew}"
        if grew < 0:
            return f"scope shrank by {-grew}"
        return "scope edited"
    if "securitytxt_url" in fields:
        return "security.txt moved"
    if set(fields) <= {"name", "tls_verified", "sources"}:
        return "record re-verified"
    return "record updated"


def _fields_for(kind: str, raw_fields, before: dict, after: dict) -> list[str]:
    fields = _load(raw_fields) if isinstance(raw_fields, str) else (raw_fields or [])
    if not isinstance(fields, list):
        fields = [fields]
    if kind == "changed":
        fields = [f for f in fields if before.get(f) != after.get(f)]
        # A name that only varies by punctuation is not an edit worth a row.
        if fields and set(fields) == {"name"} and _slug(before.get("name")) == _slug(after.get("name")):
            return []
    elif kind == "added":
        fields = [f for f in FIELD_ORDER if after.get(f) not in (None, "", [], {})]
    else:
        fields = [f for f in FIELD_ORDER if before.get(f) not in (None, "", [], {})]
    return [f for f in FIELD_ORDER if f in fields]


SCOPE_FIELDS = {"in_scope_domains", "out_of_scope_domains"}


def _count(v) -> str:
    n = len(v) if isinstance(v, list) else (1 if v else 0)
    return f"{n} target" + ("" if n == 1 else "s")


def _diffs(kind: str, fields: list[str], before: dict, after: dict, locked: bool) -> list[dict]:
    out = []
    for f in fields[:4]:
        if locked and f in HIDDEN_FIELDS:
            out.append({"field": FIELD_LABEL.get(f, f), "before": None, "after": None,
                        "hidden": True})
            continue
        if f in SCOPE_FIELDS:
            out.append({"field": FIELD_LABEL.get(f, f),
                        "before": _count(before.get(f)) if kind != "added" else None,
                        "after": _count(after.get(f)) if kind != "removed" else None,
                        "hidden": False})
            continue
        out.append({"field": FIELD_LABEL.get(f, f),
                    "before": _short(before.get(f)) if kind != "added" else None,
                    "after": _short(after.get(f)) if kind != "removed" else None,
                    "hidden": False})
    return out


def _ago(ts: str, now: datetime) -> str:
    try:
        then = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    secs = int((now - then).total_seconds())
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400 * 2:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def build(rows: list[dict], now: datetime | None = None, reveal: bool | None = None) -> list[dict]:
    """Turn stored change rows (already joined with their program) into feed items."""
    now = now or datetime.now(timezone.utc)
    reveal = REVEAL if reveal is None else reveal
    items = []
    for c in rows:
        kind = c.get("kind") or "changed"
        before, after = _as_dict(c.get("before")), _as_dict(c.get("after"))
        fields = _fields_for(kind, c.get("fields"), before, after)
        if kind == "changed" and not fields:
            continue  # a row that asserts no edit is not a change
        platforms = _load(c.get("platforms") or "[]")
        if not isinstance(platforms, list):
            platforms = []
        locked = (not reveal) and not platforms
        h = headline(kind, fields, before, after)
        item = {
            "id": c.get("id"),
            "ts": c.get("ts") or "",
            "run_id": c.get("run_id"),
            "run": {
                "probes": c.get("run_probes"),
                "policies": c.get("run_hits"),
                "added": c.get("run_added"),
                "changed": c.get("run_changed"),
                "at": (c.get("run_finished") or c.get("ts") or ""),
            },
            "ago": _ago(c.get("ts") or "", now),
            "clock": (c.get("ts") or "")[11:16],
            "kind": kind,
            "locked": locked,
            "domain": mask_domain(c.get("domain") or "") if locked else (c.get("domain") or ""),
            "tld": "." + (c.get("domain") or "").split(".")[-1] if c.get("domain") else "",
            "headline": h,
            "chips": _chips(kind, fields, before, after, h),
            "fields_changed": [FIELD_LABEL.get(f, f) for f in fields][:6],
            "diffs": _diffs(kind, fields, before, after, locked),
            "platforms": platforms,
            "bounty": c.get("offers_bounty") == "yes",
        }
        if not locked:
            item["link"] = "/program/" + (c.get("domain") or "")
            payload = {"id": item["id"], "ts": item["ts"], "kind": kind,
                       "domain": c.get("domain"), "fields": fields,
                       "before": {f: before.get(f) for f in fields} or None,
                       "after": {f: after.get(f) for f in fields} or None}
            item["json"] = json.dumps(payload, indent=2, ensure_ascii=False)
        items.append(item)
    return items


def row_html(it: dict, index: int = 0, show_time: bool = True) -> str:
    chips = "".join(
        f'<span class="chip chip-{esc(c["tone"])}">{esc(c["label"])}</span>'
        for c in it.get("chips") or []) 
    if it.get("bounty"):
        chips += '<span class="chip chip-money">bounty</span>'
    for p in (it.get("platforms") or [])[:1]:
        chips += f'<span class="chip chip-plat">{esc(p)}</span>'

    if it["locked"]:
        body = (f'<div class="diff-line hidden-fields"><span class="f">'
                f'{esc(", ".join(it["fields_changed"][:4]) or "fields")}</span>'
                f'<span class="locked-note">&middot; values in the paid feed</span></div>')
        who = (f'<span class="dom">{esc(it["domain"])}</span>'
               f'<span class="lock" title="Listed only in the paid dataset">paid</span>')
        detail = ""
        cls = " locked"
    else:
        lines = []
        for d in it.get("diffs") or []:
            if d.get("hidden"):
                lines.append(f'<div class="diff-line"><span class="f">{esc(d["field"])}</span>'
                             f'<span class="locked-note">hidden</span></div>')
                continue
            b = f'<span class="b">{esc(d["before"])}</span>' if d.get("before") else ""
            a = f'<span class="a">{esc(d["after"])}</span>' if d.get("after") else ""
            lines.append(f'<div class="diff-line"><span class="f">{esc(d["field"])}</span>{b}{a}</div>')
        body = "".join(lines)
        who = f'<a class="dom" href="{esc(it["link"])}">{esc(it["domain"])}</a>'
        detail = (f'<details class="row-json"><summary>JSON</summary>'
                  f'<pre>{esc(it.get("json") or "")}</pre></details>')
        cls = ""

    return (f'<li class="tape-row kind-{esc(it["kind"])}{cls}" data-id="{esc(it["id"])}" '
            f'style="--i:{index}">'
            f'<span class="r-kind">{esc(it["kind"])}</span>'
            f'<span class="r-dom">{who}</span>'
            f'<span class="r-head">{esc(it["headline"])}{chips}</span>'
            + (f'<time class="r-when" data-ts="{esc(it["ts"])}" title="{esc(it["ts"])}">'
               f'{esc(it["ago"] or it["clock"])}</time>' if show_time else '<span></span>')
            + f'<div class="r-body">{body}</div>'
            f'{detail}</li>')


def _run_html(it: dict) -> str:
    run = it.get("run") or {}
    clock = (run.get("at") or it.get("ts") or "")[11:16]

    def n(key):
        v = run.get(key)
        return f"{int(v):,}" if isinstance(v, (int, float)) else ""

    bits = []
    if n("probes"):
        bits.append(f'{n("probes")} domains probed')
    if n("policies"):
        bits.append(f'{n("policies")} policies found')
    total = 0
    for k in ("added", "changed"):
        try:
            total += int(run.get(k) or 0)
        except (TypeError, ValueError):
            pass
    if total:
        bits.append(f"{total:,} changes written")
    if not bits and not it.get("run_id"):
        return ""  # a row outside a recorded run needs no sweep banner
    return (f'<li class="tape-run"><span class="rd">sweep {esc(clock)}</span>'
            f'<span>{" &middot; ".join(bits)}</span></li>')


def fragments(items: list[dict]) -> list[str]:
    """One HTML fragment per item, each carrying its sweep banner when it opens a run.

    The page serves these on first render and /feed.json serves them again for polls, so
    an arriving row brings its own banner and the client never has to rebuild one.
    """
    out, last_run, last_ts = [], object(), None
    for i, it in enumerate(items):
        chunk = ""
        if it.get("run_id") != last_run:
            chunk += _run_html(it)
            last_run = it.get("run_id")
            last_ts = None
        chunk += row_html(it, i, show_time=(it.get("ts") != last_ts))
        last_ts = it.get("ts")
        out.append(chunk)
    return out


def list_html(items: list[dict]) -> str:
    if not items:
        return '<li class="tape-empty">No changes recorded for that filter yet.</li>'
    return "".join(fragments(items))
