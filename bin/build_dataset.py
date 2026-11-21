#!/usr/bin/env python3
"""Merge security.txt discoveries with the upstream aggregators into one dataset
plus a human-readable changelog against the previous snapshot.

Inputs (data/):
  hits.jsonl            securitytxt_crawl.py output (resumable append log)
  diodb.json            disclose.io program-list.json (self-managed + VDP)
  hackerone_data.json   arkadiyt/bounty-targets-data
  bugcrowd_data.json    ...
  intigriti_data.json   ...
  yeswehack_data.json   ...
  domains.txt           flat in-scope domain list from the same source

Outputs:
  programs.json / programs.jsonl   normalized programs (one row per registrable domain)
  NEWS.md                          added / removed / changed vs the previous programs.json
"""
import json
import os
import re
import sys
from datetime import date
from urllib.parse import urlparse

DATA = os.environ.get("VDP_DATA", "data")

# second-level suffixes worth one extra label when computing "registrable domain"
SLD = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "com.au", "net.au",
       "org.au", "co.nz", "co.jp", "or.jp", "ne.jp", "co.kr", "com.br", "com.mx",
       "com.ar", "com.co", "com.cn", "com.tw", "com.hk", "com.sg", "com.tr",
       "com.ua", "com.pl", "co.za", "co.in", "co.il", "com.my", "com.ph", "com.vn",
       "co.id", "com.sa", "com.eg", "com.ng", "co.ke", "com.pk", "com.bd"}

PLATFORM_HOSTS = {"hackerone": "hackerone.com", "bugcrowd": "bugcrowd.com",
                  "intigriti": "intigriti.com", "yeswehack": "yeswehack.com"}


def registrable(host):
    host = (host or "").lower().strip().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_of(url):
    try:
        return urlparse(url or "").netloc.split(":")[0].lower()
    except ValueError:
        return ""


def load_json(name, default):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_lines(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return {l.strip().lower() for l in fh if l.strip()}


def base_program(key):
    return {"domain": key, "name": key, "sources": [], "platforms": [], "policy": None,
            "emails": [], "contact_urls": [], "expires_on": None, "expiry": None,
            "offers_bounty": None, "safe_harbor": None, "securitytxt_url": None,
            "first_seen": None, "tls_verified": None}


def main():
    programs = {}
    today = date.today().isoformat()

    def get(key):
        if key not in programs:
            programs[key] = base_program(key)
        return programs[key]

    # 1) security.txt crawl results: last record per domain wins
    hits = {}
    hits_path = os.path.join(DATA, "hits.jsonl")
    if os.path.exists(hits_path):
        for line in open(hits_path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("found_at"):
                hits[r["domain"]] = r
    for domain, r in hits.items():
        p = get(registrable(domain))
        p["sources"].append("securitytxt")
        p["securitytxt_url"] = r.get("found_at")
        p["emails"] = sorted(set(p["emails"]) | set(r.get("emails") or []))
        p["contact_urls"] = sorted(set(p["contact_urls"]) | set(r.get("contact_urls") or []))
        p["policy"] = p["policy"] or r.get("policy")
        p["expires_on"] = p["expires_on"] or r.get("expires_on")
        p["expiry"] = p["expiry"] or r.get("expiry")
        p["tls_verified"] = r.get("tls_verified")

    # 2) disclose.io diodb (self-managed heavy)
    for d in load_json("diodb.json", []):
        hosts = [host_of(d.get("policy_url")), host_of(d.get("securitytxt_url"))]
        email_domains = [e.split("@")[-1].lower() for e in [d.get("contact_email") or ""] if "@" in e]
        key = None
        for h in hosts + email_domains:
            if h and h not in PLATFORM_HOSTS.values() and not any(h.endswith(v) for v in PLATFORM_HOSTS.values()):
                key = registrable(h)
                break
        if not key:
            continue
        p = get(key)
        p["sources"].append("diodb")
        p["name"] = p["name"] if p["name"] != key else (d.get("program_name") or key)
        p["policy"] = p["policy"] or d.get("policy_url")
        p["securitytxt_url"] = p["securitytxt_url"] or d.get("securitytxt_url")
        if d.get("offers_bounty") in ("yes", "no", "partial"):
            p["offers_bounty"] = d["offers_bounty"]
        if d.get("safe_harbor"):
            p["safe_harbor"] = d["safe_harbor"]
        if d.get("contact_email") and "@" in d["contact_email"]:
            p["emails"] = sorted(set(p["emails"]) | {d["contact_email"]})

    # 3) platform data
    for fname, plat in (("hackerone_data.json", "hackerone"), ("bugcrowd_data.json", "bugcrowd"),
                        ("intigriti_data.json", "intigriti"), ("yeswehack_data.json", "yeswehack")):
        for prog in load_json(fname, []):
            if prog.get("submission_state") not in (None, "open"):
                continue
            if prog.get("disabled") is True or str(prog.get("status", "")).lower() in ("closed", "disabled"):
                continue
            p = get(registrable(prog.get("company_handle") or prog.get("handle") or prog.get("name") or ""))
            p["sources"].append(plat)
            p["platforms"].append(plat)
            if p["name"] == p["domain"]:
                p["name"] = prog.get("name") or p["name"]
            p["offers_bounty"] = p["offers_bounty"] or ("yes" if prog.get("offers_bounties") else None)

    # 4) platform scope domains: mark any program whose host appears in scope
    scope = load_lines("domains.txt")
    for d in list(scope):
        key = registrable(d)
        if key in programs:
            programs[key]["platforms"] = sorted(set(programs[key]["platforms"]))
            programs[key].setdefault("in_scope_domains", [])
            if len(programs[key]["in_scope_domains"]) < 25:
                programs[key]["in_scope_domains"].append(d)

    for p in programs.values():
        p["sources"] = sorted(set(p["sources"]))
        p["platforms"] = sorted(set(p["platforms"]))
        p["self_managed"] = bool(p["platforms"]) is False and bool(p["policy"] or p["emails"])
        if not p.get("first_seen"):
            p["first_seen"] = today

    # diff against the previous snapshot
    old = {p["domain"]: p for p in load_json("programs.json", [])}
    added = sorted(set(programs) - set(old))
    removed = sorted(set(old) - set(programs))
    changed = []
    for k in sorted(set(programs) & set(old)):
        a, b = old[k], programs[k]
        delta = [f for f in ("policy", "expiry", "expires_on", "offers_bounty", "sources")
                 if a.get(f) != b.get(f)]
        if delta:
            changed.append((k, delta))
        programs[k]["first_seen"] = a.get("first_seen") or today

    ordered = sorted(programs.values(), key=lambda p: p["domain"])
    with open(os.path.join(DATA, "programs.json"), "w", encoding="utf-8") as fh:
        json.dump(ordered, fh, indent=1, sort_keys=True)
    with open(os.path.join(DATA, "programs.jsonl"), "w", encoding="utf-8") as fh:
        for p in ordered:
            fh.write(json.dumps(p, sort_keys=True) + "\n")

    novel = [p for p in ordered if not p["platforms"] and not any(s == "diodb" for s in p["sources"])]
    with open(os.path.join(DATA, "NEWS.md"), "w", encoding="utf-8") as fh:
        fh.write(f"# VDP dataset changes, {today}\n\n")
        fh.write(f"Programs: {len(ordered)} total, {len(novel)} not in any known list, "
                 f"{sum(1 for p in ordered if p['platforms'])} on a bounty platform.\n\n")
        for title, rows in (("New programs", added[:200]), ("Removed", removed[:200])):
            fh.write(f"## {title} ({len(rows)})\n\n")
            for k in rows:
                p = programs.get(k, old.get(k, {}))
                fh.write(f"- `{k}` {p.get('name','')} -> {p.get('policy') or p.get('emails')}\n")
            fh.write("\n")
        fh.write(f"## Changed ({len(changed)})\n\n")
        for k, delta in changed[:200]:
            fh.write(f"- `{k}`: {', '.join(delta)}\n")

    print(json.dumps({"total": len(ordered), "novel_vs_known": len(novel),
                      "added": len(added), "removed": len(removed), "changed": len(changed),
                      "platform_hosted": sum(1 for p in ordered if p["platforms"])}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
