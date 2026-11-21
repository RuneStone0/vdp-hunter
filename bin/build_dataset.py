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
            "first_seen": None, "tls_verified": None,
            "disclose_maturity": None, "disclose_score": None}


def is_url(value):
    return str(value or "").lower().startswith(("http://", "https://"))


def is_ip(host):
    """A policy URL on a bare IP is not a domain anyone can attribute."""
    host = (host or "").strip("[]")
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or ":" in host


def is_platform_host(host):
    host = (host or "").lower()
    if not host:
        return True
    if host.endswith("disclose.io") or host.endswith("disclosebot.io"):
        return True
    return any(host == ph or host.endswith("." + ph) for ph in PLATFORM_HOSTS.values())


FREE_MAIL = {"gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
             "live.com", "proton.me", "protonmail.com", "icloud.com", "aol.com", "gmx.de",
             "web.de", "mail.ru", "yandex.ru", "qq.com", "163.com", "zoho.com"}


def normalize_name(name):
    """Org names differ only by case, spacing and punctuation between records."""
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def name_anchored_email(d):
    """The corporate domain, when the org's own contact address proves it.

    A contact of security@floqast.com is evidence that floqast.com is the company
    domain, stronger than a policy URL published on api-eu.floqast.app. Only
    trusted when the org name is inside the mail domain: that keeps shared desks
    like cvd@z-cert.nl from claiming an unrelated organisation.
    """
    contact = (d.get("contact") or "").strip()
    if "@" not in contact or is_url(contact):
        return None
    host = host_of("https://" + contact.split("@")[-1].strip().strip(">"))
    if not host or is_ip(host) or is_platform_host(host):
        return None
    key = registrable(host)
    name = normalize_name(d.get("name"))
    if key in FREE_MAIL or len(name) < 3:
        return None
    if name not in normalize_name(key.replace(".", "")):
        return None
    return key


def directory_host(d):
    """Where this directory row's program lives: name-anchored email, else policy."""
    anchored = name_anchored_email(d)
    if anchored:
        return anchored
    url = d.get("policy_url")
    if not url and is_url(d.get("contact")):
        url = d["contact"]
    host = host_of(url)
    if not host or is_ip(host) or is_platform_host(host):
        return None
    return registrable(host)


def fold_directory(directory):
    """Collapse records that describe the same organisation.

    The directory is submission-based, so one company can appear twice: once as a
    security.txt discovery on a subdomain, once as a hand-entered stub with no
    links at all (FloQast has exactly this pair). Records fold only when one side
    has no domain, or both resolve to the same domain: coop.co.uk and coop.no are
    different companies and must stay separate.
    """
    groups = {}
    for d in directory:
        groups.setdefault(normalize_name(d.get("name")), []).append(d)
    out, folded, kept_apart = [], 0, 0
    for _, rows in groups.items():
        if len(rows) == 1:
            out.append(rows[0])
            continue
        rows = sorted(rows, key=lambda r: (r.get("maturity_level") or 0,
                                           r.get("score") or 0,
                                           bool(r.get("policy_url"))), reverse=True)
        base = dict(rows[0])
        for other in rows[1:]:
            hb, ho = directory_host(base), directory_host(other)
            if hb and ho and hb != ho:
                out.append(other)  # genuinely different hosts: keep both
                kept_apart += 1
                continue
            folded += 1
            for field in ("policy_url",):
                if not base.get(field) and other.get(field):
                    base[field] = other[field]
            if not base.get("contact") and other.get("contact"):
                base["contact"] = other["contact"]
            base["maturity_level"] = max(base.get("maturity_level") or 0,
                                         other.get("maturity_level") or 0)
            base["maturity"] = base.get("maturity") or other.get("maturity")
            base["score"] = max(base.get("score") or 0, other.get("score") or 0)
            base.setdefault("slugs", []).append(other.get("slug"))
        out.append(base)
    return out, {"folded": folded, "kept_apart": kept_apart,
                 "in": len(directory), "out": len(out)}


def merge_disclose_directory(programs, directory):
    """Fold directory.disclose.io orgs into the program map, in place.

    Org-level rows carry no domain, so a domain is only derived from a policy or
    contact URL. Two guards keep the attribution honest:

    * an email domain is not proof of ownership (cvd@z-cert.nl is a shared
      reporting desk covering dozens of Dutch municipalities), and
    * a host claimed by three or more distinct organisations is a shared
      reporting portfolio, not one company's program.
    """
    mapped, skipped_nodomain, skipped_shared = [], 0, 0
    host_orgs = {}
    for d in directory:
        key = directory_host(d)
        if not key:
            skipped_nodomain += 1
            continue
        host_orgs.setdefault(key, set()).add((d.get("name") or key).lower())
    shared = {h for h, names in host_orgs.items() if len(names) >= 3}

    for d in directory:
        key = directory_host(d)
        if not key:
            continue
        if key in shared:
            skipped_shared += 1
            continue
        mapped.append(key)
        p = programs.get(key)
        if p is None:
            p = programs[key] = base_program(key)
        p["sources"] = sorted(set(list(p.get("sources") or []) + ["disclose-directory"]))
        if p.get("name") in (None, key) and d.get("name"):
            p["name"] = d["name"]
        p["policy"] = p.get("policy") or d.get("policy_url")
        contact = (d.get("contact") or "").strip()
        if "@" in contact and not contact.lower().startswith("http"):
            p["emails"] = sorted(set(list(p.get("emails") or []) + [contact]))
        elif is_url(contact):
            p["contact_urls"] = sorted(set(list(p.get("contact_urls") or []) + [contact]))
        if d.get("maturity_level"):
            level = int(d["maturity_level"])
            # their ladder: L3 promises no legal action, L4/L5 add explicit
            # authorisation and law exemptions. That is safe_harbor, so fold it
            # into the field the API already exposes instead of a new column.
            if level >= 4:
                p["safe_harbor"] = "full"
            elif level == 3 and not p.get("safe_harbor"):
                p["safe_harbor"] = "partial"
            p["disclose_maturity"] = d.get("maturity")
            p["disclose_score"] = d.get("score")
    return {"mapped": len(mapped), "skipped_nodomain": skipped_nodomain,
            "skipped_shared": skipped_shared, "shared_hosts": sorted(shared)}


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
        p["sources"].append(r.get("source") or "securitytxt")
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

    # 2b) disclose.io directory (~28k orgs): the public directory behind diodb.
    directory = load_json("disclose_directory.json", [])
    directory, fold_stats = fold_directory(directory)
    disclose = merge_disclose_directory(programs, directory)

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
    for d in sorted(scope):
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
        p["in_scope_domains"] = sorted(p.get("in_scope_domains") or [])
        p["emails"] = sorted(set(p["emails"]))
        p["contact_urls"] = sorted(set(p["contact_urls"]))
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
                      "platform_hosted": sum(1 for p in ordered if p["platforms"]),
                      "disclose_orgs_in": fold_stats["in"],
                      "disclose_orgs_folded": fold_stats["folded"],
                      "disclose_orgs_kept_apart": fold_stats["kept_apart"],
                      "disclose_orgs": len(directory),
                      "disclose_mapped": disclose["mapped"],
                      "disclose_skipped_nodomain": disclose["skipped_nodomain"],
                      "disclose_skipped_shared_host": disclose["skipped_shared"],
                      "disclose_shared_hosts": disclose["shared_hosts"][:10]}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
