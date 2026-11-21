"""Server-rendered HTML for the public data explorer.

The explorer is deliberately server-side: the JSON API needs a key, and handing a
read key to the browser would put it in view-source for anyone to copy. Everything
here renders from the same SQLite store the API serves, with parameters in the URL
so every view is linkable and cacheable.
"""
from __future__ import annotations

import html
from urllib.parse import urlencode

from .store import FIELDS  # noqa: F401  (kept for callers that introspect fields)

PER_PAGE = 50
SOURCES = ("securitytxt", "diodb", "hackerone", "bugcrowd", "intigriti",
           "yeswehack", "domains")
EXPIRY_LABEL = {"valid": "valid", "missing": "no expires", "expired": "expired",
                "unknown": "unknown", None: "unknown"}


def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


NAV = [("/", "Home"), ("/explore", "Explore"), ("/changes", "Changes"),
       ("/guide", "Docs"), ("/docs", "API reference"), ("/pricing", "Pricing")]


def nav_html(active: str) -> str:
    out = []
    for href, label in NAV:
        cls = ' class="on"' if href == active else ""
        out.append(f'<a href="{href}"{cls}>{label}</a>')
    out.append('<a href="https://github.com/RuneStone0/vdp-hunter">GitHub</a>')
    return "\n      ".join(out)


def page(shell: str, *, title: str, description: str, active: str, body: str) -> str:
    return shell.replace("{{title}}", esc(title)) \
                .replace("{{description}}", esc(description)) \
                .replace("{{nav}}", nav_html(active)) \
                .replace("{{body}}", body)


def chips(p: dict) -> str:
    out = []
    for plat in p.get("platforms") or []:
        out.append(f'<span class="chip chip-plat">{esc(plat)}</span>')
    if not p.get("platforms"):
        out.append('<span class="chip chip-own">self-managed</span>')
    if p.get("offers_bounty") == "yes":
        out.append('<span class="chip chip-money">bounty</span>')
    exp = p.get("expiry")
    if exp in ("expired",):
        out.append(f'<span class="chip chip-bad">{esc(EXPIRY_LABEL[exp])}</span>')
    elif exp in ("missing", "unknown", None):
        out.append(f'<span class="chip chip-warn">{esc(EXPIRY_LABEL.get(exp, "unknown"))}</span>')
    if p.get("tls_verified") in (0, False):
        out.append('<span class="chip chip-warn">tls unverified</span>')
    return " ".join(out)


def _qs(base: dict, **over) -> str:
    d = {k: v for k, v in {**base, **over}.items() if v not in (None, "", 0)}
    return ("?" + urlencode(d)) if d else ""


def pager(filters: dict, page_no: int, total: int) -> str:
    pages = max(1, -(-total // PER_PAGE))
    if pages <= 1:
        return ""
    bits = ['<div class="pager">']
    if page_no > 1:
        bits.append(f'<a href="/explore{_qs(filters, page=1)}">&laquo; first</a>')
        bits.append(f'<a href="/explore{_qs(filters, page=page_no - 1)}">&lsaquo; prev</a>')
    bits.append(f'<span class="pager-pos">page {page_no} of {pages}</span>')
    if page_no < pages:
        bits.append(f'<a href="/explore{_qs(filters, page=page_no + 1)}">next &rsaquo;</a>')
        bits.append(f'<a href="/explore{_qs(filters, page=pages)}">last &raquo;</a>')
    bits.append("</div>")
    return "".join(bits)


def options(values, selected, label=None) -> str:
    """Build <option> tags. Items may be plain values or (value, label) pairs."""
    out = []
    for v in values:
        val, text = (v[0], v[1]) if isinstance(v, tuple) else (v, (label(v) if label else v))
        sel = " selected" if str(val) == str(selected) else ""
        out.append(f'<option value="{esc(val)}"{sel}>{esc(text)}</option>')
    return "".join(out)


def filter_form(f: dict, by_platform: dict) -> str:
    platforms = sorted(by_platform or {}, key=lambda k: -by_platform[k])
    return f"""<form class="filters" method="get" action="/explore">
  <input class="search" type="search" name="q" value="{esc(f.get('q', ''))}"
         placeholder="Search domain, name or policy URL" autocomplete="off">
  <select name="platform">
    <option value="">Any platform</option>
    <option value="self"{" selected" if f.get('platform') == 'self' else ''}>Self-managed only</option>
    {options(platforms, f.get('platform'))}
  </select>
  <select name="bounty">
    <option value="">Bounty or not</option>
    {options(['yes', 'no'], f.get('bounty'), lambda v: 'Pays a bounty' if v == 'yes' else 'No bounty / VDP only')}
  </select>
  <select name="safe_harbor">
    <option value="">Any safe harbor</option>
    {options([('full', 'Full safe harbor'), ('partial', 'No legal action promised'),
              ('none', 'No safe harbor')], f.get('safe_harbor'))}
  </select>
  <select name="expiry">
    <option value="">Any expiry</option>
    {options(['valid', 'missing', 'expired', 'unknown'], f.get('expiry'), lambda v: EXPIRY_LABEL[v])}
  </select>
  <select name="source">
    <option value="">Any source</option>
    {options(SOURCES, f.get('source'))}
  </select>
  <select name="sort">
    {options([('domain', 'Sort: domain'), ('updated_at', 'Sort: recently updated'),
              ('expiry', 'Sort: expiry state'), ('expires_on', 'Sort: expires on')],
             f.get('sort', 'domain'))}
  </select>
  <button class="btn btn-primary" type="submit">Filter</button>
  <a class="btn btn-ghost" href="/explore">Reset</a>
</form>"""


def rows_table(rows: list[dict]) -> str:
    if not rows:
        return ('<p class="empty">Nothing matches those filters. '
                '<a href="/explore">Clear them</a> and try again.</p>')
    out = ['<div class="table-wrap"><table class="grid"><thead><tr>',
           "<th>Domain</th><th>Name</th><th>Type</th><th>Bounty</th>",
           "<th>Expiry</th><th>Last seen</th></tr></thead><tbody>"]
    for p in rows:
        out.append(
            "<tr>"
            f'<td class="mono"><a href="/program/{esc(p["domain"])}">{esc(p["domain"])}</a></td>'
            f'<td>{esc(p.get("name") or "")}</td>'
            f"<td>{chips(p)}</td>"
            f'<td>{"yes" if p.get("offers_bounty") == "yes" else "&ndash;"}</td>'
            f'<td class="mono-small">{esc(EXPIRY_LABEL.get(p.get("expiry"), "unknown"))}'
            f'{(" · " + esc(p["expires_on"])) if p.get("expires_on") else ""}</td>'
            f'<td class="mono-small">{esc(p.get("last_seen") or "")}</td>'
            "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _list(values) -> str:
    return ", ".join(esc(v) for v in (values or []))


def _links(values) -> str:
    return " ".join(f'<a href="{esc(v)}" rel="noreferrer noopener">{esc(v)}</a>'
                    for v in (values or []))


def program_body(p: dict) -> str:
    rows = [
        ("Name", esc(p.get("name") or "")),
        ("Platforms", _list(p.get("platforms")) or "not on a platform"),
        ("Sources", _list(p.get("sources"))),
        ("Policy", f'<a href="{esc(p.get("policy"))}" rel="noreferrer noopener">'
                   f'{esc(p.get("policy"))}</a>' if p.get("policy") else ""),
        ("security.txt", f'<a href="{esc(p.get("securitytxt_url"))}" rel="noreferrer noopener">'
                         f'{esc(p.get("securitytxt_url"))}</a>' if p.get("securitytxt_url") else ""),
        ("Email", " ".join(f'<a href="mailto:{esc(e)}">{esc(e)}</a>'
                           for e in (p.get("emails") or []))),
        ("Contact form", _links(p.get("contact_urls"))),
        ("Bounty", esc(p.get("offers_bounty") or "unknown")),
        ("Safe harbour", esc(p.get("safe_harbor") or "unknown")),
        ("Expiry", esc(EXPIRY_LABEL.get(p.get("expiry"), "unknown"))
         + (f' · {esc(p["expires_on"])}' if p.get("expires_on") else "")),
        ("TLS verified", "yes" if p.get("tls_verified") else "no"),
        ("In scope", _list(p.get("in_scope_domains"))),
        ("Out of scope", _list(p.get("out_of_scope_domains"))),
        ("First seen", esc(p.get("first_seen") or "")),
        ("Last seen", esc(p.get("last_seen") or "")),
        ("API", f'<span class="mono-small">GET /v1/programs/{esc(p["domain"])} (key required)</span>'),
    ]
    dl = "".join(f'<div class="kv"><dt>{k}</dt><dd>{v or "<span class=dim>none</span>"}</dd></div>'
                 for k, v in rows)
    hist = change_list(p.get("history") or [], compact=True)
    return f"""<p class="crumbs"><a href="/explore">&larr; back to the explorer</a></p>
<h1 class="mono">{esc(p['domain'])}</h1>
<p class="lede">{chips(p)}</p>
<div class="panel"><dl class="kv-grid">{dl}</dl></div>
<h2 class="sect">Change history</h2>
{hist or '<p class="empty">No recorded changes for this domain yet.</p>'}"""


def _diff_html(c: dict) -> str:
    before, after = c.get("before") or {}, c.get("after") or {}
    fields = c.get("fields") or list(after.keys())
    if isinstance(fields, str):
        fields = [fields]
    out = []
    for f in fields:
        b = before.get(f)
        a = after.get(f)
        if isinstance(b, list):
            b = ", ".join(str(x) for x in b)
        if isinstance(a, list):
            a = ", ".join(str(x) for x in a)
        out.append(f'<div class="diff"><span class="diff-f">{esc(f)}</span>'
                   f'<span class="diff-b">{esc(b) if b not in (None, "") else "&ndash;"}</span>'
                   f'<span class="diff-a">{esc(a) if a not in (None, "") else "&ndash;"}</span></div>')
    return "".join(out)


def change_list(rows: list[dict], compact: bool = False) -> str:
    if not rows:
        return ""
    out = ['<div class="table-wrap"><table class="grid changes"><thead><tr>',
           "<th>When</th><th>Kind</th><th>Domain</th><th>What changed</th></tr></thead><tbody>"]
    for c in rows:
        kind = c.get("kind") or ""
        out.append(
            "<tr>"
            f'<td class="mono-small">{esc((c.get("ts") or "")[:16].replace("T", " "))}</td>'
            f'<td><span class="chip chip-{esc(kind)}">{esc(kind)}</span></td>'
            f'<td class="mono"><a href="/program/{esc(c.get("domain"))}">{esc(c.get("domain"))}</a></td>'
            f"<td>{_diff_html(c)}</td></tr>")
    out.append("</tbody></table></div>")
    return "".join(out)
