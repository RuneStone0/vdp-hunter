"""Domain normalisation and validation for the vdp-hunter dataset.

Every domain in the dataset is a join key: it decides which program a scope entry
belongs to, which rows a change diff compares, and which targets a researcher may
test. A junk key is therefore worse than a missing one, because it silently
attaches real scope to a domain nobody owns.

The rules here are deliberately strict and they run at both ends: when a dataset
is built (`bin/build_dataset.py`) and again when one is ingested (`app/store.py`),
so a bad builder can never put a bad key into the API.

Accepted and repaired:
    "*.*.acme.com"        -> acme.com            (wildcards stripped, recorded by caller)
    "ACME.COM."           -> acme.com            (case, trailing dot)
    "https://acme.com/x"  -> acme.com            (URL form, path, port, userinfo)
    "acme[.]com"          -> acme.com            (defanged dot)
    "schächner.de"        -> xn--schnchner-kcb.de (IDN, via punycode)
    'acme.com"'           -> acme.com            (trailing quote / arrow / entity)

Rejected, never repaired:
    "(com|co.uk|ca)"  "au, property.com.au"  "<this-website>.com"  "co.uk"
    "a. marketplace managed bug bounty engagement"  "0 and l\u01ddncrypt2.0"
"""
from __future__ import annotations

import ipaddress
import re

# Second-level suffixes that need one extra label to reach a registrable domain.
SLD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "com.ph", "com.vn", "com.tr",
    "com.ua", "com.pl", "com.ru", "com.es", "com.pt", "com.gr", "com.ro",
    "co.za", "co.in", "co.il", "co.id", "co.ke", "co.th", "co.ve", "co.cr",
    "com.sa", "com.eg", "com.ng", "com.pk", "com.bd", "com.np", "com.kw",
    "com.qa", "com.om", "com.bh", "com.jo", "com.lb", "com.cy", "com.mt",
    "org.il", "ac.il", "gov.il", "ne.jp", "co.at", "or.at", "ac.at",
    "gv.at", "co.hu", "com.hr", "com.ba", "co.rs", "com.mk", "com.al",
}

# A single label that can never be a registrable domain on its own.
TLD_ONLY = {"com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
            "io", "co", "me", "tv", "cc", "ai", "app", "dev", "xyz", "online",
            "site", "shop", "store", "uk", "de", "fr", "nl", "be", "ch", "at",
            "se", "no", "dk", "fi", "pl", "cz", "sk", "hu", "ro", "bg", "gr",
            "es", "pt", "it", "ie", "is", "us", "ca", "au", "nz", "jp", "kr",
            "cn", "tw", "hk", "sg", "my", "th", "vn", "id", "ph", "in", "pk",
            "bd", "lk", "np", "ae", "sa", "qa", "kw", "bh", "om", "jo", "lb",
            "eg", "ng", "ke", "za", "ma", "tn", "dz", "gh", "br", "ar", "cl",
            "co", "pe", "ve", "mx", "cr", "pa", "ru", "ua", "by", "kz", "tr"}

# Scope syntax, prose and markup: if any of these appear, the string is not a host.
NOT_A_HOST = set("|(){}[]<>,;\"'` \t\r\n\u00a0")
# Trailing noise that scrapers leave behind: quotes, arrows, entities, zero-width.
TRAILING_NOISE = "\"'`,;:!?.>)]}&\u00b7\u2022\u2190\u2192\u2193\u2191\u21b5\u21b4\u00bb\u00ab\u200b\u200c\u200d\ufeff"
ENTITY = re.compile(r"&(?:nbsp|amp|lt|gt|quot|#\d+|#x[0-9a-f]+);?", re.I)
DEFANG = [(re.compile(r"\[\s*dot\s*\]|\{\s*dot\s*\}|\(\s*dot\s*\)", re.I), "."),
          (re.compile(r"\[\s*\.\s*\]|\{\s*\.\s*\}|\(\s*\.\s*\)"), ".")]
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")


def to_ascii(host: str) -> str:
    """IDN to punycode. 'schächner.de' -> 'xn--schnchner-kcb.de'."""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return ""


def clean_host(raw) -> str | None:
    """Best-effort host extraction. Returns a lowercased ASCII host, or None.

    This repairs what is unambiguously repairable and refuses everything else. It
    never guesses: a string with scope syntax in it is dropped, not truncated,
    because truncating 'au, property.com.au' would invent the domain 'au'.
    """
    s = str(raw or "").strip()
    if not s:
        return None
    s = ENTITY.sub("", s)
    for pattern, repl in DEFANG:
        s = pattern.sub(repl, s)
    if "://" in s:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(s if s.lower().startswith(("http://", "https://")) else "//" + s)
            s = parsed.netloc or parsed.path
        except ValueError:
            return None
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s.rsplit("@", 1)[-1]                      # drop userinfo
    s = re.sub(r":\d+$", "", s)                    # drop port
    s = s.strip().strip(TRAILING_NOISE)
    while s.startswith("*."):
        s = s[2:]
    s = s.lstrip("*")
    if any(ch in NOT_A_HOST for ch in s):
        return None
    s = s.lower().strip(".")
    if not s or "*" in s:
        return None
    if not s.isascii():
        s = to_ascii(s)
        if not s:
            return None
    return s or None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_valid(domain) -> bool:
    """True only for a registrable domain that could appear in the dataset."""
    if not isinstance(domain, str):
        return False
    d = (domain or "").strip().lower().rstrip(".")
    if not d or not d.isascii() or len(d) > 253 or ".." in d:
        return False
    if is_ip(d) or "." not in d:
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    if not all(LABEL.match(label) for label in labels):
        return False
    if not TLD.match(labels[-1]):
        return False
    if d in SLD or d in TLD_ONLY:
        return False
    # a public suffix with nothing in front: 'foo.co.uk' is fine, 'co.uk' is not
    if ".".join(labels[-2:]) in SLD and len(labels) < 3:
        return False
    return True


def registrable(host) -> str | None:
    """The registrable domain for a host, or None when it is not a host at all."""
    cleaned = clean_host(host)
    if not cleaned:
        return None
    labels = cleaned.split(".")
    if len(labels) > 2 and ".".join(labels[-2:]) in SLD:
        candidate = ".".join(labels[-3:])
    elif len(labels) > 2:
        candidate = ".".join(labels[-2:])
    else:
        candidate = cleaned
    return candidate if is_valid(candidate) else None


def asset_domain(raw) -> str | None:
    """A scope asset string to a registrable domain, or None if it is not one."""
    return registrable(raw)
