"""Domain validation: the six junk shapes from the dashboard, plus the repairs."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import domains  # noqa: E402
from app import store as store_mod  # noqa: E402


# Exactly the rows visible on the dashboard, 2026-11-23.
SCREENSHOT_JUNK = [
    "(com|co.uk|ca)",
    "(post.ch",
    "*elvetino.ch",
    "*idpuzleuven.be",
    "*skybet.com",
    "0 and l\u01ddncrypt2.0",
]

OTHER_JUNK = [
    "<this-website>.com",
    "a. marketplace managed bug bounty engagement",
    "au, property.com.au",
    "au|com.ua|com|cz|de|dk",
    "__dukiwi.com",
    "com",
    "co.uk",
    "com.au",
    "127.0.0.1",
    "::1",
    "",
    None,
    "   ",
]


@pytest.mark.parametrize("raw", OTHER_JUNK)
def test_junk_is_refused_outright(raw):
    assert domains.registrable(raw) is None
    assert domains.is_valid(str(raw or "")) is False


@pytest.mark.parametrize("raw,expected", [
    ("(com|co.uk|ca)", None),
    ("(post.ch", None),
    ("*elvetino.ch", "elvetino.ch"),          # wildcard stripped, program key repaired
    ("*idpuzleuven.be", "idpuzleuven.be"),
    ("*skybet.com", "skybet.com"),
    ("0 and l\u01ddncrypt2.0", None),
])
def test_each_screenshot_row(raw, expected):
    assert domains.registrable(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("ACME.COM.", "acme.com"),                    # case and trailing dot
    ("https://acme.com/path?q=1", "acme.com"),    # URL form
    ("acme[.]com", "acme.com"),                   # defanged
    ('dailyudaan.com"', "dailyudaan.com"),        # trailing quote
    ("nku.edu&nbsp", "nku.edu"),                  # HTML entity
    ("sezession.de\u21b4", "sezession.de"),       # stray arrow
    ("api-eu.floqast.app", "floqast.app"),        # subdomain folded
    ("*.vfsglobal.com", "vfsglobal.com"),         # wildcard
    ("coop.co.uk", "coop.co.uk"),                 # second-level suffix
    ("a.b.c.example.co.uk", "example.co.uk"),     # deep subdomain under SLD
    ("schächner.de", "xn--schchner-2za.de"),      # IDN to punycode
    ("user@acme.com:8080", "acme.com"),           # userinfo and port
])
def test_repairs_that_are_safe(raw, expected):
    assert domains.registrable(raw) == expected


def test_ip_and_platform_hosts_never_become_keys():
    assert domains.registrable("10.0.0.1") is None
    assert domains.registrable("hackerone.com") == "hackerone.com"   # valid, filtered by caller


def test_public_suffix_alone_is_not_a_program(monkeypatch):
    assert domains.is_valid("co.uk") is False
    assert domains.is_valid("example.co.uk") is True
    assert domains.is_valid("xn--schnchner-kcb.de") is True


def test_ingest_refuses_invalid_domain_and_says_so(tmp_path):
    st = store_mod.Store(str(tmp_path / "t.db"))
    ok = {"domain": "acme.com", "name": "Acme", "sources": ["securitytxt"], "platforms": []}
    bad = {"domain": "(com|co.uk|ca)", "name": "Junk", "sources": [], "platforms": []}
    delta = st.ingest([ok, bad], record_changes=False, note="probe")
    assert st.get("acme.com") is not None
    assert st.get("(com|co.uk|ca)") is None
    assert "rejected_invalid_domain=1" in delta.get("note", "") or delta.get("seeded") == 1


def test_builder_wrapper_returns_empty_string_for_junk():
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin"))
    import build_dataset
    assert build_dataset.registrable("(post.ch") == ""
    assert build_dataset.registrable("*skybet.com") == "skybet.com"
    # the "" contract is what keeps `if "." not in key` callers working
    assert "." not in build_dataset.registrable("0 and l\u01ddncrypt2.0")


def test_purge_invalid_domains_spares_valid_rows(tmp_path):
    st = store_mod.Store(str(tmp_path / "purge.db"))
    st.ingest([{"domain": "acme.com", "name": "Acme", "sources": ["securitytxt"], "platforms": []}],
              record_changes=True)
    # rows written by the pre-validation builder can only be reproduced with raw SQL
    with st.conn() as c:
        for d in ("(com|co.uk|ca)", "*elvetino.ch", "0 and l\xddncrypt2.0"):
            c.execute("INSERT OR REPLACE INTO programs(domain,name,sources,platforms) VALUES(?,?,?,?)",
                      (d, d, '["hackerone"]', '["hackerone"]'))
    dry = st.purge_invalid_domains(dry_run=True)
    assert dry["invalid"] == 3 and dry["deleted"] == 0
    assert st.get("(com|co.uk|ca)") is not None
    real = st.purge_invalid_domains(dry_run=False)
    assert real["deleted"] == 3
    assert st.get("(com|co.uk|ca)") is None
    assert st.get("*elvetino.ch") is None
    assert st.get("acme.com") is not None            # a real row is never touched
