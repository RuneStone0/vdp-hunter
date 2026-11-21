"""The explorer is server-rendered, so the tests assert on real HTML output."""

from app import main

ADMIN = {"X-API-Key": "test-admin-key"}

RICH = {"domain": "zapier.com", "name": "Zapier", "sources": ["diodb", "securitytxt"],
        "platforms": [], "policy": "https://zapier.com/engineering/bug-bounty-submission/",
        "emails": ["security@zapier.com"], "contact_urls": [],
        "expires_on": "2027-11-01", "expiry": "valid", "offers_bounty": "yes",
        "safe_harbor": None, "securitytxt_url": "https://zapier.com/.well-known/security.txt",
        "tls_verified": True, "in_scope_domains": ["zapier.com"]}
PLAT = dict(RICH, domain="shopify.com", name="Shopify", sources=["bugcrowd"],
            platforms=["bugcrowd"], offers_bounty="yes", securitytxt_url=None,
            policy="https://bugcrowd.com/shopify", expires_on=None, expiry="missing",
            in_scope_domains=["shopify.com"], emails=[])


def _seed():
    with main.store.conn() as c:
        for t in ("programs", "changes", "runs"):
            c.execute(f"DELETE FROM {t}")
    main.store.ingest([RICH, PLAT], record_changes=False)


def test_explore_lists_programs(client):
    _seed()
    r = client.get("/explore")
    assert r.status_code == 200
    assert "zapier.com" in r.text and "shopify.com" in r.text
    assert "2 matching programs" in r.text


def test_explore_filters(client):
    _seed()
    assert "shopify.com" not in client.get("/explore?platform=self").text
    only_bc = client.get("/explore?platform=bugcrowd").text
    assert "shopify.com" in only_bc and "zapier.com" not in only_bc
    assert "shopify.com" not in client.get("/explore?source=securitytxt").text
    assert "zapier.com" not in client.get("/explore?expiry=expired").text


def test_explore_search(client):
    _seed()
    body = client.get("/explore?q=zapier").text
    assert "zapier.com" in body and "shopify.com" not in body


def test_program_page(client):
    _seed()
    r = client.get("/program/zapier.com")
    assert r.status_code == 200
    assert "security@zapier.com" in r.text
    assert "https://zapier.com/engineering/bug-bounty-submission/" in r.text
    assert "Change history" in r.text
    assert client.get("/program/does-not-exist.example").status_code == 404


def test_changes_page_renders_diffs(client):
    _seed()
    main.store.ingest([dict(RICH, policy="https://zapier.com/security/new")])
    r = client.get("/changes")
    assert r.status_code == 200
    assert "changed" in r.text
    assert "https://zapier.com/security/new" in r.text
    assert "https://zapier.com/engineering/bug-bounty-submission/" in r.text


def test_program_page_is_escaped(client):
    _seed()
    main.store.ingest([dict(RICH, domain="evil.example", name="<script>alert(1)</script>",
                            in_scope_domains=["<img src=x onerror=alert(1)>"])],
                      record_changes=False)
    body = client.get("/program/evil.example").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
