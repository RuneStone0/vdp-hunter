"""A snapshot with no fresh probe must not erase what an earlier probe found."""

from app import main

RICH = {"domain": "zapier.com", "name": "Zapier", "sources": ["diodb", "securitytxt"],
        "platforms": [], "policy": "https://zapier.com/engineering/bug-bounty-submission/",
        "emails": ["security@zapier.com"], "contact_urls": ["https://zapier.com/engineering/bug-bounty-submission/"],
        "expires_on": "2027-11-01", "expiry": "valid", "offers_bounty": "yes",
        "safe_harbor": None, "securitytxt_url": "https://zapier.com/.well-known/security.txt",
        "tls_verified": True, "in_scope_domains": ["zapier.com"]}

BARE = {"domain": "zapier.com", "name": "Zapier", "sources": ["diodb"], "platforms": [],
        "policy": None, "emails": [], "contact_urls": [], "expires_on": None,
        "expiry": None, "offers_bounty": None, "safe_harbor": None,
        "securitytxt_url": "", "tls_verified": None, "in_scope_domains": []}


def _reset():
    with main.store.conn() as c:
        for t in ("programs", "changes", "runs"):
            c.execute(f"DELETE FROM {t}")


def test_upstream_only_snapshot_changes_nothing(client):
    _reset()
    main.store.ingest([RICH], record_changes=False)
    delta = main.store.ingest([BARE])
    assert delta["changed"] == 0, "no live probe this cycle must not register as a change"
    row = main.store.get("zapier.com")
    assert row is not None
    assert row["policy"] == RICH["policy"]
    assert row["securitytxt_url"] == RICH["securitytxt_url"]
    assert row["expiry"] == "valid"
    assert sorted(row["sources"]) == ["diodb", "securitytxt"]


def test_real_change_still_recorded(client):
    _reset()
    main.store.ingest([RICH], record_changes=False)
    moved = dict(RICH, policy="https://zapier.com/security/new-policy")
    delta = main.store.ingest([moved])
    assert delta["changed"] == 1
    row = main.store.get("zapier.com")
    assert row is not None and row["policy"] == moved["policy"]
