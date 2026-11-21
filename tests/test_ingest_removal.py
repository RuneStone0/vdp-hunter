"""An incremental crawl must never delete rows it simply did not re-probe."""

from app import main

A = {"domain": "a.example", "name": "A", "sources": ["securitytxt"], "platforms": [],
     "policy": "https://a.example/security", "emails": [], "contact_urls": [],
     "expiry": "valid", "expires_on": "2027-01-01", "offers_bounty": None,
     "in_scope_domains": ["a.example"]}
B = dict(A, domain="b.example", name="B", policy="https://b.example/security",
         in_scope_domains=["b.example"])


def _reset():
    with main.store.conn() as c:
        for t in ("programs", "changes", "runs"):
            c.execute(f"DELETE FROM {t}")


def test_partial_snapshot_keeps_absent_rows(client):
    _reset()
    main.store.ingest([A, B], record_changes=False)
    delta = main.store.ingest([A])          # B was simply not re-probed this cycle
    assert delta["removed"] == 0
    assert delta["absent"] == 1
    assert main.store.get("b.example") is not None
    assert main.store.stats()["programs"] == 2


def test_removal_only_when_explicitly_allowed(client):
    _reset()
    main.store.ingest([A, B], record_changes=False)
    delta = main.store.ingest([A], allow_removal=True)
    assert delta["removed"] == 1
    assert main.store.get("b.example") is None
    assert main.store.stats()["programs"] == 1
