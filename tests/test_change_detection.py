"""A scope list that did not change must not produce a change row.

Regression: the stored value arrives from SQLite as a JSON string and was normalised without
sorting, while the incoming value is a Python list and was sorted. Every re-scan therefore
looked like an edit to `scope_in`/`scope_out` even when the targets were identical, which made
`/changes` about 96% noise (measured 2026-11-23: 963 of 1000 sampled rows had identical before
and after, all of them scope fields).
"""
from app import main, store

SCOPE = [{"platform": "hackerone", "target": "*.a.example", "type": "WILDCARD"},
         {"platform": "hackerone", "target": "*.b.example", "type": "WILDCARD"}]

P = {
    "domain": "a.example", "name": "A", "sources": ["securitytxt"], "platforms": ["hackerone"],
    "policy": "https://a.example/security", "emails": ["s@a.example"], "contact_urls": [],
    "expiry": "valid", "expires_on": "2027-01-01", "offers_bounty": None,
    "in_scope_domains": ["a.example"], "scope_in": SCOPE, "scope_out": [], "scopes_count": 2,
    "securitytxt_url": "https://a.example/.well-known/security.txt", "tls_verified": True,
}


def _change_rows():
    with main.store.conn() as c:
        return [tuple(r) for r in c.execute("SELECT kind, domain, fields, before, after FROM changes")]


def test_identical_scope_in_a_different_order_is_not_a_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    delta = main.store.ingest([dict(P, scope_in=list(reversed(SCOPE)))])
    assert delta["changed"] == 0
    assert [r for r in _change_rows() if r[0] == "changed"] == []


def test_identical_scope_reported_identically_is_not_a_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    delta = main.store.ingest([dict(P)])
    assert delta["changed"] == 0


def test_a_real_scope_addition_is_still_a_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    grown = SCOPE + [{"platform": "hackerone", "target": "*.c.example", "type": "WILDCARD"}]
    delta = main.store.ingest([dict(P, scope_in=grown)])
    assert delta["changed"] == 1
    row = [r for r in _change_rows() if r[0] == "changed"][0]
    assert "scope_in" in row[2]
    assert "*.c.example" in (row[4] or "") and "*.c.example" not in (row[3] or "")


def test_a_real_scope_removal_is_still_a_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    delta = main.store.ingest([dict(P, scope_in=SCOPE[:1])])
    assert delta["changed"] == 1


def test_a_scalar_change_is_still_a_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    delta = main.store.ingest([dict(P, name="A renamed")])
    assert delta["changed"] == 1
    row = [r for r in _change_rows() if r[0] == "changed"][0]
    assert row[2] == '["name"]'


def test_norm_treats_db_string_and_memory_object_alike():
    """The exact asymmetry that caused the bug."""
    stored = '[{"platform": "hackerone", "target": "*.z.example", "type": "WILDCARD"}, ' \
             '{"platform": "hackerone", "target": "*.a.example", "type": "WILDCARD"}]'
    memory = [{"target": "*.a.example", "type": "WILDCARD", "platform": "hackerone"},
              {"type": "WILDCARD", "platform": "hackerone", "target": "*.z.example"}]
    assert store._norm(stored) == store._norm(memory)


def _insert_noop_change(domain="a.example"):
    """A row of the shape the old comparison produced: scope fields, identical content."""
    import json
    before = json.dumps({"scope_in": [{"platform": "hackerone", "target": "*.a.example",
                                       "type": "WILDCARD"}]})
    after = json.dumps({"scope_in": [{"type": "WILDCARD", "platform": "hackerone",
                                      "target": "*.a.example"}]})
    with main.store.conn() as c:
        c.execute("INSERT INTO changes(ts,run_id,kind,domain,fields,before,after) "
                  "VALUES(?,?,?,?,?,?,?)",
                  ("2026-11-23T00:00:00+00:00", 1, "changed", domain, '["scope_in"]',
                   before, after))


def test_purge_removes_only_rows_that_assert_no_change(client):
    main.store.ingest([dict(P)], record_changes=False)
    _insert_noop_change()
    grew = SCOPE + [{"platform": "hackerone", "target": "*.c.example", "type": "WILDCARD"}]
    main.store.ingest([dict(P, scope_in=grew)])          # one genuine change row
    assert len([r for r in _change_rows() if r[0] == "changed"]) == 2

    dry = main.store.purge_noop_changes(dry_run=True)
    assert dry["noop"] == 1 and dry["deleted"] == 0
    assert len([r for r in _change_rows() if r[0] == "changed"]) == 2

    done = main.store.purge_noop_changes(dry_run=False)
    assert done["deleted"] == 1
    remaining = [r for r in _change_rows() if r[0] == "changed"]
    assert len(remaining) == 1 and "*.c.example" in (remaining[0][4] or "")


def test_purge_endpoint_defaults_to_a_dry_run(client):
    _insert_noop_change()
    r = client.post("/admin/changes/purge", headers={"X-API-Key": "test-admin-key"})
    assert r.status_code == 200
    assert r.json()["data"]["dry_run"] is True
    assert len(_change_rows()) == 1
