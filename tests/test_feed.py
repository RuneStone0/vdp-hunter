"""The public change feed page and /feed.json.

Two rules are load-bearing. The page shows the ten newest changes and nothing older, and
a row that belongs only to the paid dataset is masked: the domain is the product, so a
public page must not hand out a fresh list of it every hour.
"""
import json

from app import feed, main

PAID = {"domain": "kliksafe.nl", "name": "Kliksafe", "sources": ["securitytxt"],
        "platforms": [], "policy": "https://kliksafe.nl/cvd", "emails": ["soc@kliksafe.nl"],
        "contact_urls": [], "expiry": "valid", "expires_on": "2026-05-21",
        "offers_bounty": None, "securitytxt_url": "https://kliksafe.nl/.well-known/security.txt",
        "tls_verified": True, "in_scope_domains": []}

PUBLIC = {"domain": "shopify.com", "name": "Shopify", "sources": ["securitytxt", "hackerone"],
          "platforms": ["hackerone"], "policy": "https://hackerone.com/shopify",
          "emails": ["security@shopify.com"], "contact_urls": [], "expiry": "valid",
          "expires_on": "2027-02-01", "offers_bounty": "yes", "safe_harbor": None,
          "securitytxt_url": None, "tls_verified": True, "in_scope_domains": ["shopify.com"]}


def _add(domain, kind, fields, before, after, run_id=None, ts="2026-11-23T22:17:34+00:00"):
    with main.store.conn() as c:
        c.execute("INSERT INTO changes(ts,run_id,kind,domain,fields,before,after) "
                  "VALUES(?,?,?,?,?,?,?)",
                  (ts, run_id, kind, domain, json.dumps(fields),
                   json.dumps(before) if before is not None else None,
                   json.dumps(after) if after is not None else None))


def _found(domain="kliksafe.nl"):
    """The shape a first-time security.txt crawl writes: sources grow, values appear."""
    _add(domain, "changed", ["sources", "securitytxt_url", "emails", "expiry"],
         {"sources": ["disclose-directory"], "securitytxt_url": None, "emails": [],
          "expiry": "unknown"},
         {"sources": ["disclose-directory", "securitytxt"],
          "securitytxt_url": "https://kliksafe.nl/.well-known/security.txt",
          "emails": ["soc@kliksafe.nl"], "expiry": "valid"})


def test_feed_json_is_keyless_and_lists_the_ten_newest(client):
    for i in range(15):
        _found(f"paid{i}.nl")
    r = client.get("/feed.json")
    assert r.status_code == 200
    data = r.json()
    assert len(data["changes"]) == 10
    assert [c["id"] for c in data["changes"]] == sorted(
        [c["id"] for c in data["changes"]], reverse=True)
    assert data["newest_id"] == data["changes"][0]["id"]


def test_ten_rows_on_the_page_and_no_pagination(client):
    for i in range(15):
        _found(f"paid{i}.nl")
    body = client.get("/changes").text
    assert body.count('<li class="tape-row') == 10
    assert "next &rsaquo;" not in body
    assert 'href="/changes?page=2"' not in body


def test_paid_only_row_is_masked_in_both_outputs(client):
    main.store.ingest([dict(PAID)], record_changes=False)
    _found()

    data = client.get("/feed.json").json()
    item = data["changes"][0]
    assert item["locked"] is True
    assert "kliksafe" not in item["domain"]
    assert "\u2022" in item["domain"] and item["domain"].endswith(".nl")
    assert item["headline"] == "security.txt discovered"

    raw = json.dumps(data)
    for secret in ("kliksafe.nl", "soc@kliksafe.nl", "https://kliksafe.nl/cvd"):
        assert secret not in raw
    page = client.get("/changes").text
    assert "kliksafe" not in page and "soc@kliksafe.nl" not in page
    assert "values in the paid feed" in page


def test_public_row_is_shown_whole(client):
    main.store.ingest([dict(PUBLIC)], record_changes=False)
    _add("shopify.com", "changed", ["policy"],
         {"policy": "https://hackerone.com/shopify"}, {"policy": "https://hackerone.com/shopify2"})

    item = client.get("/feed.json").json()["changes"][0]
    assert item["locked"] is False
    assert item["domain"] == "shopify.com"
    assert item["link"] == "/program/shopify.com"
    assert item["headline"] == "policy url moved"
    assert any(d["after"] == "https://hackerone.com/shopify2" for d in item["diffs"])


def test_kind_filter_and_cursor(client):
    first = None
    for i in range(6):
        _add(f"p{i}.com", "added", [], None, {"name": f"P{i}", "sources": ["securitytxt"]})
        if i == 2:
            first = main.store.feed(limit=1)[0]["id"]
    added = client.get("/feed.json?kind=added").json()
    assert {c["kind"] for c in added["changes"]} == {"added"}

    newer = client.get(f"/feed.json?after_id={first}").json()
    assert newer["changes"] and all(c["id"] > first for c in newer["changes"])

    fresh = client.get(f"/feed.json?after_id={added['newest_id']}").json()
    assert fresh["changes"] == []

    assert client.get("/feed.json?kind=removed").json()["changes"] == []


def test_row_that_asserts_no_edit_is_not_rendered(client):
    _add("noop.com", "changed", ["policy"],
         {"policy": "https://noop.com/p"}, {"policy": "https://noop.com/p"})
    assert client.get("/feed.json").json()["changes"] == []
    assert "No changes recorded" in client.get("/changes").text


def test_reveal_mode_shows_the_domain(client, monkeypatch):
    monkeypatch.setattr(feed, "REVEAL", True)
    main.store.ingest([dict(PAID)], record_changes=False)
    _found()
    item = client.get("/feed.json").json()["changes"][0]
    assert item["locked"] is False and item["domain"] == "kliksafe.nl"
    assert client.get("/feed.json").json()["mode"] == "reveal"


def test_headlines_say_what_happened():
    assert feed.headline("changed", ["sources"], {"sources": ["a"]},
                         {"sources": ["a", "securitytxt"]}) == "security.txt discovered"
    assert feed.headline("added", [], {}, {"securitytxt_url": "https://x/.well-known/security.txt"}) \
        == "security.txt published"
    assert feed.headline("changed", ["expiry"], {"expiry": "valid"},
                         {"expiry": "expired"}) == "policy expired"
    assert feed.headline("removed", [], {"platforms": ["bugcrowd"]}, {}) \
        == "withdrawn from bugcrowd"
    assert feed.headline("changed", ["name"], {"name": "A b"}, {"name": "A.B"}) == "record re-verified"


def test_masked_name_field_does_not_leak_the_org(client):
    main.store.ingest([dict(PAID)], record_changes=False)
    _add("kliksafe.nl", "changed", ["name", "sources"],
         {"name": "Kliksafe", "sources": ["disclose-directory"]},
         {"name": "kliksafe.nl", "sources": ["disclose-directory", "securitytxt"]})
    raw = json.dumps(client.get("/feed.json").json())
    assert "Kliksafe" not in raw and "kliksafe" not in raw


def test_sweep_banner_carries_the_run_numbers(client):
    with main.store.conn() as c:
        c.execute("INSERT INTO runs(started_at,finished_at,kind,probes,hits,added,changed) "
                  "VALUES(?,?,?,?,?,?,?)",
                  ("2026-11-23T22:17:34+00:00", "2026-11-23T22:17:40+00:00", "crawl",
                   3014, 66, 46, 20))
        run_id = c.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]
    _add("kliksafe.nl", "added", [], None, {"name": "K", "sources": ["securitytxt"]}, run_id=run_id)
    page = client.get("/changes").text
    assert "sweep 22:17" in page
    assert "3,014 domains probed" in page
    assert "66 policies found" in page
    assert "66 changes written" in page
