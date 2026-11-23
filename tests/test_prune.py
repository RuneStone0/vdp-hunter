"""A prune must never reach beyond the source being refreshed."""

from app import main  # noqa: E402


def _row(domain, sources):
    return {"domain": domain, "name": domain, "sources": sources, "platforms": [],
            "policy": f"https://{domain}/policy", "emails": [], "contact_urls": [],
            "expires_on": None, "expiry": "missing", "offers_bounty": None,
            "safe_harbor": None, "securitytxt_url": None, "tls_verified": None,
            "in_scope_domains": []}


def _platform_row(domain):
    row = _row(domain, ["hackerone"])
    row["platforms"] = ["hackerone"]
    return row


def test_dotless_rows_are_retired(client):
    # Ingest now refuses dotless keys, so a legacy database that already holds them
    # (built before app/domains.py existed) is the case the prune has to cover.
    with main.store.conn() as c:
        for d in ("localhost", "floqast"):
            c.execute("INSERT OR REPLACE INTO programs(domain,name,sources,platforms) "
                      "VALUES(?,?,?,?)", (d, d, '["securitytxt"]', '["hackerone"]'))
    assert main.store.get("localhost") is not None          # legacy row really is there
    res = main.store.ingest([_platform_row("acme.com")], record_changes=True,
                            allow_removal=True, prune_dotless_platform=True)
    assert res["removed"] == 2
    assert main.store.get("floqast") is None
    assert main.store.get("localhost") is None
    assert main.store.get("acme.com") is not None


def test_ingest_refuses_dotless_keys_so_they_never_come_back(client):
    res = main.store.ingest([_row("localhost", ["securitytxt"]), _platform_row("acme.com")],
                            record_changes=False)
    assert res["seeded"] == 1
    assert main.store.get("localhost") is None


def test_prune_only_removes_rows_from_that_source(client):
    main.store.ingest([_row("dir-only.example", ["disclose-directory"]),
                       _row("crawled.example", ["securitytxt"]),
                       _row("both.example", ["disclose-directory", "securitytxt"])],
                      record_changes=False)

    # snapshot no longer mentions any of them, pruned as directory-only
    res = main.store.ingest([_row("unrelated.example", ["securitytxt"])],
                            record_changes=True, allow_removal=True,
                            prune_only_sources={"disclose-directory"})
    assert res["removed"] == 1

    domains = {d for d in ("dir-only.example", "crawled.example", "both.example")
               if main.store.get(d)}
    assert domains == {"crawled.example", "both.example"}
