"""Free keys get the data that is already public on the commercial platforms.
The self-managed programs we discover are the paid product, so they must not
leak through the API, the detail endpoint or the change feed."""


from app import main  # noqa: E402


def _seed(store):
    rich = {
        "domain": "unlisted.example", "name": "Unlisted Corp", "sources": ["czds"],
        "platforms": [], "policy": "https://unlisted.example/policy",
        "emails": ["security@unlisted.example"], "contact_urls": [],
        "expires_on": "2027-01-01", "expiry": "valid", "offers_bounty": "yes",
        "safe_harbor": None, "securitytxt_url": "https://unlisted.example/.well-known/security.txt",
        "tls_verified": True, "in_scope_domains": ["unlisted.example"],
    }
    plat = {
        "domain": "listed.example", "name": "Listed Corp", "sources": ["hackerone"],
        "platforms": ["hackerone"], "policy": "https://hackerone.com/listed",
        "emails": [], "contact_urls": [], "expires_on": None, "expiry": "missing",
        "offers_bounty": "yes", "safe_harbor": None, "securitytxt_url": None,
        "tls_verified": None, "in_scope_domains": ["listed.example"],
    }
    store.ingest([rich, plat], record_changes=True)


def _keys(store):
    store.add_key("free-key-1", "free", "test")
    store.add_key("pro-key-1", "pro", "test")


def test_free_key_sees_only_platform_programs(client):
    store = main.store
    _seed(store)
    _keys(store)

    body = client.get("/v1/programs", headers={"X-API-Key": "free-key-1"}).json()
    domains = [r["domain"] for r in body["data"]]
    assert domains == ["listed.example"], domains
    assert body["meta"]["free_tier_restricted"] is True

    body = client.get("/v1/programs", headers={"X-API-Key": "pro-key-1"}).json()
    domains = sorted(r["domain"] for r in body["data"])
    assert domains == ["listed.example", "unlisted.example"], domains
    assert "free_tier_restricted" not in body["meta"]


def test_free_key_detail_is_forbidden_for_unlisted(client):
    store = main.store
    _seed(store)
    _keys(store)

    r = client.get("/v1/programs/unlisted.example", headers={"X-API-Key": "free-key-1"})
    assert r.status_code == 403
    assert "paid dataset" in r.json()["detail"]

    r = client.get("/v1/programs/unlisted.example", headers={"X-API-Key": "pro-key-1"})
    assert r.status_code == 200
    assert r.json()["data"]["domain"] == "unlisted.example"


def test_free_key_change_feed_excludes_unlisted(client):
    store = main.store
    _seed(store)
    _keys(store)

    body = client.get("/v1/changes", headers={"X-API-Key": "free-key-1"}).json()
    assert all(c["domain"] == "listed.example" for c in body["data"]), body["data"]

    body = client.get("/v1/changes", headers={"X-API-Key": "pro-key-1"}).json()
    assert {c["domain"] for c in body["data"]} == {"listed.example", "unlisted.example"}
