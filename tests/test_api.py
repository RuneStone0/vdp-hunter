from fastapi.testclient import TestClient

from app import main

ADMIN = {"X-API-Key": "test-admin-key"}


def test_health_is_public(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_requires_key(client):
    assert client.get("/v1/programs").status_code == 401
    assert client.get("/v1/stats", headers={"X-API-Key": "nope"}).status_code == 401


def test_programs_and_filters(seeded):
    r = seeded.get("/v1/programs", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] == 2
    assert {p["domain"] for p in body["data"]} == {"anthropic.com", "shopify.com"}

    r = seeded.get("/v1/programs?bounty=yes", headers=ADMIN)
    assert [p["domain"] for p in r.json()["data"]] == ["shopify.com"]

    r = seeded.get("/v1/programs?platform=hackerone", headers=ADMIN)
    assert [p["domain"] for p in r.json()["data"]] == ["shopify.com"]

    r = seeded.get("/v1/programs?q=anthro", headers=ADMIN)
    assert r.json()["meta"]["total"] == 1


def test_single_program_and_404(seeded):
    r = seeded.get("/v1/programs/anthropic.com", headers=ADMIN)
    assert r.json()["data"]["policy"].endswith("responsible-disclosure-policy")
    assert isinstance(r.json()["data"]["history"], list)
    assert seeded.get("/v1/programs/nope.example", headers=ADMIN).status_code == 404


def test_changes_reflect_ingest(seeded):
    r = seeded.get("/v1/changes?kind=added", headers=ADMIN)
    assert r.status_code == 200
    assert r.json()["meta"]["total"] == 2

    # a second identical ingest must not invent changes
    main.store.ingest([
        {"domain": "anthropic.com", "name": "Anthropic", "sources": ["securitytxt"],
         "platforms": [], "policy": "https://www.anthropic.com/responsible-disclosure-policy",
         "emails": [], "contact_urls": [], "expiry": "valid", "expires_on": "2027-01-01",
         "offers_bounty": None, "safe_harbor": None, "securitytxt_url": None,
         "tls_verified": True, "in_scope_domains": [], "first_seen": "2026-11-21"},
    ], run_kind="test")
    r = seeded.get("/v1/changes?kind=changed", headers=ADMIN)
    assert r.json()["meta"]["total"] == 0


def test_change_detects_field_edit(seeded):
    main.store.ingest([
        {"domain": "anthropic.com", "name": "Anthropic", "sources": ["securitytxt"],
         "platforms": [], "policy": "https://www.anthropic.com/changed-policy",
         "emails": [], "contact_urls": [], "expiry": "expired", "expires_on": "2026-01-01",
         "offers_bounty": None, "safe_harbor": None, "securitytxt_url": None,
         "tls_verified": True, "in_scope_domains": [], "first_seen": "2026-11-21"},
    ], run_kind="test")
    body = seeded.get("/v1/changes?kind=changed", headers=ADMIN).json()
    assert body["meta"]["total"] == 1
    row = body["data"][0]
    assert row["domain"] == "anthropic.com"
    assert "policy" in row["fields"]
    assert row["after"]["expiry"] == "expired"


def test_key_lifecycle(client):
    r = client.post("/admin/keys", json={"tier": "free", "owner": "t"}, headers=ADMIN)
    new_key = r.json()["data"]["key"]
    h = {"X-API-Key": new_key}
    assert client.get("/v1/stats", headers=h).status_code == 200
    assert client.delete(f"/admin/keys?key={new_key}", headers=ADMIN).status_code == 200
    assert client.get("/v1/stats", headers=h).status_code == 401


def test_openapi_contract(client):
    spec = client.get("/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    for path in ("/v1/programs", "/v1/programs/{domain}", "/v1/changes", "/v1/stats"):
        assert path in spec["paths"]
    assert "APIKeyHeader" in str(spec["components"]["securitySchemes"])


def test_site_pages(client):
    for path in ("/", "/guide", "/pricing", "/assets/style.css", "/docs"):
        assert client.get(path).status_code == 200, path
