"""safe_harbor is the field that turns a raw security.txt into a commercial signal:
full means the company explicitly authorises testing, partial means it promises not
to pursue legal action. It has to be filterable in both the API and the explorer."""

from app import main  # noqa: E402

ADMIN = {"X-API-Key": "test-admin-key"}


def _row(domain, harbor):
    return {"domain": domain, "name": domain, "sources": ["disclose-directory"],
            "platforms": [], "policy": f"https://{domain}/policy", "emails": [],
            "contact_urls": [], "expires_on": None, "expiry": "missing",
            "offers_bounty": None, "safe_harbor": harbor, "securitytxt_url": None,
            "tls_verified": None, "in_scope_domains": []}


def _seed():
    main.store.ingest([_row("full.example", "full"),
                       _row("partial.example", "partial"),
                       _row("none.example", "none")], record_changes=False)


def test_api_filters_by_safe_harbor(client):
    _seed()
    body = client.get("/v1/programs?safe_harbor=full", headers=ADMIN).json()
    assert [r["domain"] for r in body["data"]] == ["full.example"]
    body = client.get("/v1/programs?safe_harbor=partial", headers=ADMIN).json()
    assert [r["domain"] for r in body["data"]] == ["partial.example"]


def test_explorer_offers_the_filter(client):
    _seed()
    body = client.get("/explore?safe_harbor=full").text
    assert '<option value="full" selected>Full safe harbor</option>' in body
    assert "of 1 matching programs" in body
    assert "full.example" in body and "partial.example" not in body
