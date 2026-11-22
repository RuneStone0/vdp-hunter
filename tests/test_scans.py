"""The /scans page and the snapshot endpoint the zone runner posts to."""
ADMIN = {"X-API-Key": "test-admin-key"}


def test_scans_page_renders(client):
    r = client.get("/scans")
    assert r.status_code == 200
    body = r.text
    assert "security.txt crawl" in body
    assert "CZDS zone sweep" in body
    # the placeholders must all be substituted, or the page ships raw braces
    assert "{{" not in body


def test_zone_snapshot_shows_up(client):
    payload = {"tld": "tax", "names": 31811, "checked": 31811, "parked": 0,
               "hits": 3, "seconds": 48.8, "rate": 651.0, "stopped_early": False}
    r = client.post("/admin/scan-status", json=payload, headers=ADMIN)
    assert r.status_code == 200
    page = client.get("/scans").text
    assert "tax" in page and "31,811" in page
    data = client.get("/v1/scans", headers=ADMIN).json()["data"]
    assert data["zones"]["tax"]["hits"] == 3
    assert data["crawl"]["seed"]["path"].endswith("tranco1m.csv")


def test_zone_snapshot_needs_a_tld(client):
    assert client.post("/admin/scan-status", json={"hits": 1},
                       headers=ADMIN).status_code == 422
