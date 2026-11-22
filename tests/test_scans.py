"""The /scans page and the snapshot endpoint the zone runner posts to."""
import json
import subprocess

import pytest

from app import main, zonescan

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


def test_czds_token_is_installed_for_the_sweeper(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CZDS_TOKEN_FILE", str(tmp_path / "czds_token.txt"))
    assert client.post("/admin/czds-token", json={"token": "short"},
                       headers=ADMIN).status_code == 422
    token = "e" * 600
    r = client.post("/admin/czds-token", json={"token": token}, headers=ADMIN)
    assert r.status_code == 200
    assert (tmp_path / "czds_token.txt").read_text() == token
    assert (tmp_path / "czds_token.txt").stat().st_mode & 0o777 == 0o600


def test_czds_token_round_trip(client):
    """The host-side sweep reads the token back over the API, so install then read must work."""
    import os
    from pathlib import Path
    tok_file = Path(os.environ.get("CZDS_TOKEN_FILE", "data/czds_token.txt"))
    tok_file.unlink(missing_ok=True)
    assert client.get("/admin/czds-token", headers=ADMIN).status_code == 404
    token = "x" * 60
    assert client.post("/admin/czds-token", json={"token": token},
                       headers=ADMIN).status_code == 200
    body = client.get("/admin/czds-token", headers=ADMIN).json()["data"]
    assert body["token"] == token and body["length"] == 60
    assert client.get("/admin/czds-token").status_code == 401
    tok_file.unlink(missing_ok=True)


def test_zone_snapshot_needs_a_tld(client):
    assert client.post("/admin/scan-status", json={"hits": 1},
                       headers=ADMIN).status_code == 422


def test_czds_page_install_wakes_the_blocked_sweeper(client, tmp_path, monkeypatch):
    """A token pasted at /czds-token must not sit behind the 30 minute blocked backoff."""
    monkeypatch.setenv("CZDS_TOKEN_FILE", str(tmp_path / "czds_token.txt"))
    monkeypatch.setattr(main, "_czds_verify", lambda token: (True, "ICANN answered 206"))
    woke = []
    monkeypatch.setattr(main.sweeper, "wake", lambda: woke.append(1))
    token = "z" * 60
    r = client.post("/czds-token", data={"token": token})
    assert r.status_code == 200
    assert (tmp_path / "czds_token.txt").read_text() == token
    assert (tmp_path / "czds_token.txt").stat().st_mode & 0o777 == 0o600
    assert main.sweeper.token == token
    assert woke == [1]
    running = json.loads(main.store.get_state("zone_running") or "{}")
    assert running["state"] == "idle" and running["last_error"] is None


def test_zone_download_puts_the_installed_token_on_the_wire(tmp_path, monkeypatch):
    """A download that sends a placeholder instead of the token 401s forever."""
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="401", stderr="")

    monkeypatch.setattr(zonescan.subprocess, "run", fake_run)
    token = "live-token-abcdef"
    sweeper = zonescan.ZoneSweeper(main.store, str(tmp_path), ["accountant"],
                                   token=token, token_file="",
                                   files_dir=str(tmp_path / "zones"))
    with pytest.raises(PermissionError):
        sweeper._download("accountant")
    sent = [a for a in seen["cmd"] if a.startswith("Authorization:")]
    assert sent == [f"Authorization: Bearer {token}"]
    assert not (tmp_path / "zones" / "accountant.zone.gz").exists()

