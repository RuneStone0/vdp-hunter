"""The Bugcrowd API pull is the only source that carries a program's out-of-scope
groups, per-severity reward ranges and safe harbor status, and it describes the
same engagements the daily bounty-targets-data file already lists. Two failures
matter: the row shape drifts from what build_dataset expects, or both rows get
merged and the program's scope is counted twice.
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bin"))

import fetch_bugcrowd_api as bc  # noqa: E402

from app import main  # noqa: E402

ADMIN = {"X-API-Key": "test-admin-key"}


def brief(in_scope=None, out_scope=None, **attrs):
    scope = []
    if in_scope is not None:
        scope.append({"name": "Web", "in_scope": True, "targets": in_scope,
                      "reward_range": {"p1_max_cents": 500000, "program_max_cents": 500000}})
    if out_scope is not None:
        scope.append({"name": "Out", "in_scope": False, "targets": out_scope})
    base = {"name": "Example", "published_at": "2026-11-01T00:00:00Z",
            "redacted": False, "safe_harbor_status": "full", "scope": scope}
    base.update(attrs)
    return {"id": "b1", "type": "engagement_brief", "attributes": base}


def engagement(code="example-1", state="in_progress"):
    return {"id": "e1", "type": "engagement",
            "attributes": {"code": code, "state": state}}


def test_scope_splits_in_and_out():
    ins, outs = bc.brief_scope(brief(
        [{"name": "app", "uri": "https://app.example.com", "category": "website"}],
        [{"name": "blog", "uri": "https://blog.example.com", "category": "website"}]))
    assert [t["target"] for t in ins] == ["https://app.example.com"]
    assert [t["target"] for t in outs] == ["https://blog.example.com"]
    assert ins[0]["type"] == "website"


def test_row_shape_matches_upstream_contract():
    row = bc.to_row(engagement(), [brief(
        [{"name": "app", "uri": "https://app.example.com", "category": "website"}], [])])
    assert row["url"] == "https://bugcrowd.com/engagements/example-1"
    assert row["safe_harbor"] == "full"
    assert row["max_payout"] == 5000          # 500000 cents
    assert row["offers_bounties"] is True
    assert row["submission_state"] == "open"
    assert row["targets"]["in_scope"][0]["uri"] == "https://app.example.com"
    assert row["managed_by_bugcrowd"] is True


def test_zero_reward_range_is_not_a_bounty():
    row = bc.to_row(engagement(), [brief(
        [{"name": "app", "uri": "https://app.example.com"}], [],
        scope=[{"name": "Web", "in_scope": True, "reward_range": {},
                "targets": [{"name": "app", "uri": "https://app.example.com"}]}])])
    assert row["max_payout"] == 0
    assert row["offers_bounties"] is False


def test_closed_engagement_is_marked_closed():
    row = bc.to_row(engagement(state="completed"), [brief()])
    assert row["submission_state"] == "closed"


def test_redacted_brief_is_ignored():
    live = brief([{"name": "app", "uri": "https://app.example.com"}])
    dead = {"id": "b0", "type": "engagement_brief",
            "attributes": {"name": "Old", "redacted": True, "scope": []}}
    row = bc.to_row(engagement(), [dead, live])
    assert row["name"] == "Example"
    assert len(row["targets"]["in_scope"]) == 1


@pytest.mark.parametrize("url,code", [
    ("https://bugcrowd.com/engagements/CCData-mbb-og", "CCData-mbb-og"),
    ("https://bugcrowd.com/engagements/abc/", "abc"),
])
def test_engagement_code_from_url(url, code):
    import build_dataset
    assert build_dataset.engagement_code({"url": url}) == code
    assert build_dataset.engagement_code({"url": "https://bugcrowd.com/programs/x"}) == ""


def _write(tmp, name, payload):
    (tmp / name).write_text(json.dumps(payload))


def test_build_dataset_prefers_the_api_row(tmp_path):
    """Same engagement in both files: the API row wins and the upstream row must
    not add a second scope entry for the same program."""
    upstream = {"name": "Example Program", "url": "https://bugcrowd.com/engagements/example-1",
                "submission_state": "open", "offers_bounties": True, "max_payout": 100,
                "targets": {"in_scope": [{"type": "website",
                                          "asset_identifier": "https://old.example.com"}],
                            "out_of_scope": []}}
    api_row = {"name": "Example Program", "url": "https://bugcrowd.com/engagements/example-1",
               "submission_state": "open", "offers_bounties": True, "max_payout": 5000,
               "safe_harbor": "full",
               "targets": {"in_scope": [{"type": "website", "target": "https://app.example.com",
                                         "uri": "https://app.example.com", "name": "app"}],
                           "out_of_scope": [{"type": "website", "target": "https://old.example.com",
                                             "uri": "https://old.example.com", "name": "old"}]}}
    _write(tmp_path, "bugcrowd_data.json", [upstream])
    _write(tmp_path, "bugcrowd_api.json", [api_row])
    env = dict(os.environ, VDP_DATA=str(tmp_path))
    res = subprocess.run([sys.executable, str(REPO / "bin" / "build_dataset.py")],
                         capture_output=True, text=True, env=env, timeout=120)
    assert res.returncode == 0, res.stderr[-800:]
    programs = json.loads((tmp_path / "programs.json").read_text())
    row = next(p for p in programs if p["domain"] == "example.com")
    assert row["safe_harbor"] == "full", "API row should supply safe harbor"
    assert row["in_scope_domains"] == ["example.com"], row["in_scope_domains"]
    assert len(row["scope_in"]) == 1, row["scope_in"]
    assert [s["target"] for s in row["scope_out"]] == ["https://old.example.com"]
    assert not any(p["domain"] == "old.example.com" for p in programs)


def test_pull_skips_without_a_credential(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "BUGCROWD_TOKEN"}
    env["VDP_DATA"] = str(tmp_path)
    res = subprocess.run(
        [sys.executable, str(REPO / "bin" / "fetch_bugcrowd_api.py"),
         "--out", str(tmp_path / "api.json"), "--status", str(tmp_path / "status.json"),
         "--cred-file", str(tmp_path / "absent")],
        capture_output=True, text=True, env=env, timeout=60)
    assert res.returncode == 0, res.stderr
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["status"] == "no_credential"
    assert not (tmp_path / "api.json").exists(), "a skip must not write an empty dataset"


def test_endpoint_reports_no_credential(client, monkeypatch):
    fake = SimpleNamespace(returncode=0,
                           stdout='{"status": "no_credential", "detail": "absent"}\n',
                           stderr="")
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: fake)
    body = client.post("/admin/bugcrowd-sync", headers=ADMIN).json()
    assert body["data"]["status"] == "no_credential"
    assert body["data"]["ingested"] is False


def test_endpoint_stops_when_the_build_fails(client, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[-1].endswith("fetch_bugcrowd_api.py"):
            return SimpleNamespace(returncode=0, stdout='{"status": "ok", "rows": 3}\n', stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(main.subprocess, "run", fake_run)
    body = client.post("/admin/bugcrowd-sync", headers=ADMIN).json()
    assert body["data"]["status"] == "build_failed"
    assert body["data"]["ingested"] is False
    assert len(calls) == 2


def test_endpoint_requires_admin_key(client):
    r = client.post("/admin/bugcrowd-sync")
    assert r.status_code in (401, 403)
