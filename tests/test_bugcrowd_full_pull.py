"""End-to-end pull through a loopback JSON:API stub.

This is the test that would have caught the real failure modes in production:
wrong auth header, a page walk that stops early, a brief request that 404s for
one engagement taking the whole run down, and a row that arrives with no URL for
build_dataset to key on.

The stub answers only what the client is allowed to call, so a whitelist
regression shows up here too.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(__file__).resolve().parent.parent

SEEN = {"auth": [], "paths": []}

ENGAGEMENTS = [
    {"id": "aaaaaaaa-0000-0000-0000-000000000001", "type": "engagement",
     "attributes": {"code": "alpha-1", "state": "in_progress"}},
    {"id": "aaaaaaaa-0000-0000-0000-000000000002", "type": "engagement",
     "attributes": {"code": "bravo-2", "state": "paused"}},
    {"id": "aaaaaaaa-0000-0000-0000-000000000003", "type": "engagement",
     "attributes": {"code": "charlie-3", "state": "in_progress"}},
]

BRIEF_ALPHA = {
    "id": "b1", "type": "engagement_brief",
    "attributes": {
        "name": "Alpha", "published_at": "2026-11-01T00:00:00Z", "redacted": False,
        "safe_harbor_status": "full", "coordinated_disclosure": True,
        "tagline": "Alpha tagline",
        "scope": [
            {"name": "Web", "in_scope": True,
             "reward_range": {"p1_max_cents": 500000, "program_max_cents": 500000},
             "targets": [{"name": "alpha.example", "uri": "https://alpha.example",
                          "category": "website"}]},
            {"name": "Out", "in_scope": False,
             "targets": [{"name": "staging", "uri": "https://staging.alpha.example",
                          "category": "website"}]},
        ],
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/vnd.bugcrowd+json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        SEEN["paths"].append(u.path)
        SEEN["auth"].append(self.headers.get("Authorization"))
        if u.path == "/engagements":
            limit = int(q.get("page[limit]", ["25"])[0])
            offset = int(q.get("page[offset]", ["0"])[0])
            page = ENGAGEMENTS[offset:offset + limit]
            self._send(200, {"data": page,
                             "meta": {"count": len(page), "total_hits": len(ENGAGEMENTS)}})
            return
        if u.path.endswith("/engagement_briefs"):
            if "000000000001" in u.path:
                self._send(200, {"data": [BRIEF_ALPHA], "meta": {"count": 1}})
            elif "000000000003" in u.path:
                self._send(200, {"data": [], "meta": {"count": 0}})
            else:
                self._send(404, {"errors": [{"status": 404}]})
            return
        self._send(404, {"errors": [{"status": 404}]})


def test_full_pull_writes_upstream_shaped_rows(tmp_path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        env = {k: v for k, v in os.environ.items() if k != "BUGCROWD_TOKEN"}
        env.update({"BUGCROWD_TOKEN": "tokenname:tokensecret",
                    "BUGCROWD_API_BASE": "http://127.0.0.1:%d" % srv.server_address[1],
                    "VDP_DATA": str(tmp_path)})
        res = subprocess.run(
            [sys.executable, str(REPO / "bin" / "fetch_bugcrowd_api.py"),
             "--out", str(tmp_path / "api.json"),
             "--status", str(tmp_path / "status.json"),
             "--cred-file", str(tmp_path / "absent"), "--limit", "2"],
            capture_output=True, text=True, env=env, timeout=90)
    finally:
        srv.shutdown()
        srv.server_close()

    assert res.returncode == 0, res.stderr
    assert SEEN["auth"][0] == "Token tokenname:tokensecret"
    assert set(SEEN["paths"]) <= {"/engagements",
                                  "/engagements/aaaaaaaa-0000-0000-0000-000000000001/engagement_briefs",
                                  "/engagements/aaaaaaaa-0000-0000-0000-000000000003/engagement_briefs"}

    rows = json.loads((tmp_path / "api.json").read_text())
    assert [r["url"] for r in rows] == ["https://bugcrowd.com/engagements/alpha-1"]
    row = rows[0]
    assert row["safe_harbor"] == "full"
    assert row["allows_disclosure"] is True
    assert row["max_payout"] == 5000
    assert [t["uri"] for t in row["targets"]["in_scope"]] == ["https://alpha.example"]
    assert [t["uri"] for t in row["targets"]["out_of_scope"]] == ["https://staging.alpha.example"]

    status = json.loads((tmp_path / "status.json").read_text())
    assert status["status"] == "ok"
    assert status["engagements_seen"] == 3
    assert status["rows"] == 1
    assert status["skipped_closed_or_briefless"] == 2
    assert status["with_payout"] == 1
