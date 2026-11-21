"""A platform company handle is not a domain, but the program almost always
publishes one: its website, or the assets in scope. Key the row by that, and drop
the handle only when the program publishes nothing host-shaped."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HACKERONE = [
    {"handle": "acronis", "name": "Acronis", "website": "https://www.acronis.com/",
     "offers_bounties": True, "submission_state": "open",
     "targets": {"in_scope": [{"asset_identifier": "*.acronis.com",
                               "asset_type": "WILDCARD"}]}},
    {"handle": "20 minuten", "name": "20 Minuten", "offers_bounties": True,
     "submission_state": "open", "targets": {"in_scope": []}},
    {"handle": "sample_corp", "name": "Sample Corp", "submission_state": "open",
     "website": "", "targets": {"in_scope": [{"asset_identifier": "https://app.sample-corp.io/login",
                                              "asset_type": "URL"}]}},
]


def build(tmp: Path):
    (tmp / "hackerone_data.json").write_text(json.dumps(HACKERONE))
    env = dict(os.environ, VDP_DATA=str(tmp))
    out = subprocess.run([sys.executable, str(ROOT / "bin" / "build_dataset.py")],
                         capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    return {p["domain"]: p for p in json.loads((tmp / "programs.json").read_text())}, json.loads(out.stdout)


def test_handle_maps_to_the_company_domain(tmp_path):
    programs, summary = build(tmp_path)
    assert "acronis.com" in programs
    assert programs["acronis.com"]["platforms"] == ["hackerone"]
    assert "sample-corp.io" in programs
    assert not any("." not in d for d in programs), sorted(programs)
    assert summary["platform_handles_undomainable"] == 1


def test_handle_without_any_host_is_dropped(tmp_path):
    programs, _ = build(tmp_path)
    assert "20 minuten" not in programs
