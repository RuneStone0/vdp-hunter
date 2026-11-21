"""directory.disclose.io carries two records for FloQast: a security.txt discovery
on api-eu.floqast.app with a security@floqast.com contact, and a stub with no
links at all. The merge has to produce one program, on the corporate domain."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DIRECTORY = [
    {"name": "floqast", "slug": "floqast-650148", "maturity": "L2 Basic", "maturity_level": 2,
     "score": 45.0, "policy_url": "https://api-eu.floqast.app/.well-known/security.txt",
     "contact": "security@floqast.com"},
    {"name": "FloQast", "slug": "floqast-697488", "maturity": "L1 Contact Only",
     "maturity_level": 1, "score": 20.0, "policy_url": None, "contact": ""},
    # same name, genuinely different companies: must not fold
    {"name": "Coop", "slug": "coop-uk", "maturity": "L3 Partial", "maturity_level": 3,
     "score": 64.0, "policy_url": "https://coop.co.uk/security", "contact": ""},
    {"name": "coop", "slug": "coop-no", "maturity": "L3 Partial", "maturity_level": 3,
     "score": 64.0, "policy_url": "https://coop.no/security", "contact": ""},
]


def build(tmp: Path) -> tuple[dict, dict]:
    (tmp / "disclose_directory.json").write_text(json.dumps(DIRECTORY))
    env = dict(os.environ, VDP_DATA=str(tmp))
    out = subprocess.run([sys.executable, str(ROOT / "bin" / "build_dataset.py")],
                         capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    programs = {p["domain"]: p for p in json.loads((tmp / "programs.json").read_text())}
    return programs, json.loads(out.stdout)


def test_duplicate_records_become_one_program(tmp_path):
    programs, summary = build(tmp_path)

    assert "floqast.com" in programs, sorted(programs)
    assert "floqast.app" not in programs, "the security.txt subdomain must not become its own program"
    assert summary["disclose_orgs_folded"] == 1

    row = programs["floqast.com"]
    assert row["emails"] == ["security@floqast.com"]
    assert row["policy"] == "https://api-eu.floqast.app/.well-known/security.txt"
    # the folded stub must not drag the maturity down
    assert row["disclose_score"] == 45.0


def test_same_name_on_different_domains_stays_separate(tmp_path):
    programs, summary = build(tmp_path)
    assert "coop.co.uk" in programs and "coop.no" in programs
    assert summary["disclose_orgs_kept_apart"] == 1
