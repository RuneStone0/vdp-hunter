"""The disclose.io directory has to merge into the same program rows as everything
else, not sit beside them. These tests run the real merge script against a
throwaway data directory and assert what ends up in programs.json."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HITS = [{
    "domain": "existing.com", "found_at": "https://existing.com/.well-known/security.txt",
    "source": "securitytxt", "emails": ["security@existing.com"], "contact_urls": [],
    "policy": None, "expiry": "valid", "expires_on": "2027-01-01", "tls_verified": True,
}]

DIODB = [{
    "program_name": "Existing Corp", "policy_url": "https://existing.com/security-policy",
    "offers_bounty": "no", "safe_harbor": "partial", "contact_email": "security@existing.com",
}]

DIRECTORY = [
    {"name": "Existing Corp", "slug": "existing-1", "policy_url": "https://www.existing.com/security-policy",
     "contact": "security@existing.com", "maturity": "L4 Full Safe Harbor", "maturity_level": 4, "score": 92.5},
    {"name": "Fresh Co", "slug": "fresh-2", "policy_url": "https://fresh.example/report",
     "contact": "https://fresh.example/report", "maturity": "L2 Basic VDP", "maturity_level": 2, "score": 44.4},
    {"name": "No Link Co", "slug": "nolink-3", "policy_url": None, "contact": "",
     "maturity": "L1 Contact Only", "maturity_level": 1, "score": 20.0},
    {"name": "Muni A", "slug": "muni-a", "policy_url": "https://shared-z-cert.nl/a", "contact": "cvd@z-cert.nl",
     "maturity": "L3 Partial", "maturity_level": 3, "score": 64.0},
    {"name": "Muni B", "slug": "muni-b", "policy_url": "https://shared-z-cert.nl/b", "contact": "cvd@z-cert.nl",
     "maturity": "L3 Partial", "maturity_level": 3, "score": 64.0},
    {"name": "Muni C", "slug": "muni-c", "policy_url": "https://shared-z-cert.nl/c", "contact": "cvd@z-cert.nl",
     "maturity": "L3 Partial", "maturity_level": 3, "score": 64.0},
    {"name": "Platform Co", "slug": "platform-4", "policy_url": "https://hackerone.com/platformco",
     "contact": "", "maturity": "L2 Basic", "maturity_level": 2, "score": 45.0},
    {"name": "IP Only Co", "slug": "ip-5", "policy_url": "https://23.128.160.51/security-policy",
     "contact": "", "maturity": "L1 security.txt", "maturity_level": 1, "score": 20.0},
]


def build(tmp: Path) -> tuple[dict, dict]:
    (tmp / "hits.jsonl").write_text("".join(json.dumps(r) + "\n" for r in HITS))
    (tmp / "diodb.json").write_text(json.dumps(DIODB))
    (tmp / "disclose_directory.json").write_text(json.dumps(DIRECTORY))
    env = dict(os.environ, VDP_DATA=str(tmp))
    out = subprocess.run([sys.executable, str(ROOT / "bin" / "build_dataset.py")],
                         capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    summary = json.loads(out.stdout)
    programs = {p["domain"]: p for p in json.loads((tmp / "programs.json").read_text())}
    return programs, summary


def test_directory_merges_into_existing_rows(tmp_path):
    programs, summary = build(tmp_path)

    assert set(programs) == {"existing.com", "fresh.example"}, set(programs)

    existing = programs["existing.com"]
    assert "disclose-directory" in existing["sources"]
    assert existing["emails"] == ["security@existing.com"]
    # L4 is an explicit safe-harbor promise, stronger than diodb's "partial"
    assert existing["safe_harbor"] == "full"
    assert existing["disclose_maturity"] == "L4 Full Safe Harbor"


def test_new_org_with_its_own_policy_becomes_a_program(tmp_path):
    programs, _ = build(tmp_path)
    fresh = programs["fresh.example"]
    assert fresh["name"] == "Fresh Co"
    assert fresh["sources"] == ["disclose-directory"]
    assert fresh["policy"] == "https://fresh.example/report"
    assert fresh["self_managed"] is True


def test_rows_without_a_derivable_domain_are_skipped(tmp_path):
    _, summary = build(tmp_path)
    # No Link Co, Platform Co and a policy URL on a bare IP
    assert summary["disclose_skipped_nodomain"] == 3


def test_shared_reporting_host_is_not_attributed_to_one_org(tmp_path):
    programs, summary = build(tmp_path)
    assert not any("shared-z-cert.nl" in d for d in programs)
    assert summary["disclose_skipped_shared_host"] == 3
    assert "shared-z-cert.nl" in summary["disclose_shared_hosts"]


def test_dedup_is_by_registrable_domain(tmp_path):
    """www.existing.com and existing.com are one program, not two."""
    programs, _ = build(tmp_path)
    assert "www.existing.com" not in programs
