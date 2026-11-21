import os
import sys
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="vdp-test-"))
os.environ["VDP_DB"] = str(TMP / "test.db")
os.environ["VDP_ADMIN_KEY"] = "test-admin-key"
os.environ["VDP_SCAN_ENABLED"] = "0"
os.environ["VDP_BOOTSTRAP"] = "0"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

ADMIN = {"X-API-Key": "test-admin-key"}


@pytest.fixture()
def client():
    with main.store.conn() as c:
        c.execute("DELETE FROM programs")
        c.execute("DELETE FROM changes")
        c.execute("DELETE FROM runs")
    with TestClient(main.app) as tc:
        yield tc


@pytest.fixture()
def seeded(client):
    main.store.ingest([
        {"domain": "anthropic.com", "name": "Anthropic", "sources": ["securitytxt"],
         "platforms": [], "policy": "https://www.anthropic.com/responsible-disclosure-policy",
         "emails": [], "contact_urls": [], "expiry": "valid", "expires_on": "2027-01-01",
         "offers_bounty": None, "safe_harbor": None, "securitytxt_url": None,
         "tls_verified": True, "in_scope_domains": [], "first_seen": "2026-11-21"},
        {"domain": "shopify.com", "name": "Shopify", "sources": ["securitytxt", "hackerone"],
         "platforms": ["hackerone"], "policy": "https://hackerone.com/shopify",
         "emails": ["security@shopify.com"], "contact_urls": [], "expiry": "valid",
         "expires_on": "2027-02-01", "offers_bounty": "yes", "safe_harbor": None,
         "securitytxt_url": None, "tls_verified": True, "in_scope_domains": ["shopify.com"],
         "first_seen": "2026-11-21"},
    ], run_kind="test")
    return client
