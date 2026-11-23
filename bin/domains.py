"""Compatibility shim: the canonical validators live in app/domains.py.

bin/ scripts run with bin/ on sys.path and app/ on a package path, so this
re-export keeps `from domains import registrable` working in either context
without a second copy of the rules.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.domains import (SLD, TLD_ONLY, asset_domain, clean_host, is_ip,  # noqa: F401,E402
                         is_valid, registrable, to_ascii)
