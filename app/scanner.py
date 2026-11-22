"""Continuous scanner.

Every cycle: refresh the seed list if stale, refresh upstream datasets if stale,
crawl the next chunk of Tranco, rebuild the merged dataset, and ingest it into the
store (which records the diff). Progress is a monotonic offset in `state`, so a
restart resumes where it stopped and wraps around at the end of the seed list.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone

from .store import Store, now

TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"


class Scanner:
    def __init__(self, store: Store, root: str, chunk_size: int = 2000,
                 interval_s: int = 900, concurrency: int = 200,
                 upstream_hours: int = 24):
        self.store = store
        self.root = root
        self.seed = os.path.join(root, "data", "tranco1m.csv")
        self.hits = os.path.join(root, "data", "hits.jsonl")
        self.chunk_size = chunk_size
        self.interval_s = interval_s
        self.concurrency = concurrency
        self.upstream_hours = upstream_hours
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status = {"state": "idle", "last_error": None, "cycles": 0}

    # ---------- seed + upstream ----------
    def ensure_seed(self) -> bool:
        if os.path.exists(self.seed) and os.path.getsize(self.seed) > 1000:
            age_h = (time.time() - os.path.getmtime(self.seed)) / 3600
            if age_h < 24 * 7:
                return True
        try:
            meta = json.loads(_run(["curl", "-fsSL", TRANCO_LATEST]).stdout)
            url = meta["download"]
            _run(["curl", "-fsSL", "-o", self.seed + ".tmp", url], timeout=300)
            os.replace(self.seed + ".tmp", self.seed)
            self.store.set_state("seed_downloaded_at", now())
            return True
        except Exception as e:  # noqa: BLE001
            self.status["last_error"] = f"seed: {e}"
            return os.path.exists(self.seed)

    def ensure_upstream(self) -> None:
        stamp = self.store.get_state("upstream_refreshed_at")
        fresh = False
        if stamp:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(stamp)).total_seconds()
            fresh = age < self.upstream_hours * 3600
        if fresh:
            return
        _run(["bash", os.path.join(self.root, "bin", "fetch_upstream.sh")], timeout=600)
        self.store.set_state("upstream_refreshed_at", now())

    # ---------- one cycle ----------
    def cycle(self) -> dict:
        with self._lock:
            self.status["state"] = "scanning"
            try:
                self.ensure_upstream()
                if not self.ensure_seed():
                    raise RuntimeError("no seed list available")
                total = _count_lines(self.seed)
                self.store.set_state("seed_rows", str(total))
                offset = int(self.store.get_state("coverage_offset", "0") or 0)
                if offset >= total:
                    offset = 0
                chunk = min(self.chunk_size, max(total - offset, 1))
                res = _run([
                    "python3", os.path.join(self.root, "bin", "securitytxt_crawl.py"),
                    "--input", self.seed, "--offset", str(offset), "--limit", str(chunk),
                    "--concurrency", str(self.concurrency), "--out", self.hits,
                    "--recheck"],
                    timeout=3600)
                stats = _last_json(res.stdout) or {}
                _run(["python3", os.path.join(self.root, "bin", "build_dataset.py")],
                     timeout=900)
                programs = json.load(open(os.path.join(self.root, "data", "programs.json"),
                                          encoding="utf-8"))
                # a virgin install has nothing to diff against: seed silently
                seed_only = self.store.stats()["programs"] == 0
                delta = self.store.ingest(programs, run_kind="crawl",
                                          chunk=(offset, chunk),
                                          probes=stats.get("done", chunk),
                                          hits=stats.get("hits", 0),
                                          record_changes=not seed_only)
                self.store.set_state("coverage_offset", str(offset + chunk))
                self.status.update({"state": "idle", "cycles": self.status["cycles"] + 1,
                                    "last_cycle_at": now(), "last_delta": delta,
                                    "last_error": None})
                return delta
            except Exception as e:  # noqa: BLE001
                self.status.update({"state": "error", "last_error": str(e)[:300]})
                return {"error": str(e)[:300]}
            finally:
                if self.status["state"] != "error":
                    self.status["state"] = "idle"

    # ---------- loop ----------
    def _loop(self) -> None:
        while not self._stop.is_set():
            self.cycle()
            self._stop.wait(self.interval_s)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="vdp-scanner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _last_json(text: str) -> dict | None:
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def _count_lines(path: str) -> int:
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)
