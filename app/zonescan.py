"""Zone sweeps as part of the service, not a script on someone's laptop.

One thread, one TLD at a time, in bounded windows: download, extract the names,
then sweep with a time budget. Every phase writes its progress into the same
state the API already uses, so /scans can show a sweep while it is running.

The CZDS bearer token expires. A 401 is reported as `token_expired` on the page
instead of being retried in a loop; the queue simply waits until a fresh token is
in place.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .store import Store, now

CZDS_URL = "https://czds-api.icann.org/czds/downloads/{tld}.zone"


class ZoneSweeper:
    def __init__(self, store: Store, root: str, tlds: list[str], minutes: int = 120,
                 pause_s: int = 300, token: str = "", token_file: str = "",
                 state_dir: str | None = None, files_dir: str | None = None,
                 hits: str | None = None, merge: bool = True):
        self.store = store
        self.root = Path(root)
        self.tlds = tlds
        self.minutes = minutes
        self.pause_s = pause_s
        self.token = token
        self.token_file = token_file
        self.state_dir = Path(state_dir or self.root / "data" / "zone-state")
        self.files_dir = Path(files_dir or self.root / "data" / "zones")
        self.hits = Path(hits or self.root / "data" / "hits-czds.jsonl")
        self.merge = merge
        self.progress = self.state_dir / "progress.json"
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self.status = {"state": "idle", "tld": None, "phase": None, "last_error": None}

    # ---------- helpers ----------
    def _token(self) -> str:
        if self.token:
            return self.token
        if self.token_file and Path(self.token_file).exists():
            return Path(self.token_file).read_text().strip()
        return ""

    def _set(self, **kv) -> None:
        self.status.update(kv)
        kv["updated_at"] = now()
        self.store.set_state("zone_running", json.dumps({**self.status, **kv}))

    def _queue(self) -> list[str]:
        raw = self.store.get_state("zone_queue")
        if raw:
            try:
                queue = [t for t in json.loads(raw) if t]
                if queue:
                    return queue
            except json.JSONDecodeError:
                pass
        return list(self.tlds)

    def _save_queue(self, queue: list[str]) -> None:
        self.store.set_state("zone_queue", json.dumps(queue))

    def _record(self, tld: str, **fields) -> None:
        current = json.loads(self.store.get_state("zone_status") or "{}")
        entry = {**current.get(tld, {}), **fields, "tld": tld, "updated_at": now()}
        current[tld] = entry
        self.store.set_state("zone_status", json.dumps(current))

    # ---------- phases ----------
    def _download(self, tld: str) -> Path:
        token = self._token()
        if not token:
            raise PermissionError("no CZDS token configured")
        self.files_dir.mkdir(parents=True, exist_ok=True)
        raw = self.files_dir / f"{tld}.zone"
        gz = self.files_dir / f"{tld}.zone.gz"
        self._set(phase="download", tld=tld)
        res = subprocess.run(
            ["curl", "-sS", "-m", "3600", "-o", str(gz), "-w", "%{http_code}",
             "-H", f"Authorization: Bearer {token}", "-H", "ngsw-bypass: true",
             CZDS_URL.format(tld=tld)],
            capture_output=True, text=True, timeout=3700)
        code = (res.stdout or "").strip()
        if code != "200":
            gz.unlink(missing_ok=True)
            self._record(tld, phase="download", http=code,
                         error="token expired" if code == "401" else f"http {code}")
            raise PermissionError(f"czds http {code}")
        self._set(phase="extract", tld=tld)
        names = self.files_dir / f"{tld}.names"
        out = subprocess.run(
            [str(self.root / "bin" / "go" / "zonex"), "-in", str(gz), "-tld", tld,
             "-out", str(names)], capture_output=True, text=True, timeout=3600)
        if out.returncode != 0 or not names.exists():
            self._record(tld, phase="extract", error=(out.stderr or "")[:200])
            raise RuntimeError(f"zonex failed for {tld}")
        gz.unlink(missing_ok=True)
        raw.unlink(missing_ok=True)
        return names

    def _sweep(self, tld: str, names: Path) -> dict:
        self._set(phase="sweep", tld=tld)
        cmd = [str(self.root / "bin" / "go" / "scan"), "-zone", str(names), "-tld", tld,
               "-state", str(self.state_dir / "parked"), "-hits", str(self.hits),
               "-max-minutes", str(self.minutes), "-progress", str(self.progress),
               "-dns-workers", "400", "-port-workers", "200", "-http-workers", "150",
               "-dns-timeout", "2s", "-http-timeout", "3s"]
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=(self.minutes + 10) * 60)
        summary = {}
        line = (res.stdout or "").strip().splitlines()[-1] if (res.stdout or "").strip() else ""
        for part in line.split():
            if "=" in part:
                k, _, v = part.partition("=")
                summary[k] = v
        if res.returncode != 0 and not summary:
            raise RuntimeError((res.stderr or "scan failed")[:200])
        try:
            progress = json.loads(self.progress.read_text())
        except (OSError, json.JSONDecodeError):
            progress = {}

        def num(key, cast=float, default=0):
            """Coerce a summary field, tolerating a trailing unit like `rate=34/s`."""
            raw = str(summary.get(key, "") or "").strip()
            if key == "rate":
                raw = raw.removesuffix("/s")
            if not raw:
                return default
            try:
                return cast(raw)
            except (TypeError, ValueError):
                return default

        done = bool(progress.get("done"))
        self._record(tld, phase="sweep", done=done,
                     names=num("names", int),
                     checked=num("checked", int),
                     parked=num("parked_skip", int),
                     hits=num("hits", int),
                     seconds=num("seconds"),
                     rate=num("rate"),
                     stopped_early=summary.get("shards_stopped_early", "0") not in ("0", ""),
                     error=None)
        return {"done": done, "hits": num("hits", int)}

    def merge_hits(self) -> None:
        script = self.root / "bin" / "merge_hits.py"
        if not (self.merge and script.exists()):
            return
        env = {**os.environ, "VDP_ADMIN_KEY": os.environ.get("VDP_ADMIN_KEY", "")}
        subprocess.run(["python3", str(script), "--api", "http://127.0.0.1:8110"],
                       capture_output=True, text=True, timeout=1800, env=env)

    # ---------- one turn ----------
    def tick(self) -> dict:
        queue = self._queue()
        if not queue:
            return {"state": "idle", "reason": "empty queue"}
        tld = queue[0]
        started = time.time()
        try:
            names = self.files_dir / f"{tld}.names"
            if not (names.exists() and names.stat().st_size > 0):
                names = self._download(tld)
            result = self._sweep(tld, names)
            if result["done"]:
                queue = queue[1:] + [tld]
                self._save_queue(queue)
            if result["hits"]:
                self.merge_hits()
            self._set(state="idle", phase=None, tld=None, last_error=None)
            return {"state": "ok", "tld": tld, **result, "seconds": round(time.time() - started)}
        except PermissionError as e:
            self._set(state="blocked", last_error=str(e), tld=tld)
            return {"state": "blocked", "tld": tld, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            self._set(state="error", last_error=str(e)[:200], tld=tld)
            return {"state": "error", "tld": tld, "error": str(e)[:200]}

    def _loop(self) -> None:
        while not self._stop.is_set():
            res = self.tick()
            # a blocked token does not need a tight retry, someone has to refresh it
            wait = 1800 if res.get("state") == "blocked" else self.pause_s
            self._wake.wait(wait)
            self._wake.clear()

    def wake(self) -> None:
        """A fresh token should not wait out the backoff the last failure earned."""
        self._wake.set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="vdp-zone-sweeper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def live(self) -> dict:
        """What the site shows: the running phase plus the last progress snapshot."""
        try:
            snap = json.loads(self.progress.read_text())
        except (OSError, json.JSONDecodeError):
            snap = {}
        try:
            running = json.loads(self.store.get_state("zone_running") or "{}")
        except json.JSONDecodeError:
            running = {}
        return {"status": running, "progress": snap,
                "queue": self._queue(), "tlds": self.tlds,
                "minutes": self.minutes, "configured": bool(self._token())}
