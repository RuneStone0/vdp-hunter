# Architecture

```
Tranco top-1M ─┐
               ├─> bin/securitytxt_crawl.py ─> data/hits.jsonl
page probe ────┘        (resumable, 2 req/domain)
                              │
upstream dumps ───────────────┴─> bin/build_dataset.py ─> data/programs.json
(diodb, H1, BC,                    (merge + NEWS.md diff)
 Intigriti, YWH)                              │
                                              ▼
                                   app/scanner.py.cycle()
                                   ├─ crawl next 2,000-domain slice
                                   ├─ rebuild programs.json
                                   └─ app/store.py.ingest()  ──> SQLite
                                                                 ├─ programs (current)
                                                                 ├─ changes  (append-only)
                                                                 └─ runs     (scan log)
                                                                        │
                                   app/main.py (FastAPI) ───────────────┘
                                   ├─ /v1/* JSON API (X-API-Key, one paid tier)
                                   ├─ /openapi.json, /docs, /redoc
                                   └─ /, /guide, /pricing
```

## Design decisions

**SQLite, not Postgres.** The dataset is a few thousand rows and the write pattern is one
snapshot per cycle. SQLite keeps the whole product installable in one container with no
external service.

**Diff on ingest, not on read.** `store.ingest()` compares the incoming snapshot against the
stored rows and writes explicit `changes` rows. That makes the change feed O(1) to read and
keeps history even if the upstream file is regenerated.

**Order-insensitive comparison.** List fields (`sources`, `platforms`, `emails`,
`in_scope_domains`) are sorted on both sides before comparing, otherwise Python set
iteration order produces phantom "changed" rows every cycle. This was a real bug; there is
a test for it (`test_changes_reflect_ingest`).

**Idempotent ingest.** Re-ingesting the same snapshot must produce zero changes. If it does
not, the diff is noise and the product is worthless.

**Coverage is a cursor.** `state.coverage_offset` advances through the seed list and wraps.
Restarting the container resumes; a full pass over 1M domains takes hours, so partial
coverage is normal and is reported in `/v1/stats`.

**TLS is verified first, and flagged.** A security.txt served over a broken chain can carry
attacker-injected contacts, so those rows are labelled `tls_verified: false` instead of being
silently trusted or silently dropped.

## Known limits

- Registrable-domain rollup is heuristic; multi-tenant hosts are not special-cased.
- Coverage is the Tranco top-1M, not the internet.
- Bounty vs VDP is only known where diodb or a platform states it; policy text is not parsed yet.
- Upstream platform joins by name can miss programs whose handle differs from the domain.
