# vdp-hunter

Finds vulnerability disclosure programs (VDPs) and bug bounty programs that the
big aggregators miss, by probing `/.well-known/security.txt` (RFC 9116) across a
domain seed list, then merging the hits with the existing public datasets into one
diffable file.

## Why this exists

Two free datasets cover most of the market, and neither one covers all of it:

| Dataset | What it holds | Measured 2026-11-21 | Gap |
|---|---|---|---|
| [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data) | HackerOne, Bugcrowd, Intigriti, YesWeHack programs + in-scope assets | 448 H1 (218 paying), 296 BC, 144 Intigriti, 52 YWH, 37,955 domains | no self-managed programs; no other platforms |
| [`disclose/diodb`](https://github.com/disclose/diodb) | self-hosted VDPs and bounties, safe-harbor status | 2,433 programs (2,197 policy on own site, 437 paying) | human-curated PRs, so coverage lags and no scope data |

`vdp-hunter` adds the machine-discovered long tail: any organization that
publishes a security.txt is by definition inviting reports, and that file is
public, structured, and cheap to check.

## Measured baseline from the first runs

Tranco top-1M seed, 2026-11-21, 58,259 domains probed end to end (22.5 minutes at
37 domains/s and 300 connections):

| Rank band | Domains probed | security.txt found | Hits per 1k |
|---|---|---|---|
| 1 - 1,000 | 1,000 | 216 | 216 |
| 1,001 - 10,000 | 9,000 | 267 | 30 |
| 10,001 - 58,259 | 48,259 | 128 | 2.7 |
| **total** | **58,259** | **611** | **10.5** |

Of the 611: 335 unexpired, 225 with no `Expires` field at all, 52 already expired,
79 served over an unverified TLS chain. After matching against diodb (by policy /
security.txt host and program name) and against every platform program and scope
list, 525 program rows have no match. 124 of those still point at a platform URL
that the name join missed, leaving **401 programs in no existing dataset**, and
**216 of those are unexpired, self-managed, and have a usable contact or policy**.
Examples: Anthropic, Allianz, Bloomberg, Booking.com, Calendly, Ancestry, AWS VDP,
9GAG, Academia.edu.

Adoption collapses below the top 10k, so the full list is worth roughly 1,500 to
2,500 more hits, not tens of thousands.

Second channel, measured on 400 domains at ranks 20k-20.4k: conventional page
probing (`/security`, `/responsible-disclosure`, `/bug-bounty`, ...) found 5
signals, 1.25 per 100 domains, at 7 potential requests per domain versus 2 for
security.txt. Real pages (ISPsystem, Termius) but poor yield, so it stays a
targeted add-on rather than the main crawl.

## How it works

```
Tranco top-1M  ─┐
                ├─> securitytxt_crawl.py ─> data/hits.jsonl   (resumable append log)
Common Crawl  ──┘                                   │
                                                    ▼
diodb + platform data ────────────────────> build_dataset.py ─> data/programs.json
                                                    │            data/programs.jsonl
                                                    └──────────> data/NEWS.md (diff vs last run)
```

- **2 requests per domain maximum**: `https://d/.well-known/security.txt`, then
  `/security.txt` only if the first returned 404. Plain HTTP is only tried when
  HTTPS fails at the transport layer.
- **TLS is verified first.** Hosts with broken chains get exactly one unverified
  retry, and those records are flagged `tls_verified: false` so their contact
  addresses can be treated as untrusted.
- **Resumable**: every hit is appended to JSONL immediately, so a crash costs
  nothing. Re-running skips domains already recorded.
- **Diffs are free**: commit `data/programs.json` after each run and `git log -p`
  is the history. `data/NEWS.md` gives the same delta in prose.

## Politeness

security.txt exists to be fetched by automated scanners, but a 1M-domain pass is
still bulk traffic from a residential IP:

- User-Agent names the project and repo; `limit_per_host=1`; 400 global
  connections; 4s connect / 8s total timeouts; no retries beyond the TLS fallback.
- Expect a small number of abuse reports from edge firewalls anyway. Run large
  passes overnight, and keep the UA reachable.

## Usage

```bash
# refresh upstream datasets (diodb, 4 platforms, flat scope list)
bin/fetch_upstream.sh

# crawl a slice; resumable, safe to re-run
python3 bin/securitytxt_crawl.py \
  --input tranco1m.csv --limit 50000 --offset 0 \
  --concurrency 400 --out data/hits.jsonl

# rebuild programs.json + NEWS.md (diff is computed against the previous file)
python3 bin/build_dataset.py
```

Seed list: Tranco daily list, `https://tranco-list.eu/api/lists/date/latest`
(CSV: rank,domain).

## Schema (`data/programs.json`)

| Field | Meaning |
|---|---|
| `domain` | registrable domain, heuristic (handles `co.uk`-style suffixes) |
| `sources` | any of `securitytxt`, `diodb`, `hackerone`, `bugcrowd`, `intigriti`, `yeswehack` |
| `platforms` | platforms whose program or scope list contains this org |
| `policy` | disclosure policy URL |
| `emails` / `contact_urls` | from security.txt `Contact:` |
| `expiry`, `expires_on` | RFC 9116 `Expires` state (`valid` / `expired` / `missing`) |
| `tls_verified` | whether the security.txt was fetched over a verified chain |
| `offers_bounty`, `safe_harbor` | from diodb or the platform record |
| `first_seen` | first snapshot date this domain appeared |
| `in_scope_domains` | up to 25 domains from the platform scope lists |

## Known limits

- Only the seed list is covered. 1M domains is a sample of the internet, not all of it.
- Registrable-domain rollup is a heuristic; multi-tenant hosts (`*.amazonaws.com`,
  `*.github.io`) are not special-cased yet.
- No classification of bounty vs VDP from policy text yet, so "paying" is only
  known where diodb or a platform says so.
- An expired `Expires` is recorded, not dropped: 47% of hits in the head of the
  list are expired, which is itself a useful signal about program hygiene.
- Platform-hosted programs whose security.txt points at HackerOne/Bugcrowd are
  matched to the platform row only if the org name matches; some are labelled
  self-managed when they are not.

## Roadmap

- [ ] Full Tranco top-1M pass, nightly incremental re-check of known hits.
- [ ] Common Crawl index sweep for pages that mention responsible disclosure
      (catches orgs with no security.txt at all).
- [ ] Platform coverage: Immunefi (web3), huntr (AI/ML), Hackenproof, Cobalt,
      Open Bug Bounty, plus US federal `.gov` VDPs from CISA BOD 20-01.
- [ ] Classify bounty vs VDP by fetching `Policy:` once and scanning for reward
      language.
- [ ] Publish as a fork-style repo with hourly-rebuilt data, mirroring
      `bounty-targets-data`'s structure so existing tooling can consume it.

## Licence

Upstream data keeps its own licence (MIT for `bounty-targets-data`, CC0 for
`diodb`). This pipeline is MIT.
