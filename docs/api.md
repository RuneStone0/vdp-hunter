# vdp-hunter API

Base URL: `https://api.vdphunter.com` (hosted) or `http://localhost:8110` (self-hosted).
Full machine-readable contract: [`/openapi.json`](https://github.com/RuneStone0/vdp-hunter) served by the
app itself. Interactive reference: `/docs`. Human guide: `/guide`.

## Authentication

All `/v1/*` endpoints require `X-API-Key`.

| Tier | Requests / minute |
|---|---|
| free | 120 |
| pro | 2,000 |
| admin | unlimited |

Missing or revoked keys return `401`; over-limit returns `429`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, no key required |
| GET | `/v1/programs` | Search current dataset |
| GET | `/v1/programs/{domain}` | One program plus its last 20 changes |
| GET | `/v1/changes` | Added / removed / changed rows since a timestamp |
| GET | `/v1/changes/{id}` | Single change record |
| GET | `/v1/stats` | Counts, expiry distribution, coverage position |
| GET | `/v1/sources` | Where each data source comes from and how often it refreshes |
| GET | `/v1/runs` | Recent scan runs |
| GET | `/feed.json` | Public preview: the 10 newest changes, no key, paid-only rows masked |
| POST | `/admin/keys` | Issue a key (admin) |
| DELETE | `/admin/keys?key=` | Revoke a key (admin) |
| POST | `/admin/scan` | Run one scan cycle now (admin) |
| POST | `/admin/reload` | Re-ingest `data/programs.json` without crawling (admin) |

## Response envelope

```json
{
  "data": [ ... ],
  "meta": { "count": 100, "total": 2763, "limit": 100, "offset": 0,
            "has_more": true, "generated_at": "2026-11-21T16:40:00+00:00" }
}
```

Single-object endpoints return `{"data": {...}, "meta": {"count": 1, ...}}`.

## Filters (`/v1/programs`)

`q` (substring on domain, name, policy), `platform`, `source`, `bounty` (`yes`/`no`),
`expiry` (`valid`/`expired`/`missing`), `limit` (1-1000), `offset`, `sort`
(`domain`, `expiry`, `expires_on`, `updated_at`).

## Change feed semantics

- Append-only, newest first.
- `since` is inclusive, timezone aware.
- `kind=changed` rows carry `fields` plus `before` / `after` objects holding only the
  fields that moved.
- Poll with the newest `ts` you have seen. Do not diff `/v1/programs` yourself.

`/feed.json` is not part of the paid API: it is the same ten rows the public `/changes`
page renders, for the page's own polling, and it masks rows that belong to the paid
dataset (a stable masked domain, no contact values). It accepts `kind` and `after_id`
and returns `no-store`. Anything older, whole, or unmasked comes from `/v1/changes`
with a key. `VDP_FEED_REVEAL=1` disables the mask for local review only.

## Cadence

A scan cycle probes the next Tranco slice, rebuilds the merged dataset, and records the
diff. Upstream platform data refreshes daily. Coverage wraps at the end of the seed list.

## Errors

| Code | Meaning |
|---|---|
| 401 | Missing, invalid or revoked key |
| 403 | Admin key required |
| 404 | Unknown domain or change id |
| 422 | Parameter validation failure |
| 429 | Tier rate limit exceeded |

## Versioning

Breaking changes ship under a new path prefix (`/v2`). Additive fields appear without a
version bump; clients must ignore unknown fields.
