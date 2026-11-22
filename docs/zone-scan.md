# Zone-file scanning: how to reach every domain monthly

The goal is a monthly look at every name under the TLDs we hold, for a
`.well-known/security.txt`. That is about 240M names, and the naive version
(a request per name) is impossible. This is the staged design that makes it
possible, with the numbers that were measured rather than assumed.

## The four decisions

**1. Ask the cheapest question first, and only escalate on a yes.** Resolution
is one UDP round trip with a 2 second ceiling; a security.txt fetch is a TCP
connect, a TLS handshake and an HTTP exchange. Names that do not resolve never
reach the expensive stages.

**2. Park what cannot change quickly.** A name with no DNS answer is not going
to answer next week, and a name that serves no policy does not publish one by
accident. Parked sets are keyed by a 64-bit hash of the name, sharded 4096 ways,
stored as sorted 12-byte records (hash plus an expiry day). A `.com` parked set
is far too large for memory as a whole, which is why the shards exist: one shard
is about 40k names, so a pass holds a few megabytes, not gigabytes.
Parking is what makes a run resumable: a pass that stops at its time budget keeps
every decision it already made, and the next night starts with those names
skipped.

**3. Do not port-scan before asking for the file.** A failed HTTPS request proves
the port is closed just as well as a connect probe, so the port stage is off by
default (`-port-check` turns it back on). In the benchmark this halved the network
round trips per name.

**4. Tier the TLDs.** `.com`, `.net` and `.app` monthly; `.io`, `.co`, `.org`,
`.dev`, `.tech`, `.shop`, `.site`, `.studio`, `.xyz`, `.cloud`, `.ai` quarterly;
everything else on a slow rotation.

## What was measured (2026-11-21, this host)

| Run | Names | Wall | Rate | Outcome |
|---|---|---|---|---|
| Tranco sample, cold | 20,000 | 300 s | 67/s | 6,030 resolve, 43 policies found |
| Same names, second pass | 20,000 | 36 s | 549/s | 18,103 parked and skipped, 5 new |
| `.tax` zone, cold | 31,811 | 49 s | 651/s | 3,257 resolve, 350 reachable, 0 policies |
| `.tax` zone, second pass | 31,811 | 0.1 s | 314k/s | every name parked |

The second-pass rows are the point: once a zone's decisions are parked, the
monthly pass only touches what changed. A fully parked zone costs nothing.

## What that implies for `.com`

160M names. Cold, at 67 names/s, that is 27 days, which is why the first pass is
expected to be the slow one and is expected to run for several nights with
`-max-minutes`. In steady state roughly 70% of names are parked, so a monthly
pass costs about a third of a cold one, still tens of hours of wall clock,
spread over nightly windows.

Two honest caveats:

- The limit is not CPU. This host sits behind a home connection; at 2000
  concurrent connects the failure rate rose and fewer hosts were reached than at
  200 (6,030 reachable at 400 DNS / 150 HTTP workers versus 2,694 at 2000 / 200).
  The tunables in `bin/monthly_zone_scan.sh` are set to the measured-sane values,
  not the maximum.
- Every request goes to a third party. The rate limits here are deliberately
  conservative for that reason; pushing them higher is not a free win.

## Running it

The sweeps run inside the service, as one thread next to the Tranco crawler, so
there is nothing to schedule and nothing to keep alive on a laptop. On boot the
sweeper takes the next TLD from its queue, downloads the zone, extracts the apex
names, and sweeps for `VDP_ZONE_MINUTES` before yielding. Progress is written
into the same state the API serves, so `/scans` shows the phase, the names
checked and the policies found while it is running.

Settings (environment): `VDP_ZONE_SCAN` (default on), `VDP_ZONE_TLDS` (comma
list, default the approved list in `seed/czds_tlds.txt`), `VDP_ZONE_MINUTES`
(120), `VDP_ZONE_PAUSE` (300). State and zone files live under `/app/data`, so
they survive a redeploy with the rest of the dataset.

The CZDS token expires within hours. `POST /admin/czds-token` installs a fresh
one into `/app/data/czds_token.txt` (mode 600) and wakes the sweeper; until then
`/scans` shows `blocked: czds http 401` and the queue waits instead of retrying.
`/opt/data/private/czds_intake.py` is a one-shot local page that takes the token
in a masked field and posts it to that endpoint.

`bin/monthly_zone_scan.sh` still works as a manual host-side fallback, with its
own state under `/opt/data/vdp-zone-state`.

## The token

The CZDS bearer token comes from a signed-in browser session and expires within
hours. It is installed at `http://<host>:8118/czds-token`, a page served by the
app itself: a listener bound inside the container is not reachable from another
machine, which is what the earlier standalone intake page got wrong. The page
asks ICANN for one byte of a real zone before storing anything, so an expired
token is refused at entry rather than failing mid-sweep. The sweep reads it back
with `GET /admin/czds-token`, and when no token is installed the download fails
loudly and the run skips that TLD rather than scanning nothing.
