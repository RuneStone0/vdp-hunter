# CZDS zone-file pipeline

The Tranco crawl finds security.txt on domains that are already popular. Zone files
find the rest: every registered name under a gTLD, including the companies that
never appear in a ranking because nobody links to them.

This is the paid dataset. Platform program lists stay free.

## Why zone files

A gTLD zone file is the authoritative list of what exists. There is no sampling and
no popularity threshold, so a 40-person company in a niche industry is in it, and
that company is exactly the target that no aggregator lists.

Measured yield on the Tranco sample, for calibration against zone-file data:

| Sample | Domains | Hits | Hits per 1k |
|---|---|---|---|
| Tranco ranks 1-4,000 | 150 | 42 | 214 |
| Tranco ranks 4,000-4,400 | 400 | 53 | 106 |

Expect zone-file names to land far below this. They are unranked, often parked, and
the value is in the tail, not the rate.

## Pipeline

```
CZDS  ->  czds (download)  ->  zonex (apex names)  ->  probe (security.txt)  ->  hits.jsonl
                                                                                  |
                                                      merge (bin/build_dataset.py)
                                                                     |
                                                          source = "czds" rows
```

`source` is written into every row, so the merge keeps CZDS discoveries distinct from
the Tranco crawl and the API can gate on them.

## Running it

Credentials are an ICANN account that has already been approved for the TLDs on
https://czds.icann.org. The tool downloads what the account is entitled to; it does
not request access on your behalf. Nothing is accepted or agreed to automatically.

```bash
export CZDS_USER=you@example.com CZDS_PASS='...'

# 1. download
./bin/go/czds -tlds io,ai,dev,app,co -out zones

# 2. apex names, one per line
./bin/go/zonex -in zones/io.zone.gz -tld io -out data/domains-io.txt

# 3. probe, resumable, JSONL hits only
./bin/go/probe -in data/domains-io.txt -out data/hits-czds.jsonl     -workers 200 -source czds -rate 0

# 4. merge into the dataset
VDP_DATA=data python3 bin/build_dataset.py
```

`probe` appends and skips domains already in the output file, so a killed run resumes
where it stopped.

## Measured throughput

On a container with a normal residential-grade uplink:

| Stage | Measured |
|---|---|
| zonex parse | 1,000,000 names from a 90 MB master file in 1.2 s (~830k names/s) |
| probe, 60 workers | 150 domains in 21 s (~7/s, one retry pass) |
| probe, 200 workers | 400 domains in 74 s (~5/s, 24% transport errors) |

Throughput is latency-bound, not CPU-bound: a 12 s timeout on a dead host holds a
worker for 12 s. Two consequences worth planning around:

- **Shard by TLD, not by one giant queue.** A .com-sized zone is 100M+ names; at
  ~15 domains/s per node that is months. Start with the corporate-heavy gTLDs where
  the whole zone is a few hundred thousand names.
- **Do not cut the timeout to go faster.** A 3 s timeout on a slow host is a false
  negative, and false negatives are the one thing this dataset cannot afford.

## Rules the prober follows

- One request per path, two paths (`/.well-known/security.txt`, then `/security.txt`
  only after a 404), documented user agent.
- Transport failures are not absence: they are collected and retried once at a
  quarter of the concurrency. This recovered ~35% of hits in the Python crawler.
- A 200 that parses to no `Contact:` is not a hit.
- `tls_verified` is recorded per row; the unverified and plain-HTTP attempts only
  happen after the verified attempt fails outright.
