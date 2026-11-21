# Sources and de-duplication

One row per registrable domain. Every row records which sources contributed to it
in `sources`, so a customer can tell a platform listing from a discovery.

| Source | Rows | Cadence | What it adds |
|---|---|---|---|
| HackerOne, Bugcrowd, Intigriti, YesWeHack | 904 programs | daily | In-scope assets, bounty status, platform identity |
| disclose.io `diodb.json` | 2,433 orgs | daily | Self-hosted VDPs and safe-harbor statements |
| disclose.io directory | 28,115 orgs | on demand (`bin/fetch_disclose_directory.py`) | The long tail the diodb feed does not carry |
| RFC 9116 crawl (Tranco) | 6,293 programs | every 15 minutes | security.txt published outside any directory |
| CZDS zone files (Go pipeline) | on demand | as zone files land | Companies with no ranking at all |

## Directory merge rules

The directory is org-level: a name, a policy URL, a contact and a maturity score.
It has no domain column, so attribution is inferred, and inferred attribution has
to be conservative:

1. **Domain comes from a policy or contact URL, never from an email domain.**
   Shared reporting desks (`cvd@z-cert.nl`, `security@aafes.com` for a different
   brand) would otherwise attach dozens of organisations to one company.
2. **A host claimed by three or more distinct organisations is skipped.** In the
   current mirror that drops 991 rows: 142 orgs whose policy lives in a GitHub
   repo, plus shared government and university portals (`gov.au`, `ac.id`,
   `berlin.de`, `admin.ch`, `ca.gov`).
3. **Platform and disclose.io hosts are skipped** (930 rows): a policy URL on
   hackerone.com identifies the platform, not the company.
4. **Bare IPs are skipped**: `https://23.128.160.51/security-policy` is not a
   company domain.
5. Everything else merges into the existing row for that registrable domain, so
   `www.example.com` and `example.com` are one program, not two.

### Two records, one company

The directory is submission-based, so the same organisation can appear twice: a
security.txt discovery on a subdomain, plus a hand-entered stub with no links.
FloQast is the worked example:

| Record | Policy | Contact | Level |
|---|---|---|---|
| `floqast-650148` | `https://api-eu.floqast.app/.well-known/security.txt` | security@floqast.com | L2 |
| `floqast-697488` | none | none | L1 |

`fold_directory()` merges records with the same normalised name when one side has
no domain or both resolve to the same one, so the stub folds into the real record.
`name_anchored_email()` then picks the corporate domain: because the contact is
security@floqast.com and the org name appears in that domain, the row lands on
floqast.com rather than on the security.txt subdomain. Across the current mirror
this folds 49 records and leaves 31 name collisions apart, because same name does
not mean same company (coop.co.uk and coop.no are different retailers).

A row discovered independently by our own crawl is not deleted by this: if a
security.txt really is served on a subdomain, that domain keeps its row and its
history.

Measured on the 2026-11-21 mirror:

| Outcome | Rows |
|---|---|
| Orgs in the directory | 28,115 |
| Mapped to a registrable domain | 26,193 |
| Merged into an existing program | 1,719 |
| New programs created | 24,319 |
| Skipped, no derivable domain | 931 |
| Skipped, shared reporting host | 991 |

## Maturity to safe_harbor

disclose.io scores each org L1 to L5. The ladder maps onto the field the API
already exposes:

| Their level | Meaning | Our `safe_harbor` |
|---|---|---|
| L1 | a contact exists | none |
| L2 | public policy and channel | none |
| L3 | will not pursue legal action | partial |
| L4 | explicit authorisation, law exemptions | full |
| L5 | L4 plus a disclosure timeline | full |

This is their assessment, not ours, and it never downgrades a statement we parsed
from the policy itself. Counts after the merge: 772 full, 1,572 partial.
