+++
title = "epss.cr"
description = "A Crystal implementation of the Exploit Prediction Scoring System (EPSS)"
+++

A Crystal library for the [Exploit Prediction Scoring System
(EPSS)](https://www.first.org/epss/) published by FIRST.

`epss.cr` covers the two surfaces EPSS is consumed through in practice:

| Surface | Source | Module |
| --- | --- | --- |
| REST API | `https://api.first.org/data/v1/epss` | `EPSS::Client` |
| Daily CSV feed | `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` | `EPSS::CSV` |

## Quick Links

- **[Getting Started](/user-guide/getting-started/)** — installation and first call
- **[API Client](/user-guide/api-client/)** — REST API, filters, retries, pagination
- **[CSV Feed](/user-guide/csv-feed/)** — daily-feed parser with gzip auto-detect
- **[Time-series](/user-guide/time-series/)** — 30-day history per CVE
- **[JSON & Bands](/user-guide/json-and-bands/)** — round-trip and qualitative classification
- **[API Reference](/api-reference/score/)** — all types and methods

## Highlights

- Auto-detecting top-level helpers: `EPSS.score(cve)`, `EPSS.scores(cves)`.
- Strict spec-conformant parsing: handles the FIRST API envelope, time-series
  expansion, and the `#`-prefixed daily-feed metadata header.
- `Comparable(Score)` — sort and threshold by EPSS probability.
- Structural equality + `hash` — Scores work as `Set` / `Hash` keys
  (CVE + date + values).
- JSON round-trip in the FIRST API row shape.
- `EPSS::Band` qualitative bucket (None/Low/Medium/High/Critical) for both
  raw probability and percentile rank.
- Retry-After-aware retries with exponential backoff and SSL/IO/timeout
  rescue.
- Pluggable `EPSS::Transport` for offline / test-stubbed clients.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  epss:
    github: hahwul/epss.cr
```

Then run:

```bash
shards install
```

## Quick Example

```crystal
require "epss"

if score = EPSS.score("CVE-2022-27225")
  puts "EPSS=#{score.epss}"
  puts "Percentile=#{score.percentile}"
  puts "Band=#{score.band}"
end
```
