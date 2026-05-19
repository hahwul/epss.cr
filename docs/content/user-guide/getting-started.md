+++
title = "Getting Started"
description = "Install epss.cr and fetch your first EPSS score"
weight = 1
+++

## Prerequisites

| Requirement | Version    |
|-------------|------------|
| Crystal     | >= 1.20.2  |

epss.cr is pure Crystal with no native dependencies — it runs anywhere
Crystal does. The only external services it touches are the public FIRST
EPSS API and the public daily CSV feed.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  epss:
    github: hahwul/epss.cr
```

Then install:

```bash
shards install
```

## Your First Program

Create `hello.cr`:

```crystal
require "epss"

if score = EPSS.score("CVE-2022-27225")
  puts "CVE        : #{score.cve}"
  puts "EPSS       : #{score.epss}"
  puts "Percentile : #{score.percentile}"
  puts "Date       : #{score.date.try(&.to_s("%Y-%m-%d"))}"
  puts "Band       : #{score.band}"
end
```

Run it:

```bash
crystal run hello.cr
```

`EPSS.score(cve)` returns `EPSS::Score?` — `nil` when FIRST has no
published score for the CVE.

## Batch lookup

`EPSS.scores(cves)` batches into chunks of 100 CVEs per request and
returns a flat `Array(EPSS::Score)`:

```crystal
EPSS.scores(["CVE-2024-3094", "CVE-2021-44228", "CVE-2014-0160"]).each do |s|
  puts "#{s.cve}\t#{s.epss}\t#{s.band}"
end
```

## Non-raising parse

For JSON input arriving from another system, use `EPSS.from_json?` to get
`nil` on malformed payloads instead of an exception:

```crystal
if scores = EPSS.from_json?(payload)
  scores.each { |s| store(s) }
else
  log_invalid_payload(payload)
end
```

## Next Steps

- **[API Client](/user-guide/api-client/)** — filters, pagination, retries
- **[CSV Feed](/user-guide/csv-feed/)** — parse the daily score dump
- **[Time-series](/user-guide/time-series/)** — 30-day history per CVE
- **[JSON & Bands](/user-guide/json-and-bands/)** — serialization and qualitative classification
