+++
title = "CSV Feed"
description = "Parsing the public daily EPSS score dump"
weight = 3
+++

FIRST publishes a daily CSV at
`https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`.
Call `EPSS::CSV.fetch` to follow the stable current-feed URL to the latest
publication, or pass a date to download a specific day's file.

The file format is a single `#`-prefixed metadata line, a header row, and
the score rows:

```text
#model_version:v2025.03.14,score_date:2026-05-18T00:00:00Z
cve,epss,percentile
CVE-1999-0001,0.0046,0.7385
CVE-1999-0002,0.04525,0.92176
...
```

`EPSS::CSV` parses both the gzipped and uncompressed variants.

## Stream-by-row (recommended for the full feed)

The current feed is ~240k rows. `EPSS::CSV.each_score` streams them
without buffering:

```crystal
require "epss"

File.open("epss_scores-2026-05-18.csv.gz") do |io|
  EPSS::CSV.each_score(io) do |score|
    db.upsert(score.cve, score.epss, score.percentile)
  end
end
```

The gzip magic bytes are auto-detected — pass either the compressed or
the decompressed file. A `String`, an `IO`, or a `Path` all work as
input.

## Load the whole feed

If you want metadata + all rows in memory, use `EPSS::CSV.parse`:

```crystal
feed = EPSS::CSV.parse(File.read("epss_scores-2026-05-18.csv.gz"))
feed.metadata.model_version  # => "v2025.03.14"
feed.metadata.score_date     # => Time
feed.scores.size             # => 240000+
```

`Feed` is `Enumerable(Score)`, so iteration, filtering, and reduction
work directly:

```crystal
feed.select { |s| s.epss > 0.5 }
   .sort.reverse
   .first(20)
   .each { |s| puts s }
```

## Date handling

Every row in `Feed#scores` is stamped with the calendar day (UTC
midnight) of the `score_date` in the file's metadata header — the same
value the API returns as `date` — while `Feed#metadata.score_date` keeps
the full publish timestamp (rows in the feed itself don't carry per-row
dates). Feeds before 2022-02-04 have no `#` header; `fetch_feed(date)`
stamps their rows with the day you asked for. When parsing such a file
yourself, pass the day with `date:` — otherwise `Score#date` is `nil`.
Feeds from 2021-04-14 through 2021-08-31 have two columns (`cve,epss`).
Both parsers read the full two-column file before calculating percentile
ranks. Each rank includes all published scores equal to or below that
row's score, so values with the same published precision share a rank.

```crystal
feed = EPSS::CSV.parse(File.read("epss_scores-2022-02-03.csv.gz"), date: Time.utc(2022, 2, 3))
feed.first.date # => 2022-02-03 00:00:00 UTC
```

## Errors

`EPSS::CSV.parse` raises `EPSS::ParseError` when:

- The header is missing `cve` or `epss`, or a header with more than two
  columns omits `percentile`.
- A row is missing a required column.
- A numeric value can't be coerced to `Float64`.
- A row's `date` field is non-empty but doesn't match `%Y-%m-%d`.

The streaming form (`each_score`) raises the same errors at the point of
the bad row, so a corrupt mid-file row stops iteration.
