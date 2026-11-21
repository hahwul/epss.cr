+++
title = "CSV"
description = "EPSS::CSV — parser for the daily score feed"
weight = 6
+++

`EPSS::CSV` parses the public daily score dump published at
`https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`. The current format is
a single `#`-prefixed metadata line, a header row (`cve,epss,percentile`),
and the score rows.

## Module methods

### `EPSS::CSV.parse(input : String | IO | Path, *, date : Time? = nil) : EPSS::CSV::Feed`

Parse an entire feed file. Gzip-compressed input is auto-detected by
the magic bytes (`1f 8b`).

- `String` input is treated as a file path when one exists, otherwise as
  raw CSV content.
- A leading UTF-8 BOM is stripped.

```crystal
feed = EPSS::CSV.parse(File.read("epss_scores-2026-05-18.csv.gz"))
feed.metadata.model_version  # => "v2025.03.14"
feed.metadata.score_date     # => Time
feed.scores.size             # => 240000+
```

### `EPSS::CSV.each_score(input, *, date : Time? = nil, & : Score ->) : Nil`

Yield each `Score` as it is read from the daily dump. Early feeds with
only `cve,epss` are buffered to compute their percentiles.

```crystal
EPSS::CSV.each_score(File.open("feed.csv.gz")) do |score|
  index[score.cve] = score
end
```

### `EPSS::CSV.fetch(date : Time, *, host : String = FEED_HOST) : Feed`

Download and parse the feed for a specific date. Omit `date` to fetch the
most recently published feed from the stable current-feed URL. Use
`EPSS::CSV.feed_url` with the same arguments to get the URL alone.

## Types

### `EPSS::CSV::Metadata`

Extracted from the leading `#` line:

| Field | Type | Source |
| --- | --- | --- |
| `#model_version` | `String?` | `model_version:vX.Y.Z` |
| `#score_date` | `Time?` | `score_date:<ISO-8601>` |

### `EPSS::CSV::Feed`

Container for one parsed feed file:

| Field | Type |
| --- | --- |
| `#metadata` | `EPSS::CSV::Metadata` |
| `#scores` | `Array(EPSS::Score)` |

`Feed` includes `Enumerable(Score)`, with `#each`, `#size`, and `#[]`
delegated to `scores`.

## Errors

`EPSS::CSV.parse` raises `EPSS::ParseError` when:

- The header is missing `cve` or `epss`, or a header with more than two
  columns omits `percentile`.
- A row is missing a required column.
- A numeric value can't be coerced to `Float64`.
- A row's `date` field is present but doesn't match `%Y-%m-%d`.

If the file lacks a `#` metadata header (feeds before 2022-02-04 have
none), `Feed#metadata` is empty and per-row `Score#date` is the optional
`date:` argument's calendar day, or `nil` when none is given. A file's own
`score_date` or `date` column always wins over `date:`.
`Client#fetch_feed(date)` passes the requested day, so old feeds come back
dated. For two-column feeds from 2021-04-14 through 2021-08-31, each
percentile is the fraction of rows whose score is at or below that score.

## Date handling

The public feed format publishes one `score_date` for the whole file.
Every `Score` in `Feed#scores` is stamped with that date's calendar day
(UTC midnight), matching the API's `date`; `Metadata#score_date` keeps
the full timestamp. The streaming
form (`each_score`) does the same — the metadata seen so far is applied
to each row as it's yielded.
