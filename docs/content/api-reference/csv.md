+++
title = "CSV"
description = "EPSS::CSV — parser for the daily score feed"
weight = 6
+++

`EPSS::CSV` parses the public daily score dump published at
`https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz`. The format is
a single `#`-prefixed metadata line, a header row (`cve,epss,percentile`),
and the score rows.

## Module methods

### `EPSS::CSV.parse(input : String | IO | Path) : EPSS::CSV::Feed`

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

### `EPSS::CSV.each_score(input, & : Score ->) : Nil`

Yield each `Score` without buffering the whole feed. Use this when
processing the full ~240k-row daily dump.

```crystal
EPSS::CSV.each_score(File.open("feed.csv.gz")) do |score|
  index[score.cve] = score
end
```

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

- The header row is missing `cve`, `epss`, or `percentile`.
- A row has fewer columns than the declared header width.
- A numeric value can't be coerced to `Float64`.
- A row's `date` field is present but doesn't match `%Y-%m-%d`.

If the file lacks a `#` metadata header, `Feed#metadata` is empty and
per-row `Score#date` is `nil` (unless the file carries its own `date`
column, which the public feed does not).

## Date handling

The public feed format publishes one `score_date` for the whole file.
Every `Score` in `Feed#scores` is stamped with that date. The streaming
form (`each_score`) does the same — the metadata seen so far is applied
to each row as it's yielded.
