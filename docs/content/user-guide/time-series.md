+++
title = "Time-series"
description = "30-day EPSS history per CVE"
weight = 4
+++

The FIRST EPSS API exposes per-CVE history via the `scope=time-series`
query parameter. epss.cr flattens the nested response into a regular
`Array(Score)` — one entry per day — so the rest of your code doesn't
need a special case.

## Quick history

```crystal
client = EPSS::Client.new
series = client.time_series("CVE-2022-27225")

series.size            # => 31 (today + 30 prior days)
series.first.date.not_nil!.to_s("%Y-%m-%d")  # oldest
series.last.date.not_nil!.to_s("%Y-%m-%d")   # most recent
```

`#time_series` sorts the results oldest-first.

## What the API returns

For `scope=time-series`, FIRST wraps each CVE's history inside the data
row:

```json
{
  "data": [{
    "cve": "CVE-2022-27225",
    "epss": "0.001870000",
    "percentile": "0.401290000",
    "date": "2026-05-18",
    "time-series": [
      {"epss": "0.001870000", "percentile": "0.401770000", "date": "2026-05-17"},
      ...
    ]
  }]
}
```

`EPSS::Response.from_json` automatically:

1. Promotes the parent row's `{cve, epss, percentile, date}` to a `Score`.
2. Expands every entry of `time-series` into its own `Score`, copying the
   parent's `cve`.

So an `EPSS::Response` for a time-series query carries ~30 `Score`s per
queried CVE in its `scores` array.

## Plotting / charting

Because each `Score` is a regular value object with `cve`, `epss`,
`percentile`, and `date`, plotting libraries can ingest the series
directly:

```crystal
points = client.time_series("CVE-2022-27225").map do |s|
  {x: s.date.not_nil!.to_unix, y: s.epss}
end
```

## Time-series + filters

You can combine `scope=time-series` with threshold filters. The
flattening preserves filter behavior because the server pre-filters CVEs
before expanding history.

```crystal
query = EPSS::Query.new(
  cves: ["CVE-2022-27225", "CVE-2021-44228"],
  scope: "time-series",
)
client.fetch(query).scores.size  # ~31 days × 2 CVEs ≈ 62
```

## Pagination

`Client#each_score` advances by the server-reported row count
(`Response#row_count`) rather than the flattened score count, so paging
through time-series queries never skips a CVE.
