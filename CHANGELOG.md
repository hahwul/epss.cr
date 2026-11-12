# Changelog

## Unreleased

### Breaking

- `Client#fetch` (and so `#score`, `#scores`, `#each_score`,
  `#all_scores`) no longer raises `APIError` for FIRST's HTTP 422
  `listNoResults`, the answer for a `date` with no published scores. It
  returns an empty `Response` with `total == 0`, and `#score` returns
  `nil` as documented. Other 422s still raise.

### Changed

- `CSV.parse` / `CSV.each_score` take an optional `date:` fallback that
  is stamped onto rows when the feed has no `score_date` (feeds before
  2022-02-04 have no `#` metadata line). `Client#fetch_feed(date)` passes
  the requested day, so old feeds no longer yield `date = nil`.
- `Response#to_json` writes time-series pages nested the way the API
  does, so `Response.from_json(resp.to_json)` keeps `row_count` and
  `more?`, not just the scores.

## v0.2.0

- Expose the FIRST API global parameters `fields`, `pretty`, and
  `envelope` on `EPSS::Query`.
- `Query#format_float` now emits decimal notation for very small
  thresholds (previously fell into scientific notation, which the
  upstream API rejected).
- Round out `Query#with_*` builders to cover every parameter.
- Add `EPSS::CSV.feed_url(date)` and `EPSS::CSV.fetch(date)` to construct
  and download the daily feed by date; switch the canonical feed host
  to `epss.empiricalsecurity.com` and accept the legacy
  `epss.cyentia.com` host via the `host:` override.
- Add `EPSS::Client#fetch_feed(date)` so daily-feed downloads share the
  client's retry, timeout, transport, and User-Agent configuration.
  `EPSS::CSV.fetch` now delegates here, which also makes it stubable
  through `EPSS::Transport`.
- Add `EPSS::Response#to_json` so envelope payloads round-trip through
  the same parser, and `EPSS::Score.from_json` / `from_json?` for the
  single-row case.
- Convenience surface for common spec usage:
  - `Score#none?` / `low?` / `medium?` / `high?` / `critical?` predicates,
    `Score#at_least?(:high)`, `Score#percentage`,
    `Score#percentile_percentage`, `Score#age`, `Score#delta`.
  - `Query.for_cve`, `Query.top`, `Query.above`, `Query.below`,
    `Query.search`, `Query.recent` class-method factories; singular
    `Query#with_cve`.
  - Module shortcuts: `EPSS.top(n)`, `EPSS.above(t)`, `EPSS.search(q)`,
    `EPSS.band(cve)`, `EPSS.epss(cve)`, `EPSS.percentile(cve)`,
    `EPSS.feed(date)`, `EPSS.today_feed`.
  - `Band.parse` / `Band.parse?` (case-insensitive label round-trip)
    and `Band#at_least?`.

## v0.1.0

- First release. Includes the EPSS REST API client, daily CSV feed parser
  (gzip auto-detect), `Score` and `Band` value types, time-series
  flattening, JSON round-trip, and Retry-After-aware retries.
