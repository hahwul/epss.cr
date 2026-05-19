+++
title = "Score"
description = "EPSS::Score — a single daily measurement for one CVE"
weight = 1
+++

`EPSS::Score` is the central value type in epss.cr. It carries a CVE
identifier, the EPSS probability, the percentile rank, and (optionally)
the date the measurement was published.

## Constructor

```crystal
EPSS::Score.new(
  cve: String,
  epss: Float64,
  percentile: Float64,
  date: Time? = nil,
)
```

- `cve` is upper-cased; an empty string raises `EPSS::ParseError`.
- `epss` and `percentile` must be in `[0.0, 1.0]`; NaN/Infinity and
  out-of-range values raise `EPSS::ParseError`.

## Accessors

| Method | Returns |
| --- | --- |
| `#cve` | `String` |
| `#epss` | `Float64` |
| `#percentile` | `Float64` |
| `#date` | `Time?` |
| `#band` | `EPSS::Band` (from EPSS probability) |
| `#percentile_band` | `EPSS::Band` (from percentile rank) |

## Class methods

### `Score.from_row(cve, epss, percentile, date = nil)`

Coercion-friendly constructor for parser code. Accepts `String`,
`Float`, or `Int` for the numeric fields and `String` or `Time` for the
date. Raises `EPSS::ParseError` on any unparseable value.

```crystal
EPSS::Score.from_row(
  cve: "CVE-2022-27225",
  epss: "0.001870000",
  percentile: "0.401290000",
  date: "2026-05-18",
)
```

## Comparable

`Score` includes `Comparable(Score)` and compares by the EPSS
probability:

```crystal
scores.sort.last   # highest probability
scores.min_by(&.epss)  # equivalent
```

## Equality

`==` is **structural** — it requires `cve`, `epss`, `percentile`, **and**
`date` to all match. Two scores from different snapshots of the same CVE
are not equal even though `<=>` returns `0`.

`#hash` follows the same fields, so `Score` is a valid `Set` / `Hash`
key.

## JSON

```crystal
score.to_json
# => {"cve":"CVE-2022-27225","epss":"0.001870000","percentile":"0.401290000","date":"2026-05-18"}
```

Probabilities round-trip at nine decimal places. `EPSS.from_json` decodes
either a bare row or a full FIRST envelope.

See also: [`EPSS::Band`](/api-reference/band/) for the qualitative
classification, [`EPSS::Response`](/api-reference/response/) for the API
envelope wrapper.
