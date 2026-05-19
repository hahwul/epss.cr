+++
title = "Band"
description = "EPSS::Band — qualitative classification"
weight = 2
+++

`EPSS::Band` buckets an EPSS measurement into one of five severity-like
labels:

```crystal
enum EPSS::Band
  None
  Low
  Medium
  High
  Critical
end
```

EPSS itself ships only numeric values; the band cutoffs in epss.cr are
operational conventions. Pick whichever set fits the policy you're
enforcing.

## Cutoffs

| Band     | EPSS probability        | Percentile rank |
| -------- | ----------------------- | --------------- |
| None     | `< 0.01`                | `< 0.50`        |
| Low      | `[0.01, 0.10)`          | `[0.50, 0.80)`  |
| Medium   | `[0.10, 0.30)`          | `[0.80, 0.90)`  |
| High     | `[0.30, 0.70)`          | `[0.90, 0.99)`  |
| Critical | `>= 0.70`               | `>= 0.99`       |

## Class methods

### `Band.from_epss(probability : Float64) : Band`

Bucket by the raw EPSS probability.

```crystal
EPSS::Band.from_epss(0.005)  # => EPSS::Band::None
EPSS::Band.from_epss(0.92)   # => EPSS::Band::Critical
```

Out-of-range input (`< 0.0` or `> 1.0`) raises `EPSS::ParseError`.

### `Band.from_percentile(rank : Float64) : Band`

Bucket by the percentile rank.

```crystal
EPSS::Band.from_percentile(0.30)  # => EPSS::Band::None
EPSS::Band.from_percentile(0.95)  # => EPSS::Band::High
```

## Ordering

`Band` is `Comparable` in the natural order:

```crystal
EPSS::Band::Critical > EPSS::Band::High  # => true
EPSS::Band::Low      < EPSS::Band::High  # => true
```

This is useful for threshold filters:

```crystal
scores.select { |s| s.band >= EPSS::Band::High }
```

## Shortcut on Score

`EPSS::Score` exposes both bands directly:

```crystal
score.band             # uses #from_epss
score.percentile_band  # uses #from_percentile
```
