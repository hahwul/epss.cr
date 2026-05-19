+++
title = "JSON & Bands"
description = "JSON round-trip and qualitative classification"
weight = 5
+++

## JSON round-trip

`Score#to_json` emits the same row shape the FIRST API uses:

```json
{
  "cve": "CVE-2022-27225",
  "epss": "0.001870000",
  "percentile": "0.401290000",
  "date": "2026-05-18"
}
```

Probabilities are stringified to nine decimal places — the FIRST API's
own precision — so a serialized payload is byte-identical to one fetched
fresh.

```crystal
score = EPSS.score("CVE-2022-27225").not_nil!
cached = score.to_json    # store
restored = EPSS.from_json(cached).first
restored == score         # => true
```

`EPSS.from_json` accepts either:

- a bare row (`{"cve": ..., "epss": ..., ...}`), or
- a full FIRST envelope (`{"status": "OK", "data": [...]}`).

For an envelope with `scope=time-series`, the nested per-day entries are
flattened into the returned `Array(EPSS::Score)`.

## Bands

`EPSS::Band` is a qualitative bucket — useful for surfacing rows in
dashboards or filtering noise out of long lists. EPSS itself ships only
numeric values; the band cutoffs in epss.cr are conventions chosen to
fit common operational policies.

| Band     | EPSS probability        | Percentile rank |
| -------- | ----------------------- | --------------- |
| None     | `< 0.01`                | `< 0.50`        |
| Low      | `[0.01, 0.10)`          | `[0.50, 0.80)`  |
| Medium   | `[0.10, 0.30)`          | `[0.80, 0.90)`  |
| High     | `[0.30, 0.70)`          | `[0.90, 0.99)`  |
| Critical | `>= 0.70`               | `>= 0.99`       |

Pick whichever set fits the policy you're enforcing:

```crystal
EPSS::Band.from_epss(0.92)       # => EPSS::Band::Critical
EPSS::Band.from_percentile(0.85) # => EPSS::Band::Medium

score.band             # uses the EPSS probability cutoffs
score.percentile_band  # uses the percentile cutoffs
```

`Band` is `Comparable`, so you can threshold against it directly:

```crystal
critical_or_higher = scores.select { |s| s.band >= EPSS::Band::Critical }
```

## Equality, hashing, and ordering

`Score` is structurally equal on every field — cve, epss, percentile,
and date — so two scores from different snapshots of the same CVE are
not equal. The `==` override exists because including `Comparable`
otherwise derives equality from `<=>`, which compares only the EPSS
probability.

```crystal
a = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 18))
b = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 17))
a == b      # => false (different date)
a <=> b     # => 0     (same EPSS probability)
```

`Score` is also a valid `Set` / `Hash` key.

Sorting by EPSS probability is built-in:

```crystal
scores.sort.last   # highest-probability CVE
scores.min         # lowest
```
