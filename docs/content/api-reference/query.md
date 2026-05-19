+++
title = "Query"
description = "EPSS::Query — typed query builder for the FIRST API"
weight = 4
+++

`EPSS::Query` is an immutable value object that captures every supported
parameter of the FIRST EPSS REST API. The HTTP client uses it
internally; you can also use it directly to build URLs without going
through the client.

## Constructor

```crystal
EPSS::Query.new(
  cves:           Array(String) = [] of String,
  date:           Time? = nil,
  days:           Int32? = nil,
  epss_gt:        Float64? = nil,
  percentile_gt:  Float64? = nil,
  epss_lt:        Float64? = nil,
  percentile_lt:  Float64? = nil,
  q:              String? = nil,
  scope:          String? = nil,
  order:          String? = nil,
  offset:         Int32? = nil,
  limit:          Int32? = nil,
)
```

CVE ids are normalized to upper-case at construction.

## Validation

`new` raises `EPSS::ParseError` if:

- any threshold (`epss_gt`, `epss_lt`, `percentile_gt`, `percentile_lt`)
  is outside `[0.0, 1.0]`;
- `offset` is negative;
- `limit` is non-positive.

## Encoding

### `#to_params : Array({String, String})`

Returns the (key, value) pairs that should appear in the URL query
string, in stable order, with unset fields omitted.

### `#to_query_string : String`

Returns the URL-encoded query string ready to attach to a URI. Built
through `URI::Params.build`, so values are properly encoded (commas in a
CVE list become `%2C`, which the FIRST API accepts).

## Immutable derivation

The `with_*` helpers return new instances and never mutate the original:

```crystal
base = EPSS::Query.new(cves: ["CVE-2022-27225"])
page = base.with_offset(100).with_limit(50)
```

| Helper | Returns |
| --- | --- |
| `#with_cves(Array(String) \| String)` | new `Query` with `cves` replaced |
| `#with_date(Time)` | new `Query` with `date` set |
| `#with_offset(Int32)` | new `Query` with `offset` set |
| `#with_limit(Int32)` | new `Query` with `limit` set |

## Examples

```crystal
# Top-100 highest EPSS today.
EPSS::Query.new(order: "!epss", limit: 100)

# All CVEs above the 99th percentile, ordered by EPSS.
EPSS::Query.new(percentile_gt: 0.99, order: "!epss")

# Time-series history for one CVE.
EPSS::Query.new(cves: ["CVE-2022-27225"], scope: "time-series")
```

See also the [API Client guide](/user-guide/api-client/) for end-to-end
examples.
