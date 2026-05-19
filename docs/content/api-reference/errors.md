+++
title = "Errors"
description = "EPSS::Error and its subclasses"
weight = 7
+++

All errors raised by epss.cr descend from `EPSS::Error`. Catch the base
class to handle any failure without coupling to specific subclasses.

```crystal
class EPSS::Error < Exception; end
class EPSS::ParseError < EPSS::Error; end
class EPSS::APIError   < EPSS::Error
  getter status : Int32?
  getter body   : String?
end
```

## `EPSS::ParseError`

Raised for malformed structural input — a constructor argument out of
range, a JSON payload missing a required field, a CSV row with the
wrong column count, an unparseable date string. The message includes
the offending value when feasible.

Typical sources:

- `EPSS::Score.new` with `epss` outside `[0.0, 1.0]`
- `EPSS::Query.new` with `offset` < 0 or `limit` <= 0
- `EPSS.from_json` with a payload that has neither a `data` envelope nor
  a `cve` key
- `EPSS::CSV.parse` with a header missing one of `cve` / `epss` /
  `percentile`

## `EPSS::APIError`

Raised when the FIRST EPSS API responds with a non-2xx status, or when
the JSON envelope reports `status` != `"OK"`. Carries:

| Field | Description |
| --- | --- |
| `#message` | Human-readable summary |
| `#status` | HTTP status code (`Int32?`) |
| `#body` | Raw response body when available (`String?`) |
| `#cause` | Original transport exception when retries were exhausted on `IO::Error` / `Socket::Error` / `OpenSSL::SSL::Error` |

```crystal
begin
  client.fetch(query)
rescue ex : EPSS::APIError
  log.warn "EPSS API failed: #{ex.status} #{ex.message}"
  log.warn ex.body
  raise unless ex.status.try(&.in?(500..599))  # retry only on 5xx
end
```

## Non-raising variants

For input validation paths where errors are expected, use the
non-raising helpers instead of `rescue`:

```crystal
EPSS.from_json?(payload)   # => Array(Score)? — nil on any error
```

`EPSS.from_json` (and `EPSS::Score.from_row`) still raise on malformed
input — use `from_json?` only when the caller treats malformed input as
"skip this record" rather than "halt".
