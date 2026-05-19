+++
title = "Client"
description = "EPSS::Client — REST API client for the FIRST EPSS endpoint"
weight = 3
+++

`EPSS::Client` is the typed wrapper around
`https://api.first.org/data/v1/epss`. HTTP is fully delegated to an
injectable `EPSS::Transport`, so tests can swap in a stub without
touching the network.

## Constructor

```crystal
EPSS::Client.new(
  base_uri:      URI = DEFAULT_BASE_URI,
  user_agent:    String = "epss.cr/0.1.0 (+https://github.com/hahwul/epss.cr)",
  max_retries:   Int32 = 3,
  retry_backoff: Time::Span = 500.milliseconds,
  transport:     EPSS::Transport = EPSS::HTTPTransport.new,
)
```

| Argument | Default | Purpose |
| --- | --- | --- |
| `base_uri` | FIRST endpoint | Override for proxies / mirrors |
| `user_agent` | `epss.cr/<VERSION>` | Sent on every request |
| `max_retries` | `3` | 0 disables retries entirely |
| `retry_backoff` | `500ms` | Exponential base; doubled each attempt |
| `transport` | `HTTPTransport` | Swap for tests or caching layers |

## Instance methods

### `#fetch(query : Query = Query.new) : EPSS::Response`

Issue one request. Does not iterate pages — see `#each_score`.

### `#score(cve : String, *, date : Time? = nil) : EPSS::Score?`

Convenience for the single-CVE case. Returns `nil` when FIRST has no
published score.

### `#scores(cves : Enumerable(String), *, date : Time? = nil, batch_size : Int32 = 100) : Array(Score)`

Batch lookup across many CVEs. The list is chunked into requests of
`batch_size` CVEs each.

### `#time_series(cve : String) : Array(Score)`

Fetch the 30-day history for one CVE. Returns the flattened daily series
sorted oldest-first.

### `#each_score(query, *, page_size : Int32 = 1000, & : Score ->) : Nil`

Iterate every score matching `query`, fetching subsequent pages
transparently. The loop advances by the **server-reported** `row_count`
on `EPSS::Response`, so it remains correct when `scope=time-series`
expands each row.

### `#all_scores(query, *, page_size : Int32 = 1000) : Array(Score)`

Convenience around `#each_score` that materializes every page into a
single Array. Be aware that an unfiltered query can be hundreds of
thousands of rows.

### `#build_uri(query : Query) : URI`

Compose the absolute URI for a query. Useful for cache keys and logging.

## Retries

Status codes `429`, `500`, `502`, `503`, `504` are retried up to
`max_retries` times. If the response includes a `Retry-After` header
(seconds or HTTP-date form), the client honors it — capped at 60 seconds
to prevent unbounded waits.

The transport rescue covers `IO::Error` (which includes
`IO::TimeoutError`), `Socket::Error`, and `OpenSSL::SSL::Error`. When
retries are exhausted on a transport failure, the original exception is
chained through `EPSS::APIError#cause`.

Non-retryable status codes raise `EPSS::APIError` immediately with the
status and body attached.

## Transport seam

```crystal
abstract class EPSS::Transport
  abstract def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
end
```

The default `HTTPTransport` opens a fresh `HTTP::Client` per request:

```crystal
EPSS::HTTPTransport.new(
  connect_timeout: 10.seconds,
  read_timeout:    30.seconds,
)
```

For tests, see the `StubTransport` pattern in
[`spec/spec_helper.cr`](https://github.com/hahwul/epss.cr/blob/main/spec/spec_helper.cr).

## Default client

```crystal
EPSS.client          # lazily-constructed default
EPSS.client = ...    # override
EPSS.reset_client    # clear the cache
```

Construction is mutex-protected so two fibers racing the first call
won't build two `Client`s.
