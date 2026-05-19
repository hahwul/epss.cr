+++
title = "API Client"
description = "Filters, pagination, retries, and custom transports"
weight = 2
+++

The FIRST EPSS REST API lives at
`https://api.first.org/data/v1/epss`. `EPSS::Client` is the typed wrapper.

## Single CVE

```crystal
client = EPSS::Client.new
score = client.score("CVE-2022-27225")
```

## Multiple CVEs

`#scores` chunks the request list (default 100 per batch) so the URL stays
under typical server limits:

```crystal
cves = csv_file.each_line.map(&.strip).to_a
all_scores = client.scores(cves, batch_size: 100)
```

## Threshold filtering with `EPSS::Query`

```crystal
query = EPSS::Query.new(
  epss_gt:        0.95,
  percentile_gt:  0.99,
  order:          "!epss",  # sort by EPSS descending
)
client.each_score(query, page_size: 1000) do |score|
  publish(score)
end
```

`each_score` follows the server's `offset` / `total` cursor automatically.
It uses the server-reported row count (not the flattened score count) to
advance, so it stays correct even with `scope=time-series`.

## Historical lookup

`Query#date` queries a specific publication day (April 14, 2021 onwards):

```crystal
yesterday = Time.utc - 1.day
EPSS.scores(["CVE-2022-27225"], date: yesterday)
```

## Retries

By default `Client` retries up to 3 times on `429`, `500`, `502`, `503`,
and `504` responses with exponential backoff (500 ms × 2ⁿ). It also
retries the underlying transport on `IO::Error`, `Socket::Error`, and
`OpenSSL::SSL::Error`.

If the response includes a `Retry-After` header (in seconds or HTTP-date
form), the client honors it instead — capped at 60 seconds to avoid
stranding a fiber on a misbehaving server.

```crystal
EPSS::Client.new(
  max_retries: 5,
  retry_backoff: 1.second,
)
```

Non-retryable status codes (4xx other than 429) raise `EPSS::APIError`
immediately, with the original status and body attached:

```crystal
begin
  client.fetch
rescue ex : EPSS::APIError
  puts ex.status  # => 403
  puts ex.body
end
```

## Custom transports

For tests, audits, or offline tooling, swap in a custom
`EPSS::Transport`:

```crystal
class CacheTransport < EPSS::Transport
  def initialize(@cache : Hash(String, HTTP::Client::Response))
  end

  def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
    @cache[uri.to_s]? || HTTP::Client::Response.new(404)
  end
end

client = EPSS::Client.new(transport: CacheTransport.new(load_fixtures))
```

The specs in this repo drive every HTTP path through a `StubTransport`
defined in `spec/spec_helper.cr` — no test reaches the network.

## Configuring the default client

`EPSS.score`, `EPSS.scores`, and friends use a lazily-constructed default
`EPSS::Client`. Replace it for the whole process:

```crystal
EPSS.client = EPSS::Client.new(user_agent: "myapp/1.0")
```

`EPSS.reset_client` clears the cached default — useful between tests that
need a fresh stub transport.
