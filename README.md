# epss.cr

A Crystal implementation of the [Exploit Prediction Scoring System
(EPSS)](https://www.first.org/epss/) from FIRST.

`epss.cr` covers the two ways EPSS is consumed in practice:

- **The FIRST REST API** at `https://api.first.org/data/v1/epss` — lookup
  by CVE, date range, threshold, percentile, with transparent pagination.
- **The daily CSV feed** at `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`
  — streamed row-by-row, gzip auto-detected. The legacy `epss.cyentia.com`
  host still mirrors the same file and can be supplied via `host:`.

It is shaped after [`cvss.cr`](https://github.com/hahwul/cvss.cr): typed
value objects, structural equality, JSON round-trip, and a stable error
hierarchy.

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  epss:
    github: hahwul/epss.cr
```

Run `shards install`.

## Usage

```crystal
require "epss"
```

### Look up one CVE

```crystal
if score = EPSS.score("CVE-2022-27225")
  puts "EPSS=#{score.epss} percentile=#{score.percentile} band=#{score.band}"
end

# Pluck just one field
EPSS.band("CVE-2022-27225")       # => EPSS::Band::Low
EPSS.epss("CVE-2022-27225")       # => 0.00187
EPSS.percentile("CVE-2022-27225") # => 0.40129
```

### One-liner queries

```crystal
EPSS.top(10)                  # 10 highest-EPSS CVEs
EPSS.above(0.95)              # every CVE above the threshold (paginated)
EPSS.search("openssl")        # free-text search, EPSS-desc
EPSS.feed(Time.utc(2026, 5, 18))  # daily CSV feed
EPSS.today_feed               # today's CSV feed
```

Same builders are available on `EPSS::Query` for composition:

```crystal
EPSS::Query.top(50).with_percentile_gt(0.9)
EPSS::Query.search("kernel").with_limit(25)
EPSS::Query.above(0.5).with_order("!epss")
EPSS::Query.for_cve("CVE-2022-27225")
EPSS::Query.recent(7)
```

### Batch lookup

```crystal
EPSS.scores(["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]).each do |s|
  puts s
end
```

### Threshold filter with pagination

```crystal
client = EPSS::Client.new
client.each_score(EPSS::Query.new(epss_gt: 0.95, order: "!epss")) do |score|
  puts "#{score.cve}\t#{score.epss}"
end
```

### Parse the daily CSV feed

```crystal
File.open("epss_scores-2026-05-18.csv.gz") do |io|
  EPSS::CSV.each_score(io) do |score|
    db.upsert(score.cve, score.epss, score.percentile)
  end
end

# Or load it all at once and inspect the file metadata:
feed = EPSS::CSV.parse(File.read("epss_scores-2026-05-18.csv.gz"))
feed.metadata.model_version # => "v2025.03.14"
feed.metadata.score_date    # => Time(2026-05-18)
feed.scores.size            # => 240000+
```

### Download a daily feed by date

```crystal
EPSS::CSV.feed_url(Time.utc(2026, 5, 18))
# => URI("https://epss.empiricalsecurity.com/epss_scores-2026-05-18.csv.gz")

# Routed through the same retry/timeout/User-Agent pipeline as the JSON
# client — slow networks surface as EPSS::APIError rather than hangs.
feed = EPSS::CSV.fetch(Time.utc(2026, 5, 18))
feed.metadata.score_date    # => Time(2026-05-18)
```

### Field projection

Request a partial payload via the FIRST API's `fields` parameter to skip
percentile/date when the caller doesn't need them:

```crystal
query = EPSS::Query.new
  .with_epss_gt(0.95)
  .with_order("!epss")
  .with_fields(["cve", "epss"])
```

`Query` also exposes `with_pretty(true)` and `with_envelope(false)` for
the other FIRST global parameters.

### JSON round-trip

```crystal
# Single Score
score = EPSS::Score.new("CVE-2022-27225", 0.001870, 0.401290, Time.utc(2026, 5, 18))
EPSS::Score.from_json(score.to_json).should eq(score)

# Full API envelope
resp     = client.fetch(EPSS::Query.new(cves: ["CVE-2022-27225"]))
captured = resp.to_json
EPSS::Response.from_json(captured) # round-trips
```

### Bands

`EPSS::Band` provides a qualitative bucket — useful for surfacing rows
in dashboards or filtering noisy low-probability CVEs.

```crystal
EPSS::Band.from_epss(0.92)       # => EPSS::Band::Critical
EPSS::Band.from_percentile(0.85) # => EPSS::Band::Medium
EPSS::Band.parse("critical")     # => EPSS::Band::Critical
score.band                       # uses the EPSS probability cutoffs
score.percentile_band            # uses the percentile cutoffs
score.critical?                  # band predicates: none?/low?/medium?/high?/critical?
score.at_least?(:high)           # threshold check (default :high)
```

### Score helpers

```crystal
score.percentage             # => 42.0  (epss * 100, display-friendly)
score.percentile_percentage  # => 99.0
score.age                    # Time::Span since the score was published
older = EPSS.score("CVE-1", date: Time.utc - 7.days)
score.delta(older)           # change in EPSS probability since last week
```

| Band     | EPSS probability        | Percentile rank |
| -------- | ----------------------- | --------------- |
| None     | `< 0.01`                | `< 0.50`        |
| Low      | `[0.01, 0.10)`          | `[0.50, 0.80)`  |
| Medium   | `[0.10, 0.30)`          | `[0.80, 0.90)`  |
| High     | `[0.30, 0.70)`          | `[0.90, 0.99)`  |
| Critical | `>= 0.70`               | `>= 0.99`       |

The cutoffs are conventions — EPSS itself ships only numeric values.
Pick whichever set fits the policy you're enforcing.

## Configuring the client

```crystal
client = EPSS::Client.new(
  base_uri: URI.parse("https://api.first.org/data/v1/epss"),
  user_agent: "myapp/1.0",
  max_retries: 5,
  retry_backoff: 1.second,
)
```

For tests, inject a custom `EPSS::Transport`:

```crystal
class FakeTransport < EPSS::Transport
  def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
    HTTP::Client::Response.new(200, body: my_fixture)
  end
end

client = EPSS::Client.new(transport: FakeTransport.new)
```

## Error handling

All errors descend from `EPSS::Error`:

- `EPSS::ParseError` — malformed JSON / CSV / constructor argument.
- `EPSS::APIError`   — HTTP non-2xx, or `status != "OK"` in the envelope.
  Carries the response `status` and `body`.

Use `EPSS.from_json?` for the non-raising form.

## Development

```bash
crystal spec      # run the test suite
crystal build src/epss.cr --no-codegen  # type-check
```

The HTTP-touching code is fully driven through an injectable
`EPSS::Transport`; specs use a `StubTransport` (see `spec/spec_helper.cr`)
and never hit the network.

## Contributing

1. Fork it (<https://github.com/hahwul/epss.cr/fork>)
2. Create your feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feat/your-feature`)
5. Create a new Pull Request

## License

MIT. See [LICENSE](./LICENSE).
