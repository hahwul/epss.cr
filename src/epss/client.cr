require "http/client"
require "openssl"
require "socket"
require "uri"
require "./csv"
require "./query"
require "./response"
require "./version"

module EPSS
  # Pluggable transport seam for the EPSS HTTP client. Production code uses
  # `HTTPTransport`; tests can substitute an in-memory implementation to
  # exercise the client without hitting the network.
  abstract class Transport
    abstract def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
  end

  # Default `Transport` that drives a real `HTTP::Client`. Connection
  # parameters are configurable; the transport opens a fresh client for
  # each request, so it's safe to share across fibers.
  class HTTPTransport < Transport
    getter connect_timeout : Time::Span
    getter read_timeout : Time::Span

    def initialize(
      @connect_timeout : Time::Span = 10.seconds,
      @read_timeout : Time::Span = 30.seconds,
    )
    end

    def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
      client = HTTP::Client.new(uri)
      client.connect_timeout = @connect_timeout
      client.read_timeout = @read_timeout
      path = uri.request_target
      client.get(path, headers: headers)
    ensure
      client.try &.close
    end
  end

  # High-level client for the FIRST EPSS REST API
  # (`https://api.first.org/data/v1/epss`).
  #
  # ```
  # client = EPSS::Client.new
  # resp = client.fetch(EPSS::Query.new(cves: ["CVE-2022-27225"]))
  # resp.scores.first.epss # => 0.001870
  # ```
  #
  # Convenience helpers cover the common cases without constructing a
  # `Query`:
  #
  # ```
  # client.score("CVE-2022-27225")       # => EPSS::Score?
  # client.scores(["CVE-1", "CVE-2"])    # => Array(EPSS::Score)
  # client.each_score(query) { |s| ... } # paginated stream
  # ```
  class Client
    DEFAULT_BASE_URI   = URI.parse("https://api.first.org/data/v1/epss")
    DEFAULT_USER_AGENT = "epss.cr/#{EPSS::VERSION} (+https://github.com/hahwul/epss.cr)"

    # Upper bound for a single exponential-backoff sleep. Without a cap the
    # doubling delay grows unbounded and can strand a fiber for minutes; 30s
    # is plenty to let a transient outage clear.
    MAX_BACKOFF = 30.seconds

    # How many redirect hops a single request may follow. The legacy feed
    # host (`epss.cyentia.com`) answers with a 301 to the current host, so a
    # client that refuses to redirect cannot download the feed there at all.
    # One hop is what the real hosts need; the extra headroom covers a
    # future host move without allowing a redirect loop to spin forever.
    MAX_REDIRECTS = 5

    getter base_uri : URI
    getter user_agent : String
    getter max_retries : Int32
    getter retry_backoff : Time::Span
    getter transport : Transport

    def initialize(
      @base_uri : URI = DEFAULT_BASE_URI,
      @user_agent : String = DEFAULT_USER_AGENT,
      @max_retries : Int32 = 3,
      @retry_backoff : Time::Span = 500.milliseconds,
      @transport : Transport = HTTPTransport.new,
    )
      raise ArgumentError.new("max_retries must be non-negative") if @max_retries < 0
    end

    # Issue a single request and return the decoded `Response`. Does not
    # iterate pages — use `#each_score` or `#all_scores` for that.
    #
    # FIRST answers a `date` it has no scores for (before EPSS began, or a
    # day not yet published) with HTTP 422 `"message":["listNoResults"]`
    # instead of an empty page. That one case is returned as an empty
    # `Response` with `total == 0`; every other 422 still raises `APIError`.
    def fetch(query : Query = Query.new) : Response
      http = begin
        perform_get(build_uri(query))
      rescue ex : APIError
        raise ex unless ex.status == 422 && ex.body.try { |b| Response.error_message(b) } == "listNoResults"
        return Response.new(
          status: "OK",
          status_code: 200,
          version: "1.0",
          access: "public",
          total: 0,
          offset: query.offset || 0,
          # 100 is the page size FIRST reports when `limit` is not sent.
          limit: query.limit || 100,
          row_count: 0,
          scores: [] of Score,
        )
      end
      begin
        resp = Response.from_json(http.body)
      rescue ex : ::JSON::ParseException
        # A 200 that is not JSON (captive portal, truncated proxy reply).
        raise ParseError.new("EPSS API returned a non-JSON body: #{ex.message}", cause: ex)
      end
      return resp unless query.envelope == false

      # With `envelope=false` FIRST returns the bare data array and moves the
      # envelope's paging fields into `X-Total` / `X-Offset` / `X-Limit`
      # response headers, so the body alone would report `total == size`.
      Response.new(
        status: resp.status,
        status_code: resp.status_code,
        version: resp.version,
        access: resp.access,
        total: header_int(http.headers, "X-Total") || resp.total,
        offset: header_int(http.headers, "X-Offset") || query.offset || resp.offset,
        limit: header_int(http.headers, "X-Limit") || resp.limit,
        row_count: resp.row_count,
        scores: resp.scores,
      )
    end

    # Return the (at most one) score for a single CVE on the latest day,
    # or `nil` if FIRST has no published score for it.
    def score(cve : String, *, date : Time? = nil) : Score?
      query = Query.new(cves: [cve], date: date)
      fetch(query).scores.first?
    end

    # Fetch the full 30-day EPSS time-series for one CVE. Returns a flat
    # list of `Score`s — one per day, sorted oldest-first.
    #
    # ```
    # series = client.time_series("CVE-2022-27225")
    # series.first.date # => 30 days ago
    # series.last.date  # => today (or most recent publication)
    # ```
    def time_series(cve : String) : Array(Score)
      query = Query.new(cves: [cve], scope: "time-series")
      scores = fetch(query).scores
      scores.sort_by { |s| s.date || Time.unix(0) }
    end

    # Look up multiple CVEs in one call. FIRST caps the `cve` parameter at
    # `Query::MAX_CVE_PARAM` characters, so this helper batches into chunks
    # of at most `batch_size` ids (default 100) that also fit that cap, and
    # concatenates the results.
    def scores(cves : Enumerable(String), *, date : Time? = nil, batch_size : Int32 = 100) : Array(Score)
      raise ArgumentError.new("batch_size must be positive") if batch_size <= 0
      result = [] of Score
      batch = [] of String
      cves.each do |cve|
        id = cve.strip
        # Joined length of `batch` plus `id`: the ids and one comma each.
        joined = batch.sum(&.size) + batch.size + id.size
        if !batch.empty? && (batch.size >= batch_size || joined > Query::MAX_CVE_PARAM)
          result.concat(fetch(Query.new(cves: batch, date: date, limit: batch.size)).scores)
          batch = [] of String
        end
        batch << id
      end
      result.concat(fetch(Query.new(cves: batch, date: date, limit: batch.size)).scores) unless batch.empty?
      result
    end

    # Iterate every score matching `query`, transparently fetching
    # subsequent pages while results remain. Uses the API's `limit` /
    # `offset` parameters; the iteration order matches the server's
    # response order (controlled by `query.order`).
    #
    # `page_size` is the per-request page granularity. A `limit` set on the
    # query is the *total* row budget for the whole iteration — pagination
    # stops once it is exhausted, so `all_scores(Query.top(10))` yields ten
    # rows rather than the entire population.
    def each_score(query : Query = Query.new, *, page_size : Int32 = 1000, & : Score ->) : Nil
      raise ArgumentError.new("page_size must be positive") if page_size <= 0
      offset = query.offset || 0
      remaining = query.limit
      loop do
        size = remaining ? Math.min(page_size, remaining) : page_size
        # Force the envelope: with `envelope=false` FIRST moves `total` /
        # `offset` into response headers, and `fetch` can only recover them
        # when a proxy has not stripped those headers.
        page_query = query.with_offset(offset).with_limit(size).with_envelope(true)
        resp = fetch(page_query)
        resp.scores.each { |score| yield score }
        # Advance by the *server-reported* row count, not the flattened
        # score count — `scope=time-series` inflates each row into ~30
        # daily entries, which would otherwise skip pages.
        break if resp.row_count == 0
        if left = remaining
          left -= resp.row_count
          remaining = left
          break if left <= 0
        end
        break unless resp.more?
        offset += resp.row_count
      end
    end

    # Materialize every result matching `query` into a single Array.
    # Convenience wrapper around `#each_score` — be aware that an
    # unfiltered query can be hundreds of thousands of rows.
    def all_scores(query : Query = Query.new, *, page_size : Int32 = 1000) : Array(Score)
      result = [] of Score
      each_score(query, page_size: page_size) { |score| result << score }
      result
    end

    # Download and parse the daily EPSS feed for `date` using this client's
    # transport, retry policy, User-Agent, and timeouts. The feed is the
    # second canonical EPSS distribution channel; routing it through the
    # same pipeline as the JSON API means a slow network surfaces as
    # `APIError` instead of an unbounded hang.
    #
    # ```
    # feed = client.fetch_feed(Time.utc(2026, 5, 18))
    # feed.scores.size # => 240000+
    # ```
    def fetch_feed(date : Time, *, host : String = CSV::FEED_HOST) : CSV::Feed
      uri = CSV.feed_url(date, host: host)
      # Feeds before 2022-02-04 have no `#model_version` line to date the
      # rows, so fall back to the day that was asked for.
      CSV.parse(IO::Memory.new(perform_get(uri).body), date: date)
    end

    # Compose the absolute URI for a query against this client's base.
    def build_uri(query : Query) : URI
      uri = @base_uri.dup
      qs = query.to_query_string
      uri.query = qs unless qs.empty?
      uri
    end

    # FIRST answers some requests (e.g. a `date` with no published scores,
    # HTTP 422) with an error envelope whose `message` says why.
    private def failure_message(response : HTTP::Client::Response) : String
      detail = Response.error_message(response.body).try { |m| ": #{m}" }
      "EPSS API request failed: HTTP #{response.status_code}#{detail}"
    end

    private def header_int(headers : HTTP::Headers, name : String) : Int32?
      headers[name]?.try(&.strip.to_i32?).try { |v| v >= 0 ? v : nil }
    end

    private def perform_get(uri : URI) : HTTP::Client::Response
      headers = HTTP::Headers{
        "User-Agent" => @user_agent,
        "Accept"     => "application/json",
      }

      attempt = 0
      redirects = 0
      target = uri

      loop do
        attempt += 1
        begin
          response = @transport.get(target, headers)
          case response.status_code
          when 200
            return response
          when 301, 302, 303, 307, 308
            redirects += 1
            if redirects > MAX_REDIRECTS
              raise APIError.new(
                "EPSS API request failed: more than #{MAX_REDIRECTS} redirects",
                status: response.status_code,
              )
            end
            target = redirect_target(target, response)
            # A redirect hop is not a failed attempt — it must not consume
            # the retry budget reserved for transient failures.
            attempt -= 1
          when 429, 500, 502, 503, 504
            if attempt > @max_retries
              raise APIError.new(
                failure_message(response),
                status: response.status_code,
                body: response.body,
              )
            end
            # 429 / 503 may include a `Retry-After` header; honor it
            # instead of our exponential backoff when present.
            if hint = retry_after_delay(response.headers)
              sleep hint
            else
              sleep_backoff(attempt)
            end
          else
            raise APIError.new(
              failure_message(response),
              status: response.status_code,
              body: response.body,
            )
          end
        rescue ex : APIError
          raise ex
        rescue ex : IO::Error | Socket::Error | OpenSSL::SSL::Error
          # IO::TimeoutError descends from IO::Error, so it's covered here.
          if attempt > @max_retries
            raise APIError.new("EPSS API request failed: #{ex.message}", cause: ex)
          end
          sleep_backoff(attempt)
        end
      end
    end

    # Resolve the `Location` of a redirect response against the URI that
    # produced it. Relative targets are supported, and the scheme is
    # restricted to HTTP(S) so a hostile redirect cannot push the transport
    # at, say, a `file://` URI.
    private def redirect_target(from : URI, response : HTTP::Client::Response) : URI
      location = response.headers["Location"]?.presence
      unless location
        raise APIError.new(
          "EPSS API request failed: HTTP #{response.status_code} without a Location header",
          status: response.status_code,
        )
      end

      target = URI.parse(location)
      target = from.resolve(target) unless target.absolute?
      unless target.scheme == "https" || target.scheme == "http"
        raise APIError.new(
          "EPSS API redirected to an unsupported scheme: #{location.inspect}",
          status: response.status_code,
        )
      end
      target
    rescue ex : URI::Error
      raise APIError.new("EPSS API returned an invalid redirect target", cause: ex)
    end

    # Parse a Retry-After response header. Supports both the seconds form
    # (`Retry-After: 30`) and the HTTP-date form (`Retry-After: Wed, 21 Oct
    # 2015 07:28:00 GMT`). Returns nil if absent, unparseable, or negative.
    private def retry_after_delay(headers : HTTP::Headers) : Time::Span?
      raw = headers["Retry-After"]?
      return unless raw
      raw = raw.strip
      if seconds = raw.to_i?
        return if seconds < 0
        # Cap at one minute so a misbehaving server can't strand a fiber.
        capped = seconds.clamp(0, 60)
        return capped.seconds
      end
      begin
        target = HTTP.parse_time(raw)
        return unless target
        delta = target - Time.utc
        return if delta.negative?
        delta < 60.seconds ? delta : 60.seconds
      rescue
        nil
      end
    end

    private def sleep_backoff(attempt : Int32) : Nil
      sleep backoff_delay(attempt)
    end

    # Exponential backoff with a hard cap and decorrelated jitter:
    #   base * 2^(attempt-1), clamped to MAX_BACKOFF, plus up to 10% jitter.
    #
    # The cap keeps a long retry chain from sleeping for minutes, and the
    # jitter spreads concurrent retries so they don't all wake at once. This
    # is library runtime code (not a deterministic workflow script), so a
    # random source is acceptable here.
    #
    # Public so the cap/jitter bounds can be unit-tested without sleeping.
    def backoff_delay(attempt : Int32) : Time::Span
      shift = attempt - 1
      # Guard against `1 << n` overflow for large attempt counts before the
      # cap is even applied.
      factor = shift >= 30 ? (1_i64 << 30) : (1_i64 << shift)
      base = @retry_backoff * factor
      capped = base < MAX_BACKOFF ? base : MAX_BACKOFF
      jitter = capped * (rand * 0.1)
      capped + jitter
    end
  end
end
