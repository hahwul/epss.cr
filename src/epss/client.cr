require "http/client"
require "uri"
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
  # client.score("CVE-2022-27225")     # => EPSS::Score?
  # client.scores(["CVE-1", "CVE-2"])   # => Array(EPSS::Score)
  # client.each_score(query) { |s| ... } # paginated stream
  # ```
  class Client
    DEFAULT_BASE_URI = URI.parse("https://api.first.org/data/v1/epss")
    DEFAULT_USER_AGENT = "epss.cr/#{EPSS::VERSION} (+https://github.com/hahwul/epss.cr)"

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
    def fetch(query : Query = Query.new) : Response
      uri = build_uri(query)
      raw = perform_get(uri)
      Response.from_json(raw)
    end

    # Return the (at most one) score for a single CVE on the latest day,
    # or `nil` if FIRST has no published score for it.
    def score(cve : String, *, date : Time? = nil) : Score?
      query = Query.new(cves: [cve], date: date)
      fetch(query).scores.first?
    end

    # Look up multiple CVEs in one call. The API caps the URL length, so
    # this helper batches into chunks of `batch_size` (default 100) and
    # concatenates the results.
    def scores(cves : Enumerable(String), *, date : Time? = nil, batch_size : Int32 = 100) : Array(Score)
      raise ArgumentError.new("batch_size must be positive") if batch_size <= 0
      result = [] of Score
      cves.each_slice(batch_size) do |slice|
        query = Query.new(cves: slice.to_a, date: date, limit: slice.size)
        resp = fetch(query)
        result.concat(resp.scores)
      end
      result
    end

    # Iterate every score matching `query`, transparently fetching
    # subsequent pages while results remain. Uses the API's `limit` /
    # `offset` parameters; the iteration order matches the server's
    # response order (controlled by `query.order`).
    def each_score(query : Query = Query.new, *, page_size : Int32 = 1000, & : Score ->) : Nil
      raise ArgumentError.new("page_size must be positive") if page_size <= 0
      offset = query.offset || 0
      loop do
        page_query = query.with_offset(offset).with_limit(page_size)
        resp = fetch(page_query)
        resp.scores.each { |score| yield score }
        break unless resp.more?
        break if resp.scores.empty?
        offset += resp.scores.size
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

    # Compose the absolute URI for a query against this client's base.
    def build_uri(query : Query) : URI
      uri = @base_uri.dup
      qs = query.to_query_string
      uri.query = qs unless qs.empty?
      uri
    end

    private def perform_get(uri : URI) : String
      headers = HTTP::Headers{
        "User-Agent" => @user_agent,
        "Accept"     => "application/json",
      }

      attempt = 0
      last_error : Exception? = nil

      loop do
        attempt += 1
        begin
          response = @transport.get(uri, headers)
          case response.status_code
          when 200
            return response.body
          when 429, 500, 502, 503, 504
            if attempt > @max_retries
              raise APIError.new(
                "EPSS API request failed: HTTP #{response.status_code}",
                status: response.status_code,
                body: response.body,
              )
            end
            sleep_backoff(attempt)
          else
            raise APIError.new(
              "EPSS API request failed: HTTP #{response.status_code}",
              status: response.status_code,
              body: response.body,
            )
          end
        rescue ex : APIError
          raise ex
        rescue ex : IO::Error | Socket::Error
          last_error = ex
          if attempt > @max_retries
            raise APIError.new("EPSS API request failed: #{ex.message}")
          end
          sleep_backoff(attempt)
        end
      end
    end

    private def sleep_backoff(attempt : Int32) : Nil
      # Exponential backoff: base * 2^(attempt-1)
      delay = @retry_backoff * (1 << (attempt - 1))
      sleep delay
    end
  end
end
