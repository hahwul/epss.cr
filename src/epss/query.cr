require "uri"
require "time"

module EPSS
  # A pure value object describing one query to the FIRST EPSS API.
  #
  # All filter fields are optional. The struct is immutable; use `with`
  # methods to derive a new query (`q.with_date(...)`, `q.with_cves(...)`).
  #
  # Encode to a query-string fragment with `#to_params`. The `EPSS::Client`
  # uses this internally and is the usual caller — but the struct is
  # exposed publicly so consumers can build URLs without going through
  # the HTTP client (useful for caching layers and offline tooling).
  struct Query
    # CVE IDs to filter on. Normalized to upper-case at construction so
    # comparisons against `query.cves` are predictable; the FIRST API
    # itself is case-insensitive on CVE ids. The list is joined with `,`
    # at request time.
    getter cves : Array(String)

    # Specific publication date to query historical scores for.
    getter date : Time?

    # Time-series window in days. Mutually exclusive with `scope`.
    getter days : Int32?

    # Lower-bound thresholds (`epss > x` / `percentile > x`).
    getter epss_gt : Float64?
    getter percentile_gt : Float64?

    # Upper-bound thresholds (`epss < x` / `percentile < x`).
    getter epss_lt : Float64?
    getter percentile_lt : Float64?

    # Free-form text query (matches CVE descriptions in the FIRST index).
    getter q : String?

    # Scope: `"time-series"` enables the 30-day series view.
    getter scope : String?

    # Sort order — e.g. `"!epss"` for descending by EPSS, `"epss"` for asc.
    getter order : String?

    # Pagination.
    getter offset : Int32?
    getter limit : Int32?

    # Comma-separated list of fields to return. Maps to FIRST's global
    # `fields` query param — request a projected payload (e.g.
    # `"cve,epss"`) to skip percentile/date when the caller doesn't need
    # them.
    getter fields : Array(String)?

    # Request pretty-printed JSON. Off by default (extra whitespace is
    # wasted bandwidth for programmatic consumers); set when capturing
    # API responses to disk for human review.
    getter pretty : Bool?

    # Force the FIRST envelope wrapper. The EPSS endpoint already wraps
    # responses by default, but `envelope=false` can be requested to
    # receive a bare data array — set this explicitly when you want to
    # override the server's default behavior.
    getter envelope : Bool?

    def initialize(
      @cves : Array(String) = [] of String,
      @date : Time? = nil,
      @days : Int32? = nil,
      @epss_gt : Float64? = nil,
      @percentile_gt : Float64? = nil,
      @epss_lt : Float64? = nil,
      @percentile_lt : Float64? = nil,
      @q : String? = nil,
      @scope : String? = nil,
      @order : String? = nil,
      @offset : Int32? = nil,
      @limit : Int32? = nil,
      @fields : Array(String)? = nil,
      @pretty : Bool? = nil,
      @envelope : Bool? = nil,
    )
      @cves = @cves.map(&.upcase)
      validate!
    end

    # Build a query that filters by a single CVE id. Sugar for the
    # common case where `with_cves([cve])` would otherwise be required.
    #
    # ```
    # EPSS::Query.for_cve("CVE-2022-27225")
    # ```
    def self.for_cve(cve : String) : Query
      new(cves: [cve])
    end

    # Build a query that filters by multiple CVE ids.
    def self.for_cves(cves : Enumerable(String)) : Query
      new(cves: cves.to_a)
    end

    # Highest-EPSS-first query bounded by `n` rows. Use as a starting
    # point for "top-N" dashboards.
    #
    # ```
    # EPSS::Client.new.fetch(EPSS::Query.top(10)).scores
    # ```
    def self.top(n : Int32) : Query
      new(order: "!epss", limit: n)
    end

    # CVEs whose EPSS probability is strictly above `threshold`. Defaults
    # to the 0.95 cutoff commonly used by tier-1 triage policies.
    def self.above(threshold : Float64 = 0.95) : Query
      new(epss_gt: threshold, order: "!epss")
    end

    # CVEs whose EPSS probability is strictly below `threshold`. Pair
    # with `above` for inverse filters.
    def self.below(threshold : Float64) : Query
      new(epss_lt: threshold)
    end

    # Free-text search query, sorted by EPSS descending.
    #
    # ```
    # EPSS::Query.search("openssl")
    # ```
    def self.search(text : String) : Query
      new(q: text, order: "!epss")
    end

    # Restrict results to scores published in the last `days` days.
    # Maps to the FIRST `days` parameter rather than client-side
    # filtering.
    def self.recent(days : Int32) : Query
      new(days: days)
    end

    def with_cves(cves : Array(String) | String) : Query
      list = cves.is_a?(String) ? [cves] : cves
      copy(cves: list)
    end

    # Singular form of `with_cves`. Mirrors `Query.for_cve` for fluent
    # chains where a `Query` already exists.
    def with_cve(cve : String) : Query
      copy(cves: [cve])
    end

    def with_offset(offset : Int32) : Query
      copy(offset: offset)
    end

    def with_limit(limit : Int32) : Query
      copy(limit: limit)
    end

    def with_date(date : Time) : Query
      copy(date: date)
    end

    def with_days(days : Int32) : Query
      copy(days: days)
    end

    def with_epss_gt(value : Float64) : Query
      copy(epss_gt: value)
    end

    def with_epss_lt(value : Float64) : Query
      copy(epss_lt: value)
    end

    def with_percentile_gt(value : Float64) : Query
      copy(percentile_gt: value)
    end

    def with_percentile_lt(value : Float64) : Query
      copy(percentile_lt: value)
    end

    def with_q(value : String) : Query
      copy(q: value)
    end

    def with_scope(value : String) : Query
      copy(scope: value)
    end

    def with_order(value : String) : Query
      copy(order: value)
    end

    def with_fields(value : Array(String) | String) : Query
      list = value.is_a?(String) ? value.split(',').map(&.strip).reject(&.empty?) : value
      copy(fields: list)
    end

    def with_pretty(value : Bool) : Query
      copy(pretty: value)
    end

    def with_envelope(value : Bool) : Query
      copy(envelope: value)
    end

    # Encode this query as an array of `{key, value}` URL parameter pairs,
    # ready to be passed to `URI::Params.encode`. Returns only the fields
    # that are set — never emits a parameter with an empty value.
    def to_params : Array({String, String})
      params = [] of {String, String}
      params << {"cve", @cves.join(',')} unless @cves.empty?
      if d = @date
        params << {"date", d.to_s("%Y-%m-%d")}
      end
      if days = @days
        params << {"days", days.to_s}
      end
      if v = @epss_gt
        params << {"epss-gt", format_float(v)}
      end
      if v = @epss_lt
        params << {"epss-lt", format_float(v)}
      end
      if v = @percentile_gt
        params << {"percentile-gt", format_float(v)}
      end
      if v = @percentile_lt
        params << {"percentile-lt", format_float(v)}
      end
      if v = @q
        params << {"q", v}
      end
      if v = @scope
        params << {"scope", v}
      end
      if v = @order
        params << {"order", v}
      end
      if v = @offset
        params << {"offset", v.to_s}
      end
      if v = @limit
        params << {"limit", v.to_s}
      end
      if f = @fields
        params << {"fields", f.join(',')} unless f.empty?
      end
      params << {"pretty", "true"} if @pretty == true
      unless (e = @envelope).nil?
        params << {"envelope", e ? "true" : "false"}
      end
      params
    end

    # Compose this query into a URL path + query string suitable for the
    # FIRST API endpoint (relative form). The host is supplied by `Client`.
    def to_query_string : String
      pairs = to_params
      return "" if pairs.empty?
      URI::Params.build do |form|
        pairs.each { |(k, v)| form.add(k, v) }
      end
    end

    private def validate! : Nil
      if (v = @epss_gt) && !v.in?(0.0..1.0)
        raise ParseError.new("epss_gt out of range: #{v}")
      end
      if (v = @epss_lt) && !v.in?(0.0..1.0)
        raise ParseError.new("epss_lt out of range: #{v}")
      end
      if (v = @percentile_gt) && !v.in?(0.0..1.0)
        raise ParseError.new("percentile_gt out of range: #{v}")
      end
      if (v = @percentile_lt) && !v.in?(0.0..1.0)
        raise ParseError.new("percentile_lt out of range: #{v}")
      end
      if (v = @offset) && v < 0
        raise ParseError.new("offset must be non-negative")
      end
      if (v = @limit) && v <= 0
        raise ParseError.new("limit must be positive")
      end
      if (v = @days) && v <= 0
        raise ParseError.new("days must be positive")
      end
    end

    # Render a probability as a fixed-point decimal in `[0.0, 1.0]`. Plain
    # `Float#to_s` flips to scientific notation (e.g. `1.0e-7`) for very
    # small values, which the FIRST API rejects as a malformed parameter.
    # Trailing zeros are stripped so `0.5` round-trips as `"0.5"` rather
    # than `"0.500000000"`.
    private def format_float(value : Float64) : String
      return "0" if value.zero?
      s = "%.9f" % value
      if s.includes?('.')
        s = s.rstrip('0')
        s = s.rchop('.') if s.ends_with?('.')
      end
      s
    end

    # Returns a new `Query` with the given fields overridden, falling back to
    # the receiver's current value for any argument left `nil`.
    #
    # KNOWN LIMITATION (by design): for the nilable scalar/collection fields
    # the override uses `arg || @field`, so passing `nil` means "keep the
    # existing value" rather than "clear it". This is exactly what the public
    # `with_*` builders need — they are strictly additive and always pass a
    # concrete value, so a field can never be cleared back to `nil` through
    # this path. There is intentionally no `without_*` API. `pretty` and
    # `envelope` use an explicit `.nil?` check instead because `false` is a
    # meaningful (non-clearing) override for a `Bool?` field. Do not migrate
    # the other fields to the sentinel style without first adding a clearing
    # API and tests, as the additive `with_*` contract depends on this.
    private def copy(
      cves : Array(String)? = nil,
      date : Time? = nil,
      days : Int32? = nil,
      epss_gt : Float64? = nil,
      percentile_gt : Float64? = nil,
      epss_lt : Float64? = nil,
      percentile_lt : Float64? = nil,
      q : String? = nil,
      scope : String? = nil,
      order : String? = nil,
      offset : Int32? = nil,
      limit : Int32? = nil,
      fields : Array(String)? = nil,
      pretty : Bool? = nil,
      envelope : Bool? = nil,
    ) : Query
      Query.new(
        cves: cves || @cves,
        date: date || @date,
        days: days || @days,
        epss_gt: epss_gt || @epss_gt,
        percentile_gt: percentile_gt || @percentile_gt,
        epss_lt: epss_lt || @epss_lt,
        percentile_lt: percentile_lt || @percentile_lt,
        q: q || @q,
        scope: scope || @scope,
        order: order || @order,
        offset: offset || @offset,
        limit: limit || @limit,
        fields: fields || @fields,
        pretty: pretty.nil? ? @pretty : pretty,
        envelope: envelope.nil? ? @envelope : envelope,
      )
    end
  end
end
