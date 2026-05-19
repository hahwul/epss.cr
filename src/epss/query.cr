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
    )
      @cves = @cves.map(&.upcase)
      validate!
    end

    def with_cves(cves : Array(String) | String) : Query
      list = cves.is_a?(String) ? [cves] : cves
      copy(cves: list)
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
      params << {"epss-gt", format_float(@epss_gt.not_nil!)} unless @epss_gt.nil?
      params << {"epss-lt", format_float(@epss_lt.not_nil!)} unless @epss_lt.nil?
      params << {"percentile-gt", format_float(@percentile_gt.not_nil!)} unless @percentile_gt.nil?
      params << {"percentile-lt", format_float(@percentile_lt.not_nil!)} unless @percentile_lt.nil?
      params << {"q", @q.not_nil!} unless @q.nil?
      params << {"scope", @scope.not_nil!} unless @scope.nil?
      params << {"order", @order.not_nil!} unless @order.nil?
      params << {"offset", @offset.not_nil!.to_s} unless @offset.nil?
      params << {"limit", @limit.not_nil!.to_s} unless @limit.nil?
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
    end

    private def format_float(value : Float64) : String
      value.to_s
    end

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
      )
    end
  end
end
