require "time"

module EPSS
  # A single EPSS measurement for one CVE on one date.
  #
  # Every field returned by the FIRST API and the daily CSV feed is
  # captured here. Scores are `Comparable` by their EPSS probability so
  # collections can be sorted directly:
  #
  # ```
  # scores.sort.last      # highest-probability CVE
  # scores.max_by(&.epss) # equivalent
  # ```
  #
  # `==` and `#hash` are structural across all fields (cve + date + values),
  # so two `Score` objects from different snapshots of the same CVE are not
  # equal — this is intentional, since EPSS values move daily and dedup by
  # CVE alone would silently merge them.
  struct Score
    include Comparable(Score)

    # The CVE identifier (e.g., "CVE-2022-27225"). Normalized to upper-case.
    getter cve : String

    # Exploit probability for the next 30 days, in `[0.0, 1.0]`.
    getter epss : Float64

    # Percentile rank within the EPSS population, in `[0.0, 1.0]`.
    getter percentile : Float64

    # The date the score was generated. May be `nil` for CSV rows that did
    # not carry per-row dates (the feed publishes one date at the file
    # header — see `CSV.parse`).
    getter date : Time?

    def initialize(@cve : String, @epss : Float64, @percentile : Float64, @date : Time? = nil)
      raise ParseError.new("blank CVE id") if @cve.empty?
      raise ParseError.new("epss out of range: #{@epss}") unless @epss.in?(0.0..1.0)
      raise ParseError.new("percentile out of range: #{@percentile}") unless @percentile.in?(0.0..1.0)
      @cve = @cve.upcase
    end

    # Band derived from the EPSS probability.
    def band : Band
      Band.from_epss(@epss)
    end

    # Band derived from the percentile rank.
    def percentile_band : Band
      Band.from_percentile(@percentile)
    end

    def <=>(other : Score) : Int32?
      @epss <=> other.epss
    end

    # Structural equality on every field. Overrides the `==` that
    # `Comparable` would otherwise derive from `<=>` — we don't want
    # two scores with the same EPSS probability to compare equal when
    # their CVE / date / percentile differ.
    def ==(other : Score) : Bool
      @cve == other.cve &&
        @epss == other.epss &&
        @percentile == other.percentile &&
        @date == other.date
    end

    def hash(hasher)
      hasher = @cve.hash(hasher)
      hasher = @epss.hash(hasher)
      hasher = @percentile.hash(hasher)
      hasher = @date.hash(hasher)
      hasher
    end

    def to_s(io : IO) : Nil
      io << @cve << " epss=" << @epss << " pct=" << @percentile
      if d = @date
        io << " date=" << d.to_s("%Y-%m-%d")
      end
    end

    def to_s : String
      String.build { |io| to_s(io) }
    end

    # Build a Score from a raw API/CSV row hash-like object. Values may be
    # supplied as either strings (the API and CSV both return strings) or
    # already-parsed numerics.
    def self.from_row(cve : String, epss, percentile, date = nil) : Score
      new(
        cve: cve,
        epss: coerce_float(epss, "epss"),
        percentile: coerce_float(percentile, "percentile"),
        date: coerce_date(date),
      )
    end

    private def self.coerce_float(value, field : String) : Float64
      case value
      when Float64 then value
      when Float   then value.to_f64
      when Int     then value.to_f64
      when String
        value.to_f64? || raise ParseError.new("invalid #{field} value '#{value}'")
      when Nil
        raise ParseError.new("missing #{field}")
      else
        raise ParseError.new("invalid #{field} value '#{value}'")
      end
    end

    private def self.coerce_date(value) : Time?
      case value
      when Nil  then nil
      when Time then value
      when String
        stripped = value.strip
        return nil if stripped.empty?
        Time.parse(stripped, "%Y-%m-%d", Time::Location::UTC)
      else
        raise ParseError.new("invalid date value '#{value}'")
      end
    rescue Time::Format::Error
      raise ParseError.new("invalid date value '#{value}'")
    end
  end
end
