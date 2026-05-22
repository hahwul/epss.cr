module EPSS
  # Qualitative band for an EPSS score / percentile.
  #
  # EPSS itself does not standardize severity labels — FIRST publishes only
  # the numeric probability (0.0–1.0) and percentile. The bands below are a
  # conventional five-bucket split used widely in tooling (e.g. CISA-style
  # "high probability" callouts at the 90th+ percentile, low-noise floors
  # below the 50th). They are stable and ordered so consumers can sort or
  # threshold against them without committing to a hard cutoff in code.
  #
  # ```
  # EPSS::Band.from_percentile(0.97) # => EPSS::Band::Critical
  # EPSS::Band.from_epss(0.001)      # => EPSS::Band::None
  # ```
  enum Band
    None
    Low
    Medium
    High
    Critical

    def to_s : String
      case self
      in None     then "None"
      in Low      then "Low"
      in Medium   then "Medium"
      in High     then "High"
      in Critical then "Critical"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end

    # Percentile-based banding. Percentile is a CVE's rank within the EPSS
    # population (0.0 = least likely, 1.0 = most likely to be exploited).
    # Bands follow common operational cutoffs at the 50th / 80th / 90th /
    # 99th percentile.
    def self.from_percentile(percentile : Float64) : Band
      raise ParseError.new("percentile out of range: #{percentile}") unless percentile.in?(0.0..1.0)
      case percentile
      when .< 0.5  then None
      when .< 0.8  then Low
      when .< 0.9  then Medium
      when .< 0.99 then High
      else              Critical
      end
    end

    # Raw-probability banding. The EPSS score is an absolute probability of
    # exploitation in the next 30 days, so the cutoffs are tighter than the
    # percentile bands and skewed low — a 10%+ probability is already
    # operationally significant.
    def self.from_epss(score : Float64) : Band
      raise ParseError.new("epss score out of range: #{score}") unless score.in?(0.0..1.0)
      case score
      when .< 0.01 then None
      when .< 0.10 then Low
      when .< 0.30 then Medium
      when .< 0.70 then High
      else              Critical
      end
    end

    # Parse a case-insensitive band name. Accepts the labels emitted by
    # `#to_s` so user-supplied CLI flags or config values round-trip
    # without manual normalization.
    #
    # ```
    # EPSS::Band.parse("critical") # => EPSS::Band::Critical
    # EPSS::Band.parse?("nope")    # => nil
    # ```
    def self.parse(value : String) : Band
      parse?(value) || raise ParseError.new("unknown band: #{value.inspect}")
    end

    def self.parse?(value : String) : Band?
      case value.strip.downcase
      when "none"     then None
      when "low"      then Low
      when "medium"   then Medium
      when "high"     then High
      when "critical" then Critical
      end
    end

    # `true` when this band is at least as severe as `other`. Crystal's
    # enum already orders these by declaration; this alias makes the
    # intent obvious at call sites (`score.band.at_least?(:high)`).
    def at_least?(other : Band) : Bool
      value >= other.value
    end
  end
end
