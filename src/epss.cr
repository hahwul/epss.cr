# A Crystal implementation of the Exploit Prediction Scoring System (EPSS).
# See: https://www.first.org/epss/
#
# `EPSS` provides:
#   - `EPSS::Score`     — a single CVE's EPSS probability + percentile snapshot
#   - `EPSS::Band`      — qualitative band (None/Low/Medium/High/Critical)
#   - `EPSS::Client`    — HTTP client for the FIRST EPSS REST API
#   - `EPSS::Query`     — typed query builder for the REST API
#   - `EPSS::Response`  — decoded JSON envelope from one API call
#   - `EPSS::CSV`       — parser for the public daily score feed
#
# ```
# # Fetch a single CVE
# EPSS.score("CVE-2022-27225")
#
# # Parse the daily CSV feed (auto-detects gzip)
# EPSS::CSV.parse(File.read("epss_scores-2026-05-18.csv.gz"))
#
# # Stream high-probability CVEs from the API
# EPSS.client.each_score(EPSS::Query.new(epss_gt: 0.95)) do |score|
#   puts score
# end
# ```
require "./epss/version"
require "./epss/error"
require "./epss/band"
require "./epss/score"
require "./epss/csv"
require "./epss/query"
require "./epss/response"
require "./epss/client"
require "./epss/json"

module EPSS
  @@default_client : Client?
  @@default_client_mutex = Mutex.new

  # Lazily-constructed default `Client` used by the module-level convenience
  # helpers. Override via `EPSS.client=` to inject a configured client or a
  # stub during tests. The mutex protects against duplicate construction
  # when multiple fibers race the first call.
  def self.client : Client
    if c = @@default_client
      return c
    end
    @@default_client_mutex.synchronize do
      @@default_client ||= Client.new
    end
  end

  def self.client=(client : Client) : Client
    @@default_client_mutex.synchronize { @@default_client = client }
    client
  end

  # Reset the cached default client. Mainly useful after replacing
  # transport/base URI in tests.
  def self.reset_client : Nil
    @@default_client_mutex.synchronize { @@default_client = nil }
  end

  # Convenience: look up the latest EPSS score for one CVE.
  #
  # ```
  # if s = EPSS.score("CVE-2022-27225")
  #   puts "epss=#{s.epss} percentile=#{s.percentile}"
  # end
  # ```
  def self.score(cve : String, *, date : Time? = nil) : Score?
    client.score(cve, date: date)
  end

  # Convenience: batch lookup for many CVEs in one (or several batched)
  # request(s). Returns the parsed `Score` objects in the order the API
  # returned them.
  def self.scores(cves : Enumerable(String), *, date : Time? = nil) : Array(Score)
    client.scores(cves, date: date)
  end

  # Convenience: just the `EPSS::Band` for one CVE. Returns `nil` when
  # the API has no published score.
  def self.band(cve : String) : Band?
    score(cve).try(&.band)
  end

  # Convenience: just the EPSS probability for one CVE.
  def self.epss(cve : String) : Float64?
    score(cve).try(&.epss)
  end

  # Convenience: just the percentile rank for one CVE.
  def self.percentile(cve : String) : Float64?
    score(cve).try(&.percentile)
  end

  # Top-N highest-EPSS CVEs across the entire population.
  #
  # ```
  # EPSS.top(10).each { |s| puts s }
  # ```
  def self.top(n : Int32) : Array(Score)
    client.fetch(Query.top(n)).scores
  end

  # CVEs whose EPSS probability is strictly above `threshold`. Streams
  # all matching pages through the API and materializes them into an
  # array. Be aware that loose thresholds produce large result sets;
  # use `EPSS.client.each_score(Query.above(...))` directly to stream.
  def self.above(threshold : Float64 = 0.95) : Array(Score)
    client.all_scores(Query.above(threshold))
  end

  # Free-text search ordered by EPSS descending.
  def self.search(text : String, *, limit : Int32 = 100) : Array(Score)
    client.fetch(Query.search(text).with_limit(limit)).scores
  end

  # Download the daily CSV feed for `date`. Equivalent to
  # `EPSS::CSV.fetch(date)`; provided at module scope so callers don't
  # need to remember the submodule path.
  def self.feed(date : Time) : CSV::Feed
    client.fetch_feed(date)
  end

  # Download today's UTC feed. The feed is published once per day; if
  # called before the day's file has been minted the request will
  # surface as `EPSS::APIError` with a 404 status.
  def self.today_feed : CSV::Feed
    feed(Time.utc)
  end
end
