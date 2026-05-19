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
end
