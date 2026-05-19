# Download the daily EPSS feed for a given UTC date through the client's
# retry+timeout pipeline, then print the highest-probability CVEs.
#
#     crystal run examples/feed_fetch.cr -- 2026-05-18 10
require "../src/epss"

date_arg = ARGV[0]? || Time.utc.to_s("%Y-%m-%d")
top_n = (ARGV[1]? || "10").to_i

date = Time.parse(date_arg, "%Y-%m-%d", Time::Location::UTC)

feed = EPSS::CSV.fetch(date)
STDERR.puts "model=#{feed.metadata.model_version} score_date=#{feed.metadata.score_date}"
STDERR.puts "loaded #{feed.scores.size} rows"

feed.scores.sort_by!(&.epss).reverse!
feed.scores.first(top_n).each do |score|
  puts "%-20s %-12.6f %-12.6f" % [score.cve, score.epss, score.percentile]
end
