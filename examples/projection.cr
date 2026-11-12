# Demonstrate the `fields` projection — request only `cve`, `epss` and
# `percentile` from the FIRST API to skip `date`. Useful for large filtered
# queries where bandwidth matters. A `Score` needs all three fields, so a
# projection without one of them raises `EPSS::ParseError`.
#
#     crystal run examples/projection.cr -- 0.95
require "../src/epss"

threshold = (ARGV.first? || "0.95").to_f64

query = EPSS::Query.new
  .with_epss_gt(threshold)
  .with_order("!epss")
  .with_fields(["cve", "epss", "percentile"])
  .with_limit(50)

EPSS::Client.new.each_score(query) do |score|
  puts "#{score.cve}\t#{score.epss}"
end
