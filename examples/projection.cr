# Demonstrate the `fields` projection — request only `cve` and `epss`
# from the FIRST API to skip percentile/date when the caller doesn't
# need them. Useful for large filtered queries where bandwidth matters.
#
#     crystal run examples/projection.cr -- 0.95
require "../src/epss"

threshold = (ARGV.first? || "0.95").to_f64

query = EPSS::Query.new
  .with_epss_gt(threshold)
  .with_order("!epss")
  .with_fields(["cve", "epss"])
  .with_limit(50)

EPSS::Client.new.each_score(query) do |score|
  puts "#{score.cve}\t#{score.epss}"
end
