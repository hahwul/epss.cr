# Stream all CVEs with an EPSS probability above the given threshold,
# sorted by score descending. Demonstrates Query + Client pagination.
#
#     crystal run examples/filter.cr -- 0.95
require "../src/epss"

threshold = (ARGV.first? || "0.95").to_f64

client = EPSS::Client.new
query = EPSS::Query.new(epss_gt: threshold, order: "!epss")

count = 0
client.each_score(query, page_size: 500) do |score|
  puts "#{score.cve}\t#{score.epss}\t#{score.percentile}"
  count += 1
  break if count >= 100 # cap demo output
end

STDERR.puts "printed #{count} rows above EPSS=#{threshold}"
