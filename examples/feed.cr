# Parse the daily EPSS CSV feed and print the top-N highest-probability
# CVEs. Accepts either a local file (auto-detects gzip) or stdin.
#
#     curl -sL https://epss.cyentia.com/epss_scores-current.csv.gz \
#       | crystal run examples/feed.cr -- 20
require "../src/epss"

top_n = (ARGV.first? || "10").to_i
input = ARGV[1]?

io : IO = if input
            File.open(input)
          else
            STDIN
          end

top = [] of EPSS::Score
EPSS::CSV.each_score(io) do |score|
  if top.size < top_n
    top << score
  elsif score.epss > top.last.epss
    top[-1] = score
  end
  top.sort! { |a, b| b.epss <=> a.epss }
end

top.each do |score|
  puts "%-20s %-12.6f %-12.6f" % [score.cve, score.epss, score.percentile]
end
