# Basic lookup against the FIRST EPSS API.
#
#     crystal run examples/basic.cr -- CVE-2022-27225
require "../src/epss"

cve = ARGV.first? || "CVE-2022-27225"

if score = EPSS.score(cve)
  puts "CVE         : #{score.cve}"
  puts "EPSS        : #{score.epss}"
  puts "Percentile  : #{score.percentile}"
  puts "Date        : #{score.date.try(&.to_s("%Y-%m-%d")) || "n/a"}"
  puts "Band (epss) : #{score.band}"
  puts "Band (pct)  : #{score.percentile_band}"
else
  STDERR.puts "no EPSS score published for #{cve}"
  exit 1
end
