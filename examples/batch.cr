# Batch lookup, sorted by EPSS probability descending.
#
#     crystal run examples/batch.cr -- CVE-2024-3094 CVE-2021-44228 CVE-2014-0160
require "../src/epss"

cves = ARGV.empty? ? %w[CVE-2024-3094 CVE-2021-44228 CVE-2014-0160] : ARGV.to_a

scores = EPSS.scores(cves).sort.reverse!
puts "%-20s %-12s %-12s %-10s" % ["CVE", "EPSS", "Percentile", "Band"]
scores.each do |s|
  puts "%-20s %-12.6f %-12.6f %-10s" % [s.cve, s.epss, s.percentile, s.band]
end
