# Round-trip a Score through JSON, and parse a FIRST API envelope from
# stdin or a hard-coded fixture.
#
#     crystal run examples/json_io.cr
require "../src/epss"

# 1) Score -> JSON -> Score
original = EPSS::Score.new("CVE-2022-27225", 0.001870, 0.401290, Time.utc(2026, 5, 18))
serialized = original.to_json
puts "serialized: #{serialized}"

restored = EPSS.from_json(serialized).first
puts "restored == original? #{restored == original}"

# 2) FIRST envelope -> Array(Score)
envelope = <<-JSON
  {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 2,
    "offset": 0,
    "limit": 100,
    "data": [
      {"cve": "CVE-2024-3094", "epss": "0.972000000", "percentile": "0.999000000", "date": "2026-05-18"},
      {"cve": "CVE-2021-44228", "epss": "0.974000000", "percentile": "0.999500000", "date": "2026-05-18"}
    ]
  }
  JSON

EPSS.from_json(envelope).sort.reverse!.each do |s|
  puts "#{s.cve} epss=#{s.epss} band=#{s.band}"
end
