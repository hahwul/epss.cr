require "json"
require "./score"
require "./response"

# JSON serialization for `EPSS::Score` and the FIRST API envelope.
#
# A `Score` round-trips through the same row shape the FIRST EPSS API
# returns:
#
# ```json
# {
#   "cve": "CVE-2022-27225",
#   "epss": "0.001870000",
#   "percentile": "0.401290000",
#   "date": "2026-05-18"
# }
# ```
#
# Numeric fields are emitted as strings (matching the upstream API), so a
# `Score#to_json` payload can be replayed against any consumer that
# already parses the FIRST format. `EPSS.from_json` accepts both bare-row
# JSON and full-envelope JSON so a serialized stream from either source
# is consumable.
module EPSS
  struct Score
    def to_json(json : ::JSON::Builder) : Nil
      json.object do
        json.field "cve", @cve
        json_fields(json)
      end
    end

    # :nodoc:
    # The row fields other than `cve`: the shape of a FIRST `time-series`
    # entry, which inherits its CVE from the parent row.
    def json_fields(json : ::JSON::Builder) : Nil
      json.field "epss", format_probability(@epss)
      json.field "percentile", format_probability(@percentile)
      if d = @date
        json.field "date", d.to_s("%Y-%m-%d")
      end
    end

    # Parse a single bare-row JSON object (`{"cve": ..., "epss": ...}`)
    # into one `Score`. For full envelope payloads use `Response.from_json`.
    def self.from_json(input : String | IO) : Score
      scores = EPSS.from_json(input)
      raise ParseError.new("expected one score, got #{scores.size}") if scores.size != 1
      scores.first
    end

    def self.from_json?(input : String | IO) : Score?
      from_json(input)
    rescue Error | ::JSON::ParseException
      nil
    end

    # EPSS publishes probabilities to nine decimal places. Use the same
    # precision so a round-trip through JSON is byte-identical for any
    # value originally sourced from FIRST.
    private def format_probability(value : Float64) : String
      "%.9f" % value
    end
  end

  struct Response
    # Serialize this response back into the FIRST EPSS envelope shape.
    # Symmetric with `Response.from_json` — capture an API payload,
    # write it to disk for fixture use, then replay it through the same
    # parser and get the same scores, paging fields and `row_count`.
    #
    # A `scope=time-series` response is written back nested: each row's
    # flattened daily entries go into its `time-series` array again, so
    # `data.size` is `row_count` (which drives `more?`).
    def to_json(json : ::JSON::Builder) : Nil
      json.object do
        json.field "status", @status
        json.field "status-code", @status_code
        json.field "version", @version
        json.field "access", @access
        json.field "total", @total
        json.field "offset", @offset
        json.field "limit", @limit
        json.field "data" do
          json.array do
            data_rows.each do |row|
              json.object do
                json.field "cve", row[0].cve
                row[0].json_fields(json)
                if row.size > 1
                  json.field "time-series" do
                    json.array { row[1..].each { |s| json.object { s.json_fields(json) } } }
                  end
                end
              end
            end
          end
        end
      end
    end

    # The flattened `scores` regrouped into the API's `data` rows. Flattening
    # puts a row's time-series entries right after it under the same CVE,
    # and FIRST lists each CVE once per page, so runs of one CVE are rows.
    # When that does not add up to `row_count` (a hand-built response),
    # every score is its own row.
    private def data_rows : Array(Array(Score))
      rows = @scores.chunk_while { |a, b| a.cve == b.cve }.to_a
      rows.size == @row_count ? rows : @scores.map { |s| [s] }
    end
  end

  # Parse a bare row (`{"cve": ..., "epss": ..., "percentile": ...}`), a bare
  # row array (what `envelope=false` returns), or a full API envelope
  # (`{"status": "OK", "data": [...]}`). Returns an `Array(Score)` in every
  # case.
  def self.from_json(input : String | IO) : Array(Score)
    # Parse exactly once and dispatch on the decoded document: an `IO` is
    # drained by the first pass, so re-reading it downstream would fail with
    # a raw `JSON::ParseException` on an empty stream.
    json = ::JSON.parse(input)
    body = input.is_a?(String) ? input : nil

    return Response.from_json(json, body: body).scores if json.as_a?

    obj = json.as_h? || raise ParseError.new("expected JSON object")

    if obj.has_key?("data")
      Response.from_json(json, body: body).scores
    elsif obj.has_key?("cve")
      [score_from_object(obj)]
    else
      raise ParseError.new("JSON has neither a 'data' envelope nor a 'cve' key")
    end
  end

  # Parse a non-raising form. Returns `nil` for any malformed input.
  def self.from_json?(input : String | IO) : Array(Score)?
    from_json(input)
  rescue Error | ::JSON::ParseException
    nil
  end

  private def self.score_from_object(obj : Hash(String, ::JSON::Any)) : Score
    cve = obj["cve"]?.try(&.as_s?) || raise ParseError.new("missing cve")
    Score.from_row(
      cve: cve,
      epss: obj["epss"]?.try(&.raw) || raise(ParseError.new("missing epss")),
      percentile: obj["percentile"]?.try(&.raw) || raise(ParseError.new("missing percentile")),
      date: obj["date"]?.try(&.raw),
    )
  end
end
