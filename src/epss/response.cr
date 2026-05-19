require "json"
require "./score"

module EPSS
  # Decoded envelope from a single FIRST EPSS API call.
  #
  # ```
  # resp = client.fetch(Query.new(cves: ["CVE-2022-27225"]))
  # resp.total     # => 1
  # resp.scores[0] # => EPSS::Score
  # ```
  #
  # `Response` is also `Enumerable(Score)`, so it can be iterated and
  # filtered directly without first reading `#scores`.
  struct Response
    include Enumerable(Score)

    getter status : String
    getter status_code : Int32
    getter version : String
    getter access : String
    getter total : Int32
    getter offset : Int32
    getter limit : Int32
    getter scores : Array(Score)
    # Number of rows the server returned in `data` *before* any
    # time-series flattening. This is what advances pagination — the
    # flattened `scores` array can be much larger than `data.size` when
    # `scope=time-series` expands each row into ~30 daily entries.
    getter row_count : Int32

    def initialize(
      @status : String,
      @status_code : Int32,
      @version : String,
      @access : String,
      @total : Int32,
      @offset : Int32,
      @limit : Int32,
      @scores : Array(Score),
      @row_count : Int32 = @scores.size,
    )
    end

    delegate :each, :size, :[], to: @scores

    # Whether the API reported the request as successful. Mirrors the
    # FIRST envelope's `status: "OK"` convention.
    def ok? : Bool
      @status == "OK" && @status_code == 200
    end

    # Whether more pages exist beyond this response. Compares the
    # server-reported `offset + row_count` against `total`, so this stays
    # correct even when time-series flattening inflates `scores`.
    def more? : Bool
      @offset + @row_count < @total
    end

    # Decode a FIRST EPSS API JSON payload. Raises `EPSS::APIError` if the
    # envelope reports an error, or `EPSS::ParseError` if the JSON is
    # missing required fields.
    def self.from_json(input : String | IO) : Response
      json = ::JSON.parse(input)
      obj = json.as_h? || raise ParseError.new("expected JSON object at top level")

      status = string(obj, "status")
      status_code = int(obj, "status-code")

      if status != "OK" || status_code != 200
        message = obj["message"]?.try(&.as_s?) || "EPSS API error"
        raise APIError.new(message, status: status_code, body: input.is_a?(String) ? input : nil)
      end

      data_node = obj["data"]? || raise ParseError.new("missing data array in EPSS response")
      data = data_node.as_a? || raise ParseError.new("data field is not an array")

      # `scope=time-series` requests nest a `time-series` array per row,
      # each entry of which is another {epss, percentile, date} triple
      # carrying the *same* CVE as the parent. We flatten those into the
      # main score list so consumers see one Score per (cve, date) pair
      # regardless of how the API chose to bundle them.
      scores = [] of Score
      data.each { |row| scores.concat(scores_from_data_row(row)) }
      row_count = data.size

      new(
        status: status,
        status_code: status_code,
        version: string(obj, "version", default: "1.0"),
        access: string(obj, "access", default: "public"),
        total: int(obj, "total", default: row_count),
        offset: int(obj, "offset", default: 0),
        limit: int(obj, "limit", default: row_count),
        row_count: row_count,
        scores: scores,
      )
    end

    private def self.scores_from_data_row(node : ::JSON::Any) : Array(Score)
      h = node.as_h? || raise ParseError.new("expected object in data array, got #{node}")
      cve = h["cve"]?.try(&.as_s?) || raise ParseError.new("missing cve in data row")

      out = [] of Score
      out << build_score(cve, h)

      if ts = h["time-series"]?
        ts_arr = ts.as_a? || raise ParseError.new("time-series field is not an array")
        ts_arr.each do |entry|
          eh = entry.as_h? || raise ParseError.new("expected object in time-series array")
          out << build_score(cve, eh)
        end
      end

      out
    end

    private def self.build_score(cve : String, h : Hash(String, ::JSON::Any)) : Score
      Score.from_row(
        cve: cve,
        epss: h["epss"]?.try(&.raw) || raise(ParseError.new("missing epss in data row")),
        percentile: h["percentile"]?.try(&.raw) || raise(ParseError.new("missing percentile in data row")),
        date: h["date"]?.try(&.raw),
      )
    end

    private def self.string(obj : Hash(String, ::JSON::Any), key : String, *, default : String? = nil) : String
      if v = obj[key]?
        v.as_s? || v.to_s
      else
        default || raise ParseError.new("missing string field '#{key}' in EPSS response")
      end
    end

    private def self.int(obj : Hash(String, ::JSON::Any), key : String, *, default : Int32? = nil) : Int32
      if v = obj[key]?
        case raw = v.raw
        when Int64  then raw.to_i32
        when Int32  then raw
        when String then raw.to_i32? || raise ParseError.new("non-integer value for '#{key}': #{raw}")
        when Float
          if raw.to_i.to_f == raw
            raw.to_i32
          else
            raise ParseError.new("non-integer value for '#{key}': #{raw}")
          end
        else
          raise ParseError.new("non-integer value for '#{key}': #{raw}")
        end
      else
        default || raise ParseError.new("missing integer field '#{key}' in EPSS response")
      end
    end
  end
end
