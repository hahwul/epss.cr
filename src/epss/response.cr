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

    def initialize(
      @status : String,
      @status_code : Int32,
      @version : String,
      @access : String,
      @total : Int32,
      @offset : Int32,
      @limit : Int32,
      @scores : Array(Score),
    )
    end

    delegate :each, :size, :[], to: @scores

    # Whether the API reported the request as successful. Mirrors the
    # FIRST envelope's `status: "OK"` convention.
    def ok? : Bool
      @status == "OK" && @status_code == 200
    end

    # Whether more pages exist beyond this response.
    def more? : Bool
      @offset + @scores.size < @total
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

      scores = data.map { |row| score_from_json(row) }

      new(
        status: status,
        status_code: status_code,
        version: string(obj, "version", default: "1.0"),
        access: string(obj, "access", default: "public"),
        total: int(obj, "total", default: scores.size),
        offset: int(obj, "offset", default: 0),
        limit: int(obj, "limit", default: scores.size),
        scores: scores,
      )
    end

    private def self.score_from_json(node : ::JSON::Any) : Score
      h = node.as_h? || raise ParseError.new("expected object in data array, got #{node}")
      cve = h["cve"]?.try(&.as_s?) || raise ParseError.new("missing cve in data row")
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
