require "spec"
require "../src/epss"

# In-memory `EPSS::Transport` used by client specs. The responder Proc
# decides what to return for each (URI, headers) call.
class StubTransport < EPSS::Transport
  alias Responder = Proc(URI, HTTP::Headers, HTTP::Client::Response)

  getter requests : Array({URI, HTTP::Headers}) = [] of {URI, HTTP::Headers}
  property responder : Responder

  def initialize(@responder : Responder)
  end

  def self.from_queue(responses : Array(HTTP::Client::Response)) : StubTransport
    queue = responses.dup
    new ->(_uri : URI, _headers : HTTP::Headers) {
      raise "stub queue exhausted" if queue.empty?
      queue.shift
    }
  end

  def self.from_body(body : String, status : Int32 = 200) : StubTransport
    new ->(_uri : URI, _headers : HTTP::Headers) {
      HTTP::Client::Response.new(status, body: body)
    }
  end

  def get(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
    @requests << {uri, headers}
    @responder.call(uri, headers)
  end
end

# A `StubTransport` that behaves like the paginated API: it honors the
# `offset` / `limit` it is sent and reports `total` rows overall.
def paging_stub(total : Int32) : StubTransport
  StubTransport.new ->(uri : URI, _headers : HTTP::Headers) {
    params = URI::Params.parse(uri.query || "")
    offset = params["offset"]?.try(&.to_i) || 0
    limit = params["limit"]?.try(&.to_i) || 100
    rows = (offset...Math.min(offset + limit, total)).map do |i|
      {cve: "CVE-#{i}", epss: "0.1", percentile: "0.5", date: "2026-05-18"}
    end
    body = fixture_envelope(rows, total: total, offset: offset, limit: limit)
    HTTP::Client::Response.new(200, body: body)
  }
end

def fixture_envelope(
  rows : Array(NamedTuple(cve: String, epss: String, percentile: String, date: String)),
  total : Int32? = nil,
  offset : Int32 = 0,
  limit : Int32 = 100,
) : String
  total ||= rows.size
  data_json = rows.map do |s|
    %({"cve":"#{s[:cve]}","epss":"#{s[:epss]}","percentile":"#{s[:percentile]}","date":"#{s[:date]}"})
  end.join(",")
  %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":#{total},"offset":#{offset},"limit":#{limit},"data":[#{data_json}]})
end
