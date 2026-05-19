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
