require "./spec_helper"

describe EPSS::Client do
  describe "#fetch" do
    it "issues a GET against the configured base URI" do
      payload = fixture_envelope([
        {cve: "CVE-2022-27225", epss: "0.001870000", percentile: "0.401290000", date: "2026-05-18"},
      ])
      stub = StubTransport.from_body(payload)
      client = EPSS::Client.new(transport: stub)

      resp = client.fetch(EPSS::Query.new(cves: ["CVE-2022-27225"]))
      resp.scores.size.should eq(1)
      resp.scores.first.cve.should eq("CVE-2022-27225")

      stub.requests.size.should eq(1)
      stub.requests.first[0].host.should eq("api.first.org")
      stub.requests.first[0].path.should eq("/data/v1/epss")
      stub.requests.first[0].query.not_nil!.should contain("cve=CVE-2022-27225")
    end

    it "sets Accept and User-Agent headers" do
      stub = StubTransport.from_body(fixture_envelope([] of NamedTuple(cve: String, epss: String, percentile: String, date: String)))
      client = EPSS::Client.new(transport: stub)
      client.fetch

      headers = stub.requests.first[1]
      headers["Accept"].should eq("application/json")
      headers["User-Agent"].should match(/epss\.cr/)
    end

    it "raises APIError on a non-2xx response" do
      stub = StubTransport.from_body("bad request", status: 400)
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      expect_raises(EPSS::APIError, /400/) do
        client.fetch
      end
    end

    it "retries on 5xx responses then surfaces APIError" do
      attempts = 0
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        attempts += 1
        HTTP::Client::Response.new(503, body: "down")
      }
      client = EPSS::Client.new(
        transport: stub,
        max_retries: 2,
        retry_backoff: 1.millisecond,
      )
      expect_raises(EPSS::APIError, /503/) do
        client.fetch
      end
      attempts.should eq(3) # 1 initial + 2 retries
    end

    it "retries 503 then succeeds" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"},
      ])
      responses = [
        HTTP::Client::Response.new(503, body: "down"),
        HTTP::Client::Response.new(200, body: payload),
      ]
      stub = StubTransport.from_queue(responses)
      client = EPSS::Client.new(transport: stub, max_retries: 3, retry_backoff: 1.millisecond)

      resp = client.fetch
      resp.scores.first.cve.should eq("CVE-1")
      stub.requests.size.should eq(2)
    end
  end

  describe "#score" do
    it "returns the single score or nil" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.5", percentile: "0.9", date: "2026-05-18"},
      ])
      client = EPSS::Client.new(transport: StubTransport.from_body(payload))
      s = client.score("CVE-1")
      s.should_not be_nil
      s.not_nil!.epss.should eq(0.5)
    end

    it "returns nil when the API has no rows" do
      empty = fixture_envelope([] of NamedTuple(cve: String, epss: String, percentile: String, date: String))
      client = EPSS::Client.new(transport: StubTransport.from_body(empty))
      client.score("CVE-NONE").should be_nil
    end
  end

  describe "#scores" do
    it "batches large CVE lists into multiple requests" do
      cves = (1..150).map { |i| "CVE-2024-#{i}" }
      counter = 0
      stub = StubTransport.new ->(uri : URI, _h : HTTP::Headers) {
        counter += 1
        query = uri.query.not_nil!
        cve_param = URI::Params.parse(query)["cve"]
        rows = cve_param.split(",").map { |c|
          {cve: c, epss: "0.1", percentile: "0.5", date: "2026-05-18"}
        }
        HTTP::Client::Response.new(200, body: fixture_envelope(rows))
      }
      client = EPSS::Client.new(transport: stub)
      result = client.scores(cves, batch_size: 100)
      result.size.should eq(150)
      counter.should eq(2)
    end
  end

  describe "#each_score (pagination)" do
    it "follows the offset/total cursor until exhaustion" do
      page1 = fixture_envelope(
        (1..3).map { |i| {cve: "CVE-#{i}", epss: "0.1", percentile: "0.5", date: "2026-05-18"} }.to_a,
        total: 5,
        offset: 0,
        limit: 3,
      )
      page2 = fixture_envelope(
        (4..5).map { |i| {cve: "CVE-#{i}", epss: "0.1", percentile: "0.5", date: "2026-05-18"} }.to_a,
        total: 5,
        offset: 3,
        limit: 3,
      )
      stub = StubTransport.from_queue([
        HTTP::Client::Response.new(200, body: page1),
        HTTP::Client::Response.new(200, body: page2),
      ])
      client = EPSS::Client.new(transport: stub)

      seen = [] of String
      client.each_score(EPSS::Query.new(epss_gt: 0.0), page_size: 3) { |s| seen << s.cve }
      seen.should eq(["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"])
      stub.requests.size.should eq(2)
    end
  end

  describe "#build_uri" do
    it "merges the query string into the base URI" do
      client = EPSS::Client.new(transport: StubTransport.from_body("{}"))
      uri = client.build_uri(EPSS::Query.new(cves: ["CVE-1"]))
      uri.host.should eq("api.first.org")
      uri.path.should eq("/data/v1/epss")
      uri.query.not_nil!.should contain("cve=CVE-1")
    end
  end
end
