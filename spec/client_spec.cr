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

    it "raises APIError on a non-2xx response with status + body populated" do
      stub = StubTransport.from_body("bad request", status: 400)
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      begin
        client.fetch
        fail "should have raised"
      rescue ex : EPSS::APIError
        ex.status.should eq(400)
        ex.body.should eq("bad request")
        ex.message.not_nil!.should contain("400")
      end
    end

    it "honors Retry-After header (seconds) on 429" do
      attempts = 0
      slept = false
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        attempts += 1
        if attempts == 1
          slept = false
          headers = HTTP::Headers{"Retry-After" => "1"}
          HTTP::Client::Response.new(429, body: "", headers: headers)
        else
          HTTP::Client::Response.new(200, body: fixture_envelope(
            [{cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"}]
          ))
        end
      }
      client = EPSS::Client.new(transport: stub, max_retries: 2, retry_backoff: 10.seconds)
      start = Time.instant
      client.fetch
      elapsed = Time.instant - start
      # Retry-After=1 should have been used (≤2s) instead of 10s base backoff.
      elapsed.should be < 5.seconds
      attempts.should eq(2)
    end

    it "retries 429 (rate-limit) like 5xx" do
      attempts = 0
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        attempts += 1
        if attempts < 3
          HTTP::Client::Response.new(429, body: "slow down")
        else
          HTTP::Client::Response.new(200, body: fixture_envelope([
            {cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"},
          ]))
        end
      }
      client = EPSS::Client.new(transport: stub, max_retries: 5, retry_backoff: 1.millisecond)
      client.fetch.scores.first.cve.should eq("CVE-1")
      attempts.should eq(3)
    end

    it "retries transport IO errors then surfaces APIError preserving cause" do
      attempts = 0
      cause_ex = IO::TimeoutError.new("read timeout")
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        attempts += 1
        raise cause_ex
      }
      client = EPSS::Client.new(transport: stub, max_retries: 2, retry_backoff: 1.millisecond)
      begin
        client.fetch
        fail "should have raised"
      rescue ex : EPSS::APIError
        ex.cause.should eq(cause_ex)
        ex.message.not_nil!.should contain("read timeout")
      end
      attempts.should eq(3)
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

    # Regression: the legacy feed host answers with a 301 to the current
    # host, so a client that treats 3xx as a hard failure cannot download
    # the feed the README advertises.
    it "follows a redirect to another host" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"},
      ])
      stub = StubTransport.new ->(uri : URI, _headers : HTTP::Headers) {
        if uri.host == "api.first.org"
          HTTP::Client::Response.new(301, body: "", headers: HTTP::Headers{
            "Location" => "https://api2.first.org#{uri.request_target}",
          })
        else
          HTTP::Client::Response.new(200, body: payload)
        end
      }
      client = EPSS::Client.new(transport: stub, max_retries: 0)

      client.fetch(EPSS::Query.new(cves: ["CVE-1"])).scores.first.cve.should eq("CVE-1")
      stub.requests.map(&.[0].host).should eq(["api.first.org", "api2.first.org"])
      # The redirected request keeps the original query string.
      stub.requests.last[0].query.not_nil!.should contain("cve=CVE-1")
    end

    it "resolves a relative redirect Location against the current URI" do
      stub = StubTransport.new ->(uri : URI, _headers : HTTP::Headers) {
        if uri.path == "/data/v1/epss"
          HTTP::Client::Response.new(302, body: "", headers: HTTP::Headers{"Location" => "/data/v2/epss"})
        else
          HTTP::Client::Response.new(200, body: fixture_envelope(
            [{cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"}]
          ))
        end
      }
      EPSS::Client.new(transport: stub, max_retries: 0).fetch
      stub.requests.last[0].path.should eq("/data/v2/epss")
      stub.requests.last[0].host.should eq("api.first.org")
    end

    it "gives up after MAX_REDIRECTS hops instead of looping forever" do
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        HTTP::Client::Response.new(302, body: "", headers: HTTP::Headers{"Location" => "/loop"})
      }
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      expect_raises(EPSS::APIError, /redirect/) { client.fetch }
      stub.requests.size.should eq(EPSS::Client::MAX_REDIRECTS + 1)
    end

    it "raises APIError on a redirect without a Location header" do
      stub = StubTransport.from_body("", status: 301)
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      expect_raises(EPSS::APIError, /Location/) { client.fetch }
    end

    it "refuses to follow a redirect to a non-HTTP scheme" do
      stub = StubTransport.new ->(_uri : URI, _headers : HTTP::Headers) {
        HTTP::Client::Response.new(302, body: "", headers: HTTP::Headers{"Location" => "file:///etc/passwd"})
      }
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      expect_raises(EPSS::APIError, /unsupported scheme/) { client.fetch }
      stub.requests.size.should eq(1)
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

    # Regression: `score("")` sent `cve=`, which FIRST answers with the
    # unfiltered population, so it returned an unrelated CVE's score.
    it "raises on a blank CVE id instead of issuing an unfiltered request" do
      stub = StubTransport.from_body("")
      client = EPSS::Client.new(transport: stub)
      expect_raises(EPSS::ParseError, "blank CVE id") { client.score("") }
      stub.requests.should be_empty
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
        rows = cve_param.split(",").map do |c|
          {cve: c, epss: "0.1", percentile: "0.5", date: "2026-05-18"}
        end
        HTTP::Client::Response.new(200, body: fixture_envelope(rows))
      }
      client = EPSS::Client.new(transport: stub)
      result = client.scores(cves, batch_size: 100)
      result.size.should eq(150)
      counter.should eq(2)
    end
  end

  describe "#time_series" do
    it "flattens the nested time-series array into one Score per day" do
      payload = <<-JSON
        {
          "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
          "total": 1, "offset": 0, "limit": 100,
          "data": [{
            "cve": "CVE-2022-27225",
            "epss": "0.001870000",
            "percentile": "0.401290000",
            "date": "2026-05-18",
            "time-series": [
              {"epss": "0.001870000", "percentile": "0.401770000", "date": "2026-05-17"},
              {"epss": "0.001870000", "percentile": "0.401890000", "date": "2026-05-16"}
            ]
          }]
        }
        JSON
      client = EPSS::Client.new(transport: StubTransport.from_body(payload))
      series = client.time_series("CVE-2022-27225")
      series.size.should eq(3)
      series.map(&.date.not_nil!.to_s("%Y-%m-%d")).should eq([
        "2026-05-16", "2026-05-17", "2026-05-18",
      ])
      series.all? { |s| s.cve == "CVE-2022-27225" }.should be_true
    end

    it "sends scope=time-series in the query string" do
      empty = fixture_envelope([] of NamedTuple(cve: String, epss: String, percentile: String, date: String))
      stub = StubTransport.from_body(empty)
      EPSS::Client.new(transport: stub).time_series("CVE-1")
      stub.requests.first[0].query.not_nil!.should contain("scope=time-series")
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

    # Regression: `limit` used to be overwritten by `page_size`, so a bounded
    # query such as `Query.top(10)` paginated through the whole population.
    it "treats a query limit as the total row budget" do
      stub = paging_stub(total: 5000)
      client = EPSS::Client.new(transport: stub)

      scores = client.all_scores(EPSS::Query.top(10))
      scores.size.should eq(10)
      stub.requests.size.should eq(1)
      URI::Params.parse(stub.requests.first[0].query.not_nil!)["limit"].should eq("10")
    end

    it "splits a large query limit across pages and stops at the budget" do
      stub = paging_stub(total: 5000)
      client = EPSS::Client.new(transport: stub)

      scores = client.all_scores(EPSS::Query.new(epss_gt: 0.5).with_limit(2500), page_size: 1000)
      scores.size.should eq(2500)
      limits = stub.requests.map { |(uri, _)| URI::Params.parse(uri.query.not_nil!)["limit"] }
      limits.should eq(["1000", "1000", "500"])
    end

    it "still paginates to exhaustion when the query has no limit" do
      stub = paging_stub(total: 5)
      scores = EPSS::Client.new(transport: stub).all_scores(EPSS::Query.new(epss_gt: 0.5), page_size: 2)
      scores.size.should eq(5)
      stub.requests.size.should eq(3)
    end
  end

  describe "#fetch_feed" do
    it "downloads, gzip-decodes, and parses the daily feed via Transport" do
      csv_body = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-1,0.10,0.50
        CVE-2,0.20,0.60
        CSV
      gzipped = IO::Memory.new
      Compress::Gzip::Writer.open(gzipped, &.print(csv_body))
      gzipped.rewind
      stub = StubTransport.from_body(gzipped.to_s)
      client = EPSS::Client.new(transport: stub)

      feed = client.fetch_feed(Time.utc(2026, 5, 18))
      feed.scores.size.should eq(2)
      feed.metadata.model_version.should eq("v2025.03.14")
      stub.requests.first[0].host.should eq("epss.empiricalsecurity.com")
      stub.requests.first[0].path.should eq("/epss_scores-2026-05-18.csv.gz")
    end

    it "honors the legacy host override" do
      stub = StubTransport.from_body("cve,epss,percentile\nCVE-1,0.1,0.5\n")
      client = EPSS::Client.new(transport: stub)
      client.fetch_feed(Time.utc(2026, 5, 18), host: "epss.cyentia.com")
      stub.requests.first[0].host.should eq("epss.cyentia.com")
    end

    it "raises APIError when the feed host returns non-200" do
      stub = StubTransport.from_body("not found", status: 404)
      client = EPSS::Client.new(transport: stub, max_retries: 0)
      expect_raises(EPSS::APIError, /404/) do
        client.fetch_feed(Time.utc(2026, 5, 18))
      end
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

  describe "#backoff_delay" do
    it "grows exponentially for small attempt counts" do
      client = EPSS::Client.new(
        transport: StubTransport.from_body("{}"),
        retry_backoff: 1.second,
      )
      # base * 2^(attempt-1): 1s, 2s, 4s (plus <=10% jitter each).
      client.backoff_delay(1).should be >= 1.second
      client.backoff_delay(2).should be >= 2.seconds
      client.backoff_delay(3).should be >= 4.seconds
    end

    it "caps the delay at MAX_BACKOFF (plus jitter) and never grows unbounded" do
      client = EPSS::Client.new(
        transport: StubTransport.from_body("{}"),
        retry_backoff: 1.second,
      )
      ceiling = EPSS::Client::MAX_BACKOFF * 1.1
      # A large attempt count would overflow / sleep for hours without a cap.
      [10, 20, 40, 100].each do |attempt|
        delay = client.backoff_delay(attempt)
        delay.should be >= EPSS::Client::MAX_BACKOFF
        delay.should be <= ceiling
      end
    end

    it "adds jitter so concurrent retries do not wake in lockstep" do
      client = EPSS::Client.new(
        transport: StubTransport.from_body("{}"),
        retry_backoff: 1.second,
      )
      samples = Array.new(50) { client.backoff_delay(10) }
      # attempt 10 with a 1s base would be 512s, so it is clamped to
      # MAX_BACKOFF; jitter must keep it within [cap, cap*1.1] and produce
      # more than one distinct value across samples.
      samples.uniq.size.should be > 1
      samples.each do |d|
        d.should be >= EPSS::Client::MAX_BACKOFF
        d.should be <= EPSS::Client::MAX_BACKOFF * 1.1
      end
    end
  end
end

describe EPSS::Response do
  describe "#more?" do
    it "is true when offset + size < total" do
      payload = fixture_envelope(
        [{cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"}],
        total: 10,
        offset: 0,
        limit: 1,
      )
      EPSS::Response.from_json(payload).more?.should be_true
    end

    it "is false on the final page" do
      payload = fixture_envelope(
        [{cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"}],
        total: 1,
        offset: 0,
        limit: 1,
      )
      EPSS::Response.from_json(payload).more?.should be_false
    end
  end

  it "rejects an envelope reporting an error status" do
    payload = %({"status":"error","status-code":500,"message":"boom","version":"1.0","access":"public","total":0,"offset":0,"limit":100,"data":[]})
    expect_raises(EPSS::APIError, /boom/) do
      EPSS::Response.from_json(payload)
    end
  end
end
