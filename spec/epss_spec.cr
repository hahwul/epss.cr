require "./spec_helper"

describe EPSS do
  it "exposes a version constant" do
    EPSS::VERSION.should be_a(String)
  end

  describe ".from_json" do
    it "decodes a FIRST API envelope" do
      payload = fixture_envelope([
        {cve: "CVE-2022-27225", epss: "0.001870000", percentile: "0.401290000", date: "2026-05-18"},
        {cve: "CVE-2023-1111", epss: "0.500000000", percentile: "0.800000000", date: "2026-05-18"},
      ])
      scores = EPSS.from_json(payload)
      scores.size.should eq(2)
      scores.first.cve.should eq("CVE-2022-27225")
      scores.first.epss.should be_close(0.001870, 1e-9)
    end

    it "decodes a bare row" do
      json = %({"cve": "CVE-2022-27225", "epss": "0.001870000", "percentile": "0.401290000", "date": "2026-05-18"})
      scores = EPSS.from_json(json)
      scores.size.should eq(1)
      scores.first.cve.should eq("CVE-2022-27225")
    end

    it "accepts numeric values (not just stringified)" do
      json = %({"cve": "CVE-1", "epss": 0.5, "percentile": 0.9, "date": "2026-05-18"})
      scores = EPSS.from_json(json)
      scores.first.epss.should eq(0.5)
      scores.first.percentile.should eq(0.9)
    end

    # Regression: the envelope branch re-read `input` after `JSON.parse`
    # had already drained it, so an IO envelope died with a raw
    # `JSON::ParseException` on an empty stream.
    it "decodes an envelope supplied as an IO" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"},
        {cve: "CVE-2", epss: "0.2", percentile: "0.6", date: "2026-05-18"},
      ])
      scores = EPSS.from_json(IO::Memory.new(payload))
      scores.map(&.cve).should eq(["CVE-1", "CVE-2"])
    end

    it "decodes a bare row array (envelope=false)" do
      json = %([{"cve":"CVE-1","epss":"0.1","percentile":"0.5"},{"cve":"CVE-2","epss":"0.2","percentile":"0.6"}])
      EPSS.from_json(json).map(&.cve).should eq(["CVE-1", "CVE-2"])
    end

    it "raises ParseError on unknown shape" do
      expect_raises(EPSS::ParseError) do
        EPSS.from_json(%({"foo": "bar"}))
      end
    end

    it "propagates JSON parse errors" do
      expect_raises(::JSON::ParseException) do
        EPSS.from_json("not json")
      end
    end
  end

  describe ".from_json?" do
    it "returns nil for malformed JSON" do
      EPSS.from_json?("nope").should be_nil
      EPSS.from_json?(%({"oops": true})).should be_nil
    end

    it "returns scores for valid input" do
      scores = EPSS.from_json?(%({"cve": "CVE-1", "epss": "0.1", "percentile": "0.2"}))
      scores.should_not be_nil
      scores.not_nil!.first.cve.should eq("CVE-1")
    end
  end

  describe "EPSS::Response#to_json" do
    it "round-trips an envelope payload back through the parser" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.100000000", percentile: "0.500000000", date: "2026-05-18"},
        {cve: "CVE-2", epss: "0.200000000", percentile: "0.600000000", date: "2026-05-18"},
      ], total: 2, offset: 0, limit: 100)
      resp = EPSS::Response.from_json(payload)
      reparsed = EPSS::Response.from_json(resp.to_json)
      reparsed.total.should eq(resp.total)
      reparsed.scores.map(&.cve).should eq(resp.scores.map(&.cve))
      reparsed.scores.map(&.epss).should eq(resp.scores.map(&.epss))
    end
  end

  describe "EPSS::Response#to_json (time-series)" do
    # Shape of a live `scope=time-series` page: one row per CVE, its daily
    # history nested without a `cve` key.
    payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":5,"offset":2,"limit":2,"data":[) +
              %({"cve":"CVE-1","epss":"0.100000000","percentile":"0.500000000","date":"2026-05-18","time-series":[) +
              %({"epss":"0.090000000","percentile":"0.490000000","date":"2026-05-17"},{"epss":"0.080000000","percentile":"0.480000000","date":"2026-05-16"}]},) +
              %({"cve":"CVE-2","epss":"0.200000000","percentile":"0.600000000","date":"2026-05-18","time-series":[]}]})

    it "round-trips scores, row_count, and paging fields" do
      resp = EPSS::Response.from_json(payload)
      resp.row_count.should eq(2)
      resp.more?.should be_true
      reparsed = EPSS::Response.from_json(resp.to_json)
      reparsed.scores.should eq(resp.scores)
      reparsed.row_count.should eq(2)
      {reparsed.total, reparsed.offset, reparsed.limit}.should eq({5, 2, 2})
      reparsed.more?.should be_true
      reparsed.to_json.should eq(resp.to_json)
    end

    it "nests time-series entries like the API does" do
      data = JSON.parse(EPSS::Response.from_json(payload).to_json)["data"]
      data.as_a.size.should eq(2)
      data[0]["time-series"].as_a.map(&.["date"].as_s).should eq(["2026-05-17", "2026-05-16"])
      data[0]["time-series"][0].as_h.has_key?("cve").should be_false
      data[1].as_h.has_key?("time-series").should be_false
    end

    it "writes each score as its own row when CVE runs do not match row_count" do
      score = EPSS::Score.new(cve: "CVE-1", epss: 0.1, percentile: 0.5)
      resp = EPSS::Response.new(status: "OK", status_code: 200, version: "1.0", access: "public",
        total: 2, offset: 0, limit: 2, row_count: 2, scores: [score, score])
      EPSS::Response.from_json(resp.to_json).row_count.should eq(2)
    end
  end

  describe "EPSS::Score.from_json" do
    it "parses one bare row into a single Score" do
      json = %({"cve": "CVE-1", "epss": "0.1", "percentile": "0.5", "date": "2026-05-18"})
      score = EPSS::Score.from_json(json)
      score.cve.should eq("CVE-1")
      score.epss.should eq(0.1)
    end

    it "returns nil on malformed input via from_json?" do
      EPSS::Score.from_json?("bad").should be_nil
    end
  end

  describe "module-level convenience" do
    after_each { EPSS.reset_client }

    it ".score uses the default client" do
      payload = fixture_envelope([
        {cve: "CVE-2022-27225", epss: "0.001870000", percentile: "0.401290000", date: "2026-05-18"},
      ])
      EPSS.client = EPSS::Client.new(transport: StubTransport.from_body(payload))

      result = EPSS.score("CVE-2022-27225")
      result.should_not be_nil
      result.not_nil!.cve.should eq("CVE-2022-27225")
    end

    it ".band / .epss / .percentile pluck single fields" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.500000000", percentile: "0.900000000", date: "2026-05-18"},
      ])
      EPSS.client = EPSS::Client.new(transport: StubTransport.from_body(payload))
      EPSS.band("CVE-1").should eq(EPSS::Band::High)
      EPSS.epss("CVE-1").should eq(0.5)
      EPSS.percentile("CVE-1").should eq(0.9)
    end

    it ".top sends sort=-epss and limit=N" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.9", percentile: "0.99", date: "2026-05-18"},
      ])
      stub = StubTransport.from_body(payload)
      EPSS.client = EPSS::Client.new(transport: stub)
      EPSS.top(5)
      qs = stub.requests.first[0].query.not_nil!
      qs.should contain("sort=-epss")
      qs.should contain("limit=5")
    end

    it ".search sends q and order" do
      payload = fixture_envelope([] of NamedTuple(cve: String, epss: String, percentile: String, date: String))
      stub = StubTransport.from_body(payload)
      EPSS.client = EPSS::Client.new(transport: stub)
      EPSS.search("openssl")
      qs = stub.requests.first[0].query.not_nil!
      qs.should contain("q=openssl")
      qs.should contain("sort=-epss")
    end

    it ".scores batches a list" do
      payload = fixture_envelope([
        {cve: "CVE-1", epss: "0.1", percentile: "0.5", date: "2026-05-18"},
        {cve: "CVE-2", epss: "0.2", percentile: "0.6", date: "2026-05-18"},
      ])
      EPSS.client = EPSS::Client.new(transport: StubTransport.from_body(payload))

      scores = EPSS.scores(["CVE-1", "CVE-2"])
      scores.map(&.cve).should eq(["CVE-1", "CVE-2"])
    end
  end
end
