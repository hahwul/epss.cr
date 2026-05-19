require "./spec_helper"

describe EPSS::Query do
  describe "#to_params" do
    it "returns an empty list for a default query" do
      EPSS::Query.new.to_params.should be_empty
    end

    it "joins multiple CVEs with commas" do
      q = EPSS::Query.new(cves: ["CVE-1", "cve-2"])
      pairs = q.to_params
      pairs.should contain({"cve", "CVE-1,CVE-2"})
    end

    it "emits date as YYYY-MM-DD" do
      q = EPSS::Query.new(date: Time.utc(2026, 5, 18))
      q.to_params.should contain({"date", "2026-05-18"})
    end

    it "encodes filter thresholds" do
      q = EPSS::Query.new(epss_gt: 0.95, percentile_lt: 0.5)
      params = q.to_params.to_h
      params["epss-gt"].should eq("0.95")
      params["percentile-lt"].should eq("0.5")
    end

    it "encodes pagination and order" do
      q = EPSS::Query.new(offset: 100, limit: 50, order: "!epss")
      params = q.to_params.to_h
      params["offset"].should eq("100")
      params["limit"].should eq("50")
      params["order"].should eq("!epss")
    end

    it "emits decimal notation for small thresholds (no scientific form)" do
      q = EPSS::Query.new(epss_gt: 0.0000001)
      params = q.to_params.to_h
      params["epss-gt"].should_not contain("e")
      params["epss-gt"].should eq("0.0000001")
    end

    it "encodes fields/pretty/envelope global params" do
      q = EPSS::Query.new(fields: ["cve", "epss"], pretty: true, envelope: false)
      params = q.to_params.to_h
      params["fields"].should eq("cve,epss")
      params["pretty"].should eq("true")
      params["envelope"].should eq("false")
    end

    it "omits pretty when false and envelope when nil" do
      q = EPSS::Query.new(pretty: false)
      params = q.to_params.to_h
      params.has_key?("pretty").should be_false
      params.has_key?("envelope").should be_false
    end

    it "encodes days" do
      q = EPSS::Query.new(days: 7)
      q.to_params.to_h["days"].should eq("7")
    end
  end

  describe "#to_query_string" do
    it "produces a URL-encoded query string" do
      q = EPSS::Query.new(cves: ["CVE-2022-27225"], epss_gt: 0.5)
      qs = q.to_query_string
      qs.should contain("cve=CVE-2022-27225")
      qs.should contain("epss-gt=0.5")
    end

    it "returns empty string for an empty query" do
      EPSS::Query.new.to_query_string.should eq("")
    end
  end

  describe "validation" do
    it "rejects out-of-range thresholds" do
      expect_raises(EPSS::ParseError) { EPSS::Query.new(epss_gt: 1.5) }
      expect_raises(EPSS::ParseError) { EPSS::Query.new(percentile_lt: -0.1) }
    end

    it "rejects negative offset and non-positive limit" do
      expect_raises(EPSS::ParseError) { EPSS::Query.new(offset: -1) }
      expect_raises(EPSS::ParseError) { EPSS::Query.new(limit: 0) }
    end

    it "rejects non-positive days" do
      expect_raises(EPSS::ParseError) { EPSS::Query.new(days: 0) }
    end
  end

  describe "class-method factories" do
    it "Query.for_cve / for_cves build CVE-filtered queries" do
      EPSS::Query.for_cve("cve-1").cves.should eq(["CVE-1"])
      EPSS::Query.for_cves(["a", "b"]).cves.should eq(["A", "B"])
    end

    it "Query.top sorts descending with a limit" do
      q = EPSS::Query.top(10)
      q.order.should eq("!epss")
      q.limit.should eq(10)
    end

    it "Query.above / below set threshold filters" do
      EPSS::Query.above.epss_gt.should eq(0.95)
      EPSS::Query.above(0.7).epss_gt.should eq(0.7)
      EPSS::Query.below(0.01).epss_lt.should eq(0.01)
    end

    it "Query.search sets q + ordering" do
      q = EPSS::Query.search("openssl")
      q.q.should eq("openssl")
      q.order.should eq("!epss")
    end

    it "Query.recent sets days" do
      EPSS::Query.recent(7).days.should eq(7)
    end
  end

  describe "with_* derivation" do
    it "returns a new instance" do
      q = EPSS::Query.new(cves: ["CVE-1"])
      q2 = q.with_limit(50)
      q.limit.should be_nil
      q2.limit.should eq(50)
    end

    it "with_cve replaces with a single id" do
      q = EPSS::Query.new(cves: ["CVE-1", "CVE-2"]).with_cve("CVE-3")
      q.cves.should eq(["CVE-3"])
    end

    it "covers the full parameter surface" do
      q = EPSS::Query.new
        .with_q("openssl")
        .with_scope("time-series")
        .with_order("!epss")
        .with_days(7)
        .with_epss_gt(0.1)
        .with_epss_lt(0.9)
        .with_percentile_gt(0.5)
        .with_percentile_lt(0.99)
        .with_fields("cve,epss")
        .with_pretty(true)
        .with_envelope(false)
      params = q.to_params.to_h
      params["q"].should eq("openssl")
      params["scope"].should eq("time-series")
      params["order"].should eq("!epss")
      params["days"].should eq("7")
      params["epss-gt"].should eq("0.1")
      params["epss-lt"].should eq("0.9")
      params["percentile-gt"].should eq("0.5")
      params["percentile-lt"].should eq("0.99")
      params["fields"].should eq("cve,epss")
      params["pretty"].should eq("true")
      params["envelope"].should eq("false")
    end
  end
end
