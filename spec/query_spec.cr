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
  end

  describe "with_* derivation" do
    it "returns a new instance" do
      q = EPSS::Query.new(cves: ["CVE-1"])
      q2 = q.with_limit(50)
      q.limit.should be_nil
      q2.limit.should eq(50)
    end
  end
end
