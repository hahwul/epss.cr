require "./spec_helper"

describe EPSS::Score do
  describe "#initialize" do
    it "normalizes the CVE id to upper-case" do
      score = EPSS::Score.new("cve-2022-27225", 0.5, 0.6)
      score.cve.should eq("CVE-2022-27225")
    end

    it "rejects an empty CVE id" do
      expect_raises(EPSS::ParseError, /blank CVE/) do
        EPSS::Score.new("", 0.5, 0.5)
      end
    end

    it "rejects an EPSS probability outside [0, 1]" do
      expect_raises(EPSS::ParseError, /epss/) do
        EPSS::Score.new("CVE-1", -0.1, 0.5)
      end
      expect_raises(EPSS::ParseError, /epss/) do
        EPSS::Score.new("CVE-1", 1.1, 0.5)
      end
    end

    it "rejects a percentile outside [0, 1]" do
      expect_raises(EPSS::ParseError, /percentile/) do
        EPSS::Score.new("CVE-1", 0.5, 1.5)
      end
    end
  end

  describe ".from_row" do
    it "coerces string values" do
      s = EPSS::Score.from_row(cve: "CVE-1", epss: "0.5", percentile: "0.9", date: "2026-05-18")
      s.epss.should eq(0.5)
      s.percentile.should eq(0.9)
      s.date.should_not be_nil
      s.date.not_nil!.to_s("%Y-%m-%d").should eq("2026-05-18")
    end

    it "accepts floats and ints" do
      s = EPSS::Score.from_row(cve: "CVE-1", epss: 0.25_f32, percentile: 1, date: nil)
      s.epss.should eq(0.25)
      s.percentile.should eq(1.0)
      s.date.should be_nil
    end

    it "raises on non-numeric epss" do
      expect_raises(EPSS::ParseError, /epss/) do
        EPSS::Score.from_row(cve: "CVE-1", epss: "garbage", percentile: "0.5")
      end
    end

    it "raises on malformed date" do
      expect_raises(EPSS::ParseError, /date/) do
        EPSS::Score.from_row(cve: "CVE-1", epss: "0.1", percentile: "0.2", date: "2026/05/18")
      end
    end
  end

  describe "#band" do
    it "uses the epss-probability cutoffs" do
      EPSS::Score.new("CVE-1", 0.005, 0.5).band.should eq(EPSS::Band::None)
      EPSS::Score.new("CVE-1", 0.05, 0.5).band.should eq(EPSS::Band::Low)
      EPSS::Score.new("CVE-1", 0.2, 0.5).band.should eq(EPSS::Band::Medium)
      EPSS::Score.new("CVE-1", 0.5, 0.5).band.should eq(EPSS::Band::High)
      EPSS::Score.new("CVE-1", 0.9, 0.5).band.should eq(EPSS::Band::Critical)
    end

    it "uses the percentile cutoffs" do
      EPSS::Score.new("CVE-1", 0.001, 0.3).percentile_band.should eq(EPSS::Band::None)
      EPSS::Score.new("CVE-1", 0.001, 0.7).percentile_band.should eq(EPSS::Band::Low)
      EPSS::Score.new("CVE-1", 0.001, 0.85).percentile_band.should eq(EPSS::Band::Medium)
      EPSS::Score.new("CVE-1", 0.001, 0.95).percentile_band.should eq(EPSS::Band::High)
      EPSS::Score.new("CVE-1", 0.001, 0.999).percentile_band.should eq(EPSS::Band::Critical)
    end
  end

  describe "Comparable" do
    it "orders by EPSS probability" do
      low = EPSS::Score.new("CVE-1", 0.01, 0.4)
      mid = EPSS::Score.new("CVE-2", 0.1, 0.6)
      high = EPSS::Score.new("CVE-3", 0.9, 0.99)
      [high, low, mid].sort.map(&.cve).should eq(["CVE-1", "CVE-2", "CVE-3"])
    end

    it "compares with < and >" do
      a = EPSS::Score.new("CVE-A", 0.1, 0.5)
      b = EPSS::Score.new("CVE-B", 0.2, 0.5)
      (a < b).should be_true
      (b > a).should be_true
    end
  end

  describe "Equality + hash" do
    it "compares structurally on every field" do
      a = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 18))
      b = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 18))
      a.should eq(b)
      a.hash.should eq(b.hash)
    end

    it "treats different dates as not equal" do
      a = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 18))
      b = EPSS::Score.new("CVE-1", 0.5, 0.6, Time.utc(2026, 5, 17))
      a.should_not eq(b)
    end
  end

  describe "band predicates" do
    it "exposes one predicate per band level" do
      s = EPSS::Score.new("CVE-1", 0.9, 0.99)
      s.critical?.should be_true
      s.high?.should be_false
      s.none?.should be_false
    end

    it "supports at_least? with symbols and bands" do
      s = EPSS::Score.new("CVE-1", 0.5, 0.6)
      s.at_least?(:high).should be_true
      s.at_least?(:critical).should be_false
      s.at_least?(EPSS::Band::Medium).should be_true
    end
  end

  describe "display + temporal helpers" do
    it "renders percentage" do
      s = EPSS::Score.new("CVE-1", 0.42, 0.99)
      s.percentage.should be_close(42.0, 1e-9)
      s.percentile_percentage.should be_close(99.0, 1e-9)
    end

    it "computes age relative to now" do
      s = EPSS::Score.new("CVE-1", 0.1, 0.5, Time.utc(2026, 5, 18))
      span = s.age(Time.utc(2026, 5, 20)).not_nil!
      span.total_days.should be_close(2.0, 1e-6)
    end

    it "returns nil age when no date" do
      EPSS::Score.new("CVE-1", 0.1, 0.5).age.should be_nil
    end

    it "computes delta against another snapshot" do
      newer = EPSS::Score.new("CVE-1", 0.5, 0.9, Time.utc(2026, 5, 20))
      older = EPSS::Score.new("CVE-1", 0.2, 0.6, Time.utc(2026, 5, 18))
      newer.delta(older).should be_close(0.3, 1e-9)
    end
  end

  describe "JSON serialization" do
    it "emits the FIRST API row shape" do
      s = EPSS::Score.new("CVE-2022-27225", 0.00187, 0.40129, Time.utc(2026, 5, 18))
      json = JSON.parse(s.to_json)
      json["cve"].as_s.should eq("CVE-2022-27225")
      json["epss"].as_s.should eq("0.001870000")
      json["percentile"].as_s.should eq("0.401290000")
      json["date"].as_s.should eq("2026-05-18")
    end

    it "omits date when nil" do
      s = EPSS::Score.new("CVE-1", 0.1, 0.2)
      JSON.parse(s.to_json)["date"]?.should be_nil
    end

    it "round-trips via to_json + EPSS.from_json" do
      original = EPSS::Score.new("CVE-2022-27225", 0.00187, 0.40129, Time.utc(2026, 5, 18))
      restored = EPSS.from_json(original.to_json).first
      restored.cve.should eq(original.cve)
      restored.epss.should be_close(original.epss, 1e-9)
      restored.percentile.should be_close(original.percentile, 1e-9)
      restored.date.should eq(original.date)
    end
  end
end
