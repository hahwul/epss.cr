require "./spec_helper"

describe EPSS::Band do
  describe ".from_percentile" do
    it "buckets by the 50/80/90/99 cutoffs" do
      EPSS::Band.from_percentile(0.0).should eq(EPSS::Band::None)
      EPSS::Band.from_percentile(0.49).should eq(EPSS::Band::None)
      EPSS::Band.from_percentile(0.5).should eq(EPSS::Band::Low)
      EPSS::Band.from_percentile(0.79).should eq(EPSS::Band::Low)
      EPSS::Band.from_percentile(0.8).should eq(EPSS::Band::Medium)
      EPSS::Band.from_percentile(0.89).should eq(EPSS::Band::Medium)
      EPSS::Band.from_percentile(0.9).should eq(EPSS::Band::High)
      EPSS::Band.from_percentile(0.989).should eq(EPSS::Band::High)
      EPSS::Band.from_percentile(0.99).should eq(EPSS::Band::Critical)
      EPSS::Band.from_percentile(1.0).should eq(EPSS::Band::Critical)
    end

    it "rejects out-of-range values" do
      expect_raises(EPSS::ParseError) { EPSS::Band.from_percentile(-0.1) }
      expect_raises(EPSS::ParseError) { EPSS::Band.from_percentile(1.5) }
    end
  end

  describe ".from_epss" do
    it "buckets by the 0.01/0.1/0.3/0.7 cutoffs" do
      EPSS::Band.from_epss(0.0).should eq(EPSS::Band::None)
      EPSS::Band.from_epss(0.009).should eq(EPSS::Band::None)
      EPSS::Band.from_epss(0.01).should eq(EPSS::Band::Low)
      EPSS::Band.from_epss(0.099).should eq(EPSS::Band::Low)
      EPSS::Band.from_epss(0.1).should eq(EPSS::Band::Medium)
      EPSS::Band.from_epss(0.299).should eq(EPSS::Band::Medium)
      EPSS::Band.from_epss(0.3).should eq(EPSS::Band::High)
      EPSS::Band.from_epss(0.699).should eq(EPSS::Band::High)
      EPSS::Band.from_epss(0.7).should eq(EPSS::Band::Critical)
      EPSS::Band.from_epss(1.0).should eq(EPSS::Band::Critical)
    end
  end

  it "is comparable: Critical > High > Medium > Low > None" do
    (EPSS::Band::Critical > EPSS::Band::High).should be_true
    (EPSS::Band::High > EPSS::Band::Medium).should be_true
    (EPSS::Band::Medium > EPSS::Band::Low).should be_true
    (EPSS::Band::Low > EPSS::Band::None).should be_true
  end
end
