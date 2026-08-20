require "./spec_helper"

describe EPSS::Response do
  describe ".from_json" do
    # Regression: an envelope whose integer fields exceed Int32 must surface
    # the library's typed ParseError rather than leaking a raw OverflowError
    # out of the numeric conversion in `int()`.
    it "raises ParseError (not OverflowError) on an out-of-range Int64 field" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":2147483648,"offset":0,"limit":100,"data":[]})
      expect_raises(EPSS::ParseError, /out of range/) do
        EPSS::Response.from_json(payload)
      end
    end

    it "raises ParseError (not OverflowError) on an out-of-range Float field" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":2147483648.0,"offset":0,"limit":100,"data":[]})
      expect_raises(EPSS::ParseError, /out of range/) do
        EPSS::Response.from_json(payload)
      end
    end

    it "still rejects a non-integral Float field as a ParseError" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":2.5,"offset":0,"limit":100,"data":[]})
      expect_raises(EPSS::ParseError, /non-integer/) do
        EPSS::Response.from_json(payload)
      end
    end

    it "keeps decoding small in-range integer and float fields unchanged" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":42,"offset":10.0,"limit":100,"data":[]})
      resp = EPSS::Response.from_json(payload)
      resp.total.should eq(42)
      resp.offset.should eq(10)
      resp.limit.should eq(100)
    end

    # `Query#with_envelope(false)` asks the API for the bare data array, so
    # the decoder has to accept a top-level array — it used to reject the
    # payload its own query builder can request.
    it "decodes a bare data array (envelope=false)" do
      payload = %([{"cve":"CVE-1","epss":"0.1","percentile":"0.5","date":"2026-05-18"}])
      resp = EPSS::Response.from_json(payload)
      resp.ok?.should be_true
      resp.total.should eq(1)
      resp.offset.should eq(0)
      resp.more?.should be_false
      resp.scores.map(&.cve).should eq(["CVE-1"])
    end

    it "decodes an empty bare data array" do
      resp = EPSS::Response.from_json("[]")
      resp.scores.should be_empty
      resp.total.should eq(0)
    end

    # Regression: an IO source is consumed by the first read, so the decoder
    # must not re-read it.
    it "decodes an envelope supplied as an IO" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":1,"offset":0,"limit":100,"data":[{"cve":"CVE-1","epss":"0.1","percentile":"0.5"}]})
      EPSS::Response.from_json(IO::Memory.new(payload)).scores.size.should eq(1)
    end
  end
end
