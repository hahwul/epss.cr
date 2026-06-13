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
  end
end
