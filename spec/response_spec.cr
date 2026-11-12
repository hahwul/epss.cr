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

    # FIRST's live error envelope carries `message` as an array of strings.
    it "reads an error envelope's message array" do
      payload = %({"status":"Unprocessable Entity","status-code":422,"version":"1.0","access":"public","message":["listNoResults"],"data":{"error":["listNoResults"]}})
      expect_raises(EPSS::APIError, "listNoResults") do
        EPSS::Response.from_json(payload)
      end
    end
  end

  describe ".new" do
    # `row_count` defaults to `scores.size`; the default used to read
    # `@scores` before it was assigned, so omitting it did not compile.
    it "defaults row_count to the score count" do
      score = EPSS::Score.new("CVE-1", 0.1, 0.5)
      resp = EPSS::Response.new(status: "OK", status_code: 200, version: "1.0", access: "public",
        total: 3, offset: 0, limit: 100, scores: [score, score])
      resp.row_count.should eq(2)
      resp.more?.should be_true
    end
  end

  describe "#more?" do
    # `offset` is any Int32 the payload carries; `offset + row_count` must
    # not overflow on a value near Int32::MAX.
    it "does not overflow on an offset near Int32::MAX" do
      payload = %({"status":"OK","status-code":200,"version":"1.0","access":"public","total":5,"offset":2147483647,"limit":100,"data":[{"cve":"CVE-1","epss":"0.1","percentile":"0.5"}]})
      EPSS::Response.from_json(payload).more?.should be_false
    end
  end
end
