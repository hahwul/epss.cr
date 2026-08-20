require "./spec_helper"
require "compress/gzip"

describe EPSS::CSV do
  describe ".parse" do
    it "extracts metadata, header, and rows" do
      csv = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-1999-0001,0.00460,0.73850
        CVE-1999-0002,0.04525,0.92176
        CSV

      feed = EPSS::CSV.parse(csv)
      feed.metadata.model_version.should eq("v2025.03.14")
      feed.metadata.score_date.should_not be_nil
      feed.metadata.score_date.not_nil!.to_s("%Y-%m-%d").should eq("2026-05-18")

      feed.scores.size.should eq(2)
      first = feed.scores.first
      first.cve.should eq("CVE-1999-0001")
      first.epss.should be_close(0.00460, 1e-9)
      first.percentile.should be_close(0.73850, 1e-9)
      first.date.should eq(feed.metadata.score_date)
    end

    it "is Enumerable over scores" do
      csv = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-1,0.1,0.5
        CVE-2,0.2,0.6
        CSV

      feed = EPSS::CSV.parse(csv)
      feed.map(&.cve).should eq(["CVE-1", "CVE-2"])
      feed.size.should eq(2)
    end

    it "tolerates missing metadata header" do
      csv = "cve,epss,percentile\nCVE-1,0.1,0.5\n"
      feed = EPSS::CSV.parse(csv)
      feed.metadata.model_version.should be_nil
      feed.scores.first.cve.should eq("CVE-1")
      feed.scores.first.date.should be_nil
    end

    it "rejects CSVs missing required columns" do
      expect_raises(EPSS::ParseError, /required columns/) do
        EPSS::CSV.parse("cve,score\nCVE-1,0.1\n")
      end
    end

    it "accepts a Path pointing at a CSV file on disk" do
      csv = "cve,epss,percentile\nCVE-1,0.1,0.5\n"
      path = File.tempfile("epss-feed", ".csv") do |f|
        f.print csv
      end
      begin
        feed = EPSS::CSV.parse(Path.new(path.path))
        feed.scores.first.cve.should eq("CVE-1")
      ensure
        path.delete
      end
    end

    it "raises on a row that's shorter than the header" do
      csv = "cve,epss,percentile\nCVE-1,0.1\n"
      expect_raises(EPSS::ParseError, /columns/) do
        EPSS::CSV.parse(csv)
      end
    end

    # Regression: a caller-supplied IO is theirs to manage; parse must not
    # close it out from under them.
    it "does not close a caller-supplied IO" do
      io = IO::Memory.new("cve,epss,percentile\nCVE-1,0.1,0.5\n")
      EPSS::CSV.parse(io)
      io.closed?.should be_false
    end

    # Regression: parsing a Path opens (and must close) its own File, so the
    # same path can be parsed repeatedly without leaking file handles.
    it "closes its own File handle for a Path and can be re-parsed" do
      csv = "cve,epss,percentile\nCVE-1,0.1,0.5\n"
      path = File.tempfile("epss-feed", ".csv") do |f|
        f.print csv
      end
      begin
        first = EPSS::CSV.parse(Path.new(path.path))
        second = EPSS::CSV.parse(Path.new(path.path))
        first.scores.first.cve.should eq("CVE-1")
        second.scores.first.cve.should eq("CVE-1")
        first.scores.size.should eq(1)
      ensure
        path.delete
      end
    end

    it "reads model_version/score_date written with '=' separators" do
      csv = <<-CSV
        #model_version=v2025.03.14,score_date=2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-1,0.1,0.5
        CSV

      feed = EPSS::CSV.parse(csv)
      feed.metadata.model_version.should eq("v2025.03.14")
      feed.metadata.score_date.not_nil!.to_s("%Y-%m-%d").should eq("2026-05-18")
    end

    it "auto-detects gzip input" do
      raw = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-9,0.42,0.95
        CSV

      buffer = IO::Memory.new
      Compress::Gzip::Writer.open(buffer) do |gz|
        gz.print raw
      end
      buffer.rewind

      feed = EPSS::CSV.parse(buffer)
      feed.scores.size.should eq(1)
      feed.scores.first.cve.should eq("CVE-9")
      feed.scores.first.epss.should be_close(0.42, 1e-9)
    end

    # Regression: `EPSS::CSV.parse(File.read("...csv.gz"))` — the usage the
    # README documents — hands us a String full of NUL bytes. Probing the
    # filesystem with it used to raise `ArgumentError: String contains null
    # byte` before the content ever reached the gzip reader.
    it "parses a String holding raw gzip bytes" do
      raw = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-7,0.31,0.91
        CSV

      buffer = IO::Memory.new
      Compress::Gzip::Writer.open(buffer, &.print(raw))

      feed = EPSS::CSV.parse(String.new(buffer.to_slice))
      feed.metadata.model_version.should eq("v2025.03.14")
      feed.scores.map(&.cve).should eq(["CVE-7"])
    end

    # Regression: a corrupt feed must raise the library's own error type;
    # `Compress::Deflate::Error` / `IO::EOFError` used to leak straight out.
    it "raises ParseError on a truncated gzip stream" do
      buffer = IO::Memory.new
      Compress::Gzip::Writer.open(buffer) do |gz|
        gz.print "cve,epss,percentile\n"
        200.times { |i| gz.print "CVE-#{i},0.1,0.5\n" }
      end
      truncated = buffer.to_slice[0, buffer.size // 2]

      expect_raises(EPSS::ParseError, /gzip/) do
        EPSS::CSV.parse(IO::Memory.new(truncated))
      end
    end

    it "raises ParseError on a corrupt gzip header" do
      corrupt = IO::Memory.new(Bytes[0x1f, 0x8b, 0x08, 0x00, 0x41, 0x42, 0x43, 0x44])
      expect_raises(EPSS::ParseError, /gzip/) do
        EPSS::CSV.parse(corrupt)
      end
    end
  end

  describe ".feed_url" do
    it "builds the canonical empirical-security host URL by date" do
      uri = EPSS::CSV.feed_url(Time.utc(2026, 5, 18))
      uri.to_s.should eq("https://epss.empiricalsecurity.com/epss_scores-2026-05-18.csv.gz")
    end

    it "accepts a legacy host override" do
      uri = EPSS::CSV.feed_url(Time.utc(2026, 5, 18), host: "epss.cyentia.com")
      uri.host.should eq("epss.cyentia.com")
      uri.path.should eq("/epss_scores-2026-05-18.csv.gz")
    end
  end

  describe ".each_score" do
    it "streams without buffering" do
      csv = <<-CSV
        #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
        cve,epss,percentile
        CVE-1,0.1,0.5
        CVE-2,0.2,0.6
        CVE-3,0.3,0.7
        CSV

      seen = [] of String
      EPSS::CSV.each_score(IO::Memory.new(csv)) { |s| seen << s.cve }
      seen.should eq(["CVE-1", "CVE-2", "CVE-3"])
    end

    # Regression: streaming over a caller-supplied IO must not close it.
    it "does not close a caller-supplied IO" do
      io = IO::Memory.new("cve,epss,percentile\nCVE-1,0.1,0.5\n")
      EPSS::CSV.each_score(io) { |_| }
      io.closed?.should be_false
    end

    it "raises ParseError when streaming a truncated gzip stream" do
      buffer = IO::Memory.new
      Compress::Gzip::Writer.open(buffer) do |gz|
        gz.print "cve,epss,percentile\n"
        200.times { |i| gz.print "CVE-#{i},0.1,0.5\n" }
      end
      truncated = buffer.to_slice[0, buffer.size // 2]

      expect_raises(EPSS::ParseError, /gzip/) do
        EPSS::CSV.each_score(IO::Memory.new(truncated)) { |_| }
      end
    end

    # Regression: each_score opens (and must close) its own File for a Path
    # so it can be streamed repeatedly without leaking handles.
    it "closes its own File handle for a Path and can be re-streamed" do
      csv = "cve,epss,percentile\nCVE-1,0.1,0.5\n"
      path = File.tempfile("epss-feed", ".csv") do |f|
        f.print csv
      end
      begin
        seen = [] of String
        EPSS::CSV.each_score(Path.new(path.path)) { |s| seen << s.cve }
        EPSS::CSV.each_score(Path.new(path.path)) { |s| seen << s.cve }
        seen.should eq(["CVE-1", "CVE-1"])
      ensure
        path.delete
      end
    end
  end
end
