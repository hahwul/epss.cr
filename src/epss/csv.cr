require "csv"
require "compress/gzip"
require "http/client"
require "./score"

module EPSS
  # Parser for the public EPSS daily feed published at
  # `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`
  # (the prior host `https://epss.cyentia.com/...` still mirrors the same
  # file and is accepted by `CSV.feed_url(..., host: ...)`).
  #
  # Format (verbatim, leading `#` line, then a header row, then rows):
  #
  # ```text
  # #model_version:v2025.03.14,score_date:2026-05-18T00:00:00+0000
  # cve,epss,percentile
  # CVE-1999-0001,0.0046,0.7385
  # CVE-1999-0002,0.0452,0.9217
  # ...
  # ```
  #
  # The `#` line is a single metadata comment carrying the model version
  # and the publication timestamp. `CSV.parse` extracts both into a
  # `Metadata` struct and stamps every `Score` row's `date` with the
  # feed's `score_date`.
  module CSV
    extend self

    # Canonical host that publishes the gzipped daily EPSS feed.
    FEED_HOST = "epss.empiricalsecurity.com"

    # Build the canonical feed URL for a given UTC date. The FIRST EPSS
    # team publishes one file per day at this exact path; both the new
    # `empiricalsecurity.com` host and the legacy `cyentia.com` host
    # serve identical content.
    #
    # ```
    # EPSS::CSV.feed_url(Time.utc(2026, 5, 18))
    # # => URI("https://epss.empiricalsecurity.com/epss_scores-2026-05-18.csv.gz")
    # ```
    def feed_url(date : Time, *, host : String = FEED_HOST) : URI
      URI.parse("https://#{host}/epss_scores-#{date.to_s("%Y-%m-%d")}.csv.gz")
    end

    # Download and parse the daily feed for `date` in one shot. Streams
    # the gzipped body through `Compress::Gzip::Reader` so the full
    # 240k+ row file never lands in memory.
    #
    # ```
    # feed = EPSS::CSV.fetch(Time.utc(2026, 5, 18))
    # feed.scores.size # => 240000+
    # ```
    def fetch(date : Time, *, host : String = FEED_HOST) : Feed
      uri = feed_url(date, host: host)
      response = HTTP::Client.get(uri)
      unless response.status_code == 200
        raise APIError.new(
          "EPSS feed download failed: HTTP #{response.status_code}",
          status: response.status_code,
          body: response.body,
        )
      end
      parse(IO::Memory.new(response.body))
    end

    # Metadata pulled from the leading `#` header of an EPSS feed file.
    struct Metadata
      getter model_version : String?
      getter score_date : Time?

      def initialize(@model_version : String? = nil, @score_date : Time? = nil)
      end
    end

    # Parsed result of an EPSS feed file: the leading metadata and the
    # full list of `Score` rows. Iterating row-by-row is also available via
    # `CSV.each_score`.
    struct Feed
      include Enumerable(Score)

      getter metadata : Metadata
      getter scores : Array(Score)

      def initialize(@metadata : Metadata, @scores : Array(Score))
      end

      delegate :each, :size, :[], to: @scores
    end

    # Parse an entire EPSS feed from a string, IO, or path. Gzip-compressed
    # input is auto-detected by the magic bytes `1f 8b`.
    def parse(input : String | IO | Path) : Feed
      io = open_io(input)
      io = Compress::Gzip::Reader.new(io) if gzip?(io)

      metadata = Metadata.new
      scores = [] of Score
      each_score_from(io) do |score, meta|
        metadata = meta if meta
        scores << score
      end
      Feed.new(metadata, scores)
    end

    # Yield each `Score` without buffering the whole feed in memory. Useful
    # for the full daily file (200k+ rows).
    #
    # ```
    # File.open("epss_scores-2026-05-18.csv.gz") do |raw|
    #   EPSS::CSV.each_score(raw) do |score|
    #     index[score.cve] = score
    #   end
    # end
    # ```
    def each_score(input : String | IO | Path, & : Score ->) : Nil
      io = open_io(input)
      io = Compress::Gzip::Reader.new(io) if gzip?(io)
      each_score_from(io) { |score, _| yield score }
    end

    private def open_io(input : String | IO | Path) : IO
      case input
      when IO   then input
      when Path then File.open(input)
      when String
        # Treat as raw CSV content unless it points at an existing file.
        if File.file?(input)
          File.open(input)
        else
          IO::Memory.new(input)
        end
      else
        raise ArgumentError.new("unsupported input #{input.class}")
      end
    end

    # Peek two bytes to detect the gzip magic without consuming them. IOs
    # that don't support `peek` (e.g. plain sockets) fall back to no gzip.
    private def gzip?(io : IO) : Bool
      return false if io.is_a?(Compress::Gzip::Reader)
      peeked = io.peek
      return false if peeked.nil?
      peeked.size >= 2 && peeked[0] == 0x1f && peeked[1] == 0x8b
    end

    private METADATA_RE = /score_date:([^,\s]+)/
    private MODEL_RE    = /model_version:([^,\s]+)/

    private BOM = "\xEF\xBB\xBF"

    private def each_score_from(io : IO, & : Score, Metadata? ->) : Nil
      metadata : Metadata? = nil
      cve_idx = -1
      epss_idx = -1
      percentile_idx = -1
      date_idx = -1
      saw_header = false
      first = true

      io.each_line do |raw_line|
        line = raw_line.chomp
        if first
          line = line.lchop(BOM)
          first = false
        end
        next if line.empty?

        # Only the first leading `#` line is the feed header. The format
        # never embeds further `#` lines, but we keep accepting them as
        # metadata for forward compatibility.
        if line.starts_with?('#')
          metadata = parse_metadata(line)
          next
        end

        unless saw_header
          headers = line.split(',').map(&.strip.downcase)
          validate_headers(headers)
          cve_idx = headers.index("cve").not_nil!
          epss_idx = headers.index("epss").not_nil!
          percentile_idx = headers.index("percentile").not_nil!
          date_idx = headers.index("date") || -1
          saw_header = true
          next
        end

        # Feed rows are simple comma-separated triples with no quoting.
        # `split(',')` is ~5x faster than ::CSV.parse for the 240k-row
        # daily feed and produces identical output for the published
        # format. If FIRST ever starts quoting values, switch back to
        # ::CSV.parse_row here.
        cells = line.split(',')
        next if cells.empty?

        max_required = {cve_idx, epss_idx, percentile_idx}.max
        if cells.size <= max_required
          raise ParseError.new("CSV row has #{cells.size} columns, expected at least #{max_required + 1}: '#{line}'")
        end

        date_val : String? = (date_idx >= 0 && date_idx < cells.size) ? cells[date_idx] : nil
        score = Score.from_row(
          cve: cells[cve_idx],
          epss: cells[epss_idx],
          percentile: cells[percentile_idx],
          date: date_val.presence || metadata.try(&.score_date),
        )
        yield score, metadata
      end
    end

    private def validate_headers(headers : Array(String)) : Nil
      missing = {"cve", "epss", "percentile"}.reject { |h| headers.includes?(h) }
      raise ParseError.new("CSV missing required columns: #{missing.join(", ")}") unless missing.empty?
    end

    private def parse_metadata(line : String) : Metadata
      body = line.lchop('#').strip
      model = MODEL_RE.match(body).try &.[1]
      date_str = METADATA_RE.match(body).try &.[1]
      score_date = parse_metadata_date(date_str)
      Metadata.new(model_version: model, score_date: score_date)
    end

    private def parse_metadata_date(value : String?) : Time?
      return nil if value.nil? || value.empty?
      str = value
      # The feed emits an ISO-8601 timestamp like "2026-05-18T00:00:00+0000".
      begin
        return Time.parse_rfc3339(str)
      rescue Time::Format::Error
      end
      begin
        return Time.parse(str, "%Y-%m-%dT%H:%M:%S%z", Time::Location::UTC)
      rescue Time::Format::Error
      end
      nil
    end
  end
end
