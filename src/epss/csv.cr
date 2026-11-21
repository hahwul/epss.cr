require "csv"
require "compress/gzip"
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
  # calendar day (UTC midnight) of the feed's `score_date`.
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

    # The stable URL for the most recently published feed.
    def feed_url(*, host : String = FEED_HOST) : URI
      URI.parse("https://#{host}/epss_scores-current.csv.gz")
    end

    # Download and parse the daily feed for `date`. Delegates to
    # `EPSS.client.fetch_feed`, which routes the request through the
    # client's transport, retry, and timeout pipeline. To inject a stub
    # transport or use a non-default base, call `client.fetch_feed`
    # directly.
    #
    # ```
    # feed = EPSS::CSV.fetch(Time.utc(2026, 5, 18))
    # feed.scores.size # => 240000+
    # ```
    def fetch(date : Time, *, host : String = FEED_HOST) : Feed
      EPSS.client.fetch_feed(date, host: host)
    end

    # Download the most recently published feed.
    def fetch(*, host : String = FEED_HOST) : Feed
      EPSS.client.fetch_feed(host: host)
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
    #
    # `date` is the day stamped onto rows when the feed itself carries no
    # `score_date` (feeds before 2022-02-04 have no `#` metadata line).
    # A `score_date` in the file, or a `date` column, always wins.
    # `Feed#metadata` still reports only what the file says.
    def parse(input : String | IO | Path, *, date : Time? = nil) : Feed
      scores = [] of Score
      metadata = read_feed(input, date) { |score| scores << score }
      Feed.new(metadata || Metadata.new, scores)
    end

    # Yield each `Score` as it is read from a daily feed. Early feeds with
    # only `cve,epss` are buffered to compute percentiles across all rows.
    #
    # ```
    # File.open("epss_scores-2026-05-18.csv.gz") do |raw|
    #   EPSS::CSV.each_score(raw) do |score|
    #     index[score.cve] = score
    #   end
    # end
    # ```
    #
    # `date` is the fallback row date, as for `parse`.
    def each_score(input : String | IO | Path, *, date : Time? = nil, & : Score ->) : Nil
      read_feed(input, date) { |score| yield score }
    end

    private def read_feed(input : String | IO | Path, date : Time?, & : Score ->) : Metadata?
      source = open_io(input)
      io = feed_input(source)
      each_score_from(io, date) { |score| yield score }
    ensure
      # An internally created gzip reader leaves its underlying IO open.
      io.close if io.is_a?(FeedGzipReader) && !io.same?(source)
      source.try(&.close) unless input.is_a?(IO)
    end

    private def open_io(input : String | IO | Path) : IO
      case input
      when IO   then input
      when Path then File.open(input)
      when String
        # Treat as raw CSV content unless it points at an existing file.
        if path_like?(input) && File.file?(input)
          File.open(input)
        else
          IO::Memory.new(input)
        end
      else
        raise ArgumentError.new("unsupported input #{input.class}")
      end
    end

    # `File.file?` raises `ArgumentError` for a string containing a NUL byte,
    # which is exactly what `File.read("epss_scores-....csv.gz")` hands us —
    # every gzip header carries a NUL in its flag byte. Screen out values that
    # cannot possibly be a filesystem path before touching the filesystem, so
    # feed *content* is never mistaken for a path probe.
    private def path_like?(value : String) : Bool
      return false if value.empty?
      # Longer than PATH_MAX on every supported platform: it is content.
      return false if value.bytesize > 4096
      # gzip magic — binary payload, not a path.
      return false if value.byte_at?(0) == 0x1f_u8 && value.byte_at?(1) == 0x8b_u8
      value.each_char do |char|
        return false if char == '\0' || char == '\n' || char == '\r'
      end
      true
    end

    # Translate errors only while opening or reading gzip data. The row
    # callback runs outside the reader and keeps its own exceptions.
    private class FeedGzipReader < Compress::Gzip::Reader
      def initialize(io : IO)
        super(io)
      rescue ex : Compress::Gzip::Error | Compress::Deflate::Error | IO::EOFError
        raise ParseError.new("corrupt gzip stream: #{ex.message}", cause: ex)
      end

      def unbuffered_read(slice : Bytes) : Int32
        super(slice)
      rescue ex : Compress::Gzip::Error | Compress::Deflate::Error | IO::EOFError
        raise ParseError.new("corrupt gzip stream: #{ex.message}", cause: ex)
      end
    end

    # Replay the bytes consumed while detecting gzip on streams whose peek
    # is unavailable or ends at a chunk boundary.
    private class PrefixedInput < IO
      def initialize(@source : IO, @prefix : Bytes)
      end

      def read(slice : Bytes) : Int32
        return @source.read(slice) if @prefix.empty?

        count = Math.min(@prefix.size, slice.size)
        slice.copy_from(@prefix[0, count])
        @prefix += count
        count
      end

      def peek : Bytes?
        @prefix.empty? ? @source.peek : @prefix
      end

      def write(slice : Bytes) : NoReturn
        raise IO::Error.new("CSV input is read-only")
      end
    end

    private def feed_input(source : IO) : IO
      return source if source.is_a?(Compress::Gzip::Reader)

      prefix = source.peek
      if prefix.nil? || prefix.size < 2
        buffer = Bytes.new(2)
        prefix = buffer[0, source.read_greedy(buffer)]
        source = PrefixedInput.new(source, prefix)
      end
      prefix.size >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b ? FeedGzipReader.new(source) : source
    end

    # The published feed separates key and value with `:`, but mirrors and
    # older archives of the same file use `=`. Accept either.
    private METADATA_RE = /score_date[:=]([^,\s]+)/
    private MODEL_RE    = /model_version[:=]([^,\s]+)/

    private BOM = "\xEF\xBB\xBF"

    # Returns the metadata in force at the last row (a `#` line after the
    # rows is ignored), or the last `#` line when the feed has no rows.
    private def each_score_from(io : IO, fallback : Time?, & : Score ->) : Metadata?
      metadata : Metadata? = nil
      row_metadata : Metadata? = nil
      any_row = false
      # The calendar day as given (not shifted to UTC), so it names the
      # same day `feed_url` put in the file name.
      fallback_day = fallback.try { |d| Time.utc(d.year, d.month, d.day) }
      feed_date = fallback_day
      cve_idx = -1
      epss_idx = -1
      percentile_idx : Int32? = nil
      legacy_scores : Array(Score)? = nil
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
          # `score_date` is a timestamp (v2025+ feeds carry the publish time,
          # e.g. `T12:55:00Z`), but `Score#date` is a calendar day — the
          # same value the API returns as `"date": "YYYY-MM-DD"`. Stamp rows
          # with the day so a feed row equals the API row for that day.
          feed_date = metadata.score_date.try(&.to_utc.at_beginning_of_day) || fallback_day
          next
        end

        unless saw_header
          headers = line.split(',').map(&.strip.downcase)
          validate_headers(headers)
          cve_idx = headers.index!("cve")
          epss_idx = headers.index!("epss")
          percentile_idx = headers.index("percentile")
          legacy_scores = [] of Score unless percentile_idx
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

        max_required = {cve_idx, epss_idx, percentile_idx || -1}.max
        if cells.size <= max_required
          raise ParseError.new("CSV row has #{cells.size} columns, expected at least #{max_required + 1}: '#{line}'")
        end

        date_val : String? = (date_idx >= 0 && date_idx < cells.size) ? cells[date_idx] : nil
        score = Score.from_row(
          cve: cells[cve_idx],
          epss: cells[epss_idx],
          # Legacy rows are buffered with a placeholder. Only ranked scores
          # are returned to callers.
          percentile: percentile_idx ? cells[percentile_idx] : 0.0,
          date: date_val.presence || feed_date,
        )
        any_row = true
        row_metadata = metadata
        if legacy = legacy_scores
          legacy << score
        else
          yield score
        end
      end
      raise ParseError.new("CSV missing header row") unless saw_header
      if legacy = legacy_scores
        each_ranked_score(legacy) { |score| yield score }
      end
      any_row ? row_metadata : metadata
    end

    private def each_ranked_score(scores : Array(Score), & : Score ->) : Nil
      counts = scores.tally_by(&.epss)
      percentiles = {} of Float64 => Float64
      count_at_or_below = 0
      counts.keys.sort!.each do |epss|
        count_at_or_below += counts[epss]
        percentiles[epss] = count_at_or_below / scores.size
      end
      scores.each do |score|
        yield Score.new(score.cve, score.epss, percentiles[score.epss], score.date)
      end
    end

    private def validate_headers(headers : Array(String)) : Nil
      required = headers.size == 2 ? {"cve", "epss"} : {"cve", "epss", "percentile"}
      missing = required.reject { |h| headers.includes?(h) }
      raise ParseError.new("CSV missing required columns: #{missing.join(", ")}") unless missing.empty?
    end

    private def parse_metadata(line : String) : Metadata
      # Scrubbed: `Regex#match` raises `ArgumentError` on invalid UTF-8.
      body = line.lchop('#').strip.scrub
      model = MODEL_RE.match(body).try &.[1]
      date_str = METADATA_RE.match(body).try &.[1]
      score_date = parse_metadata_date(date_str)
      Metadata.new(model_version: model, score_date: score_date)
    end

    private def parse_metadata_date(value : String?) : Time?
      return if value.nil? || value.empty?
      str = value
      # The feed emits an ISO-8601 timestamp like "2026-05-18T00:00:00+0000".
      # A well-formed but impossible value (`2026-02-30`, hour 25) raises
      # `ArgumentError` rather than `Time::Format::Error`.
      begin
        return Time.parse_rfc3339(str)
      rescue Time::Format::Error | ArgumentError
      end
      begin
        return Time.parse(str, "%Y-%m-%dT%H:%M:%S%z", Time::Location::UTC)
      rescue Time::Format::Error | ArgumentError
      end
      nil
    end
  end
end
