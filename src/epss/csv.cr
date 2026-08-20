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
      source = open_io(input)
      gzipped = gzip?(source)
      begin
        translate_gzip_errors(gzipped) do
          # Constructed inside the translation block: the reader validates
          # the gzip header eagerly, so a corrupt one raises right here.
          io = gzipped ? Compress::Gzip::Reader.new(source) : source
          metadata = Metadata.new
          scores = [] of Score
          each_score_from(io) do |score, meta|
            metadata = meta if meta
            scores << score
          end
          Feed.new(metadata, scores)
        end
      ensure
        # Only close handles we opened ourselves; a caller-supplied IO is
        # theirs to manage. `open_io` returns a fresh `File`/`IO::Memory`
        # for `Path`/`String` inputs but passes any `IO` straight through.
        source.close unless input.is_a?(IO)
      end
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
      source = open_io(input)
      gzipped = gzip?(source)
      begin
        translate_gzip_errors(gzipped) do
          # See `parse`: the reader must be built inside the translation
          # block so a corrupt gzip header surfaces as `ParseError`.
          io = gzipped ? Compress::Gzip::Reader.new(source) : source
          each_score_from(io) { |score, _| yield score }
        end
      ensure
        # See `parse`: close only what we opened, never the caller's IO.
        source.close unless input.is_a?(IO)
      end
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

    # Decompression failures on a truncated or corrupt gzip stream surface as
    # `Compress::*::Error` / `IO::EOFError`. Translate them into the library's
    # own `ParseError` so a caller only ever has to rescue `EPSS::Error`.
    # Plain (non-gzip) input re-raises untouched — those exceptions come from
    # the caller's IO or block, not from our decompressor.
    private def translate_gzip_errors(gzipped : Bool, &)
      yield
    rescue ex : Compress::Gzip::Error | Compress::Deflate::Error | IO::EOFError
      raise ex unless gzipped
      raise ParseError.new("corrupt gzip stream: #{ex.message}", cause: ex)
    end

    # Peek two bytes to detect the gzip magic without consuming them. IOs
    # that don't support `peek` (e.g. plain sockets) fall back to no gzip.
    private def gzip?(io : IO) : Bool
      return false if io.is_a?(Compress::Gzip::Reader)
      peeked = io.peek
      return false if peeked.nil?
      peeked.size >= 2 && peeked[0] == 0x1f && peeked[1] == 0x8b
    end

    # The published feed separates key and value with `:`, but mirrors and
    # older archives of the same file use `=`. Accept either.
    private METADATA_RE = /score_date[:=]([^,\s]+)/
    private MODEL_RE    = /model_version[:=]([^,\s]+)/

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
          cve_idx = headers.index!("cve")
          epss_idx = headers.index!("epss")
          percentile_idx = headers.index!("percentile")
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
      return if value.nil? || value.empty?
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
