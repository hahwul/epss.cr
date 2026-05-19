module EPSS
  # Base class for every error raised by this shard. Catch this to handle
  # any EPSS-related failure without coupling to specific subclasses.
  class Error < Exception
  end

  # Raised when an EPSS payload (JSON, CSV row, or constructor argument)
  # is structurally malformed or contains a value outside its allowed range.
  class ParseError < Error
  end

  # Raised when the FIRST EPSS API responds with a non-2xx status, or when
  # the JSON envelope reports `status` != "OK".
  class APIError < Error
    getter status : Int32?
    getter body : String?

    def initialize(message : String, @status : Int32? = nil, @body : String? = nil, cause : Exception? = nil)
      super(message, cause)
    end
  end
end
