require "http/request"

module KrikriAwsSigner
  # Signs a Crystal `HTTP::Request` with AWS Signature Version 4, mutating the
  # request's headers the way AWS SDKs do:
  #
  # * `X-Amz-Security-Token` is set when the signer has a session token.
  # * `X-Amz-Date` is kept if already present (and must be a well-formed
  #   `%Y%m%dT%H%M%SZ` timestamp, or `ArgumentError` is raised); a plain `Date`
  #   header is dropped - its value is reused for `X-Amz-Date` only when it
  #   already is such a timestamp, otherwise the signing time is used.
  #   (botocore instead rewrites `Date` to RFC 822 and always overwrites
  #   `X-Amz-Date` with the signing time, so a caller relying on its own
  #   timestamp must set `X-Amz-Date` here.)
  # * `X-Amz-Content-Sha256` is set to the body's SHA-256 unless *add_sha* is
  #   false or the header is already present.
  # * `Authorization` carries the signature over every request header except the
  #   ones in `Canonical::DEFAULT_EXCLUDE` (`Authorization` itself, plus the
  #   headers the AWS SDKs never sign: `Expect`, `Transfer-Encoding`,
  #   `User-Agent`, `X-Amzn-Trace-Id`). The request must carry a non-empty
  #   `Host` header (every AWS service requires it to be signed), or
  #   `ArgumentError` is raised.
  #
  # A `Signer` caches its derived signing key per day, so signing many requests
  # does not repeat the four-step HMAC chain. The cache is mutex-protected: one
  # `Signer` can be shared across fibers and threads.
  #
  # ```
  # signer = KrikriAwsSigner::Signer.new("secretsmanager", "us-east-1", access_key, secret_key, session_token)
  # signer.sign(request)
  # ```
  class Signer
    DATE_FORMAT = "%Y%m%dT%H%M%SZ"

    # Service-specific signing flavors.
    #
    # * `Standard` is SigV4 for every service but S3: the canonical URI is the
    #   request path with dot segments removed and empty segments collapsed.
    # * `S3` signs the request path verbatim, which is what S3 requires (and what
    #   `botocore.auth.S3SigV4Auth` does) - otherwise a key containing `..` or
    #   `//` would be signed as a different object than the one addressed.
    enum Flavor
      Standard
      S3
    end

    # Matches an absolute-form request target (`https://host/path`); URI schemes
    # are case-insensitive, so the check cannot be a `starts_with?`.
    ABSOLUTE_FORM = %r{\A[A-Za-z][A-Za-z0-9+.\-]*://}

    PAYLOAD_BUFFER_SIZE = 16_384

    def initialize(@service : String, @region : String, @access_key : String,
                   @secret_key : String, @session_token : String? = nil,
                   @flavor : Flavor = Flavor::Standard)
      raise ArgumentError.new("Cannot sign requests: service must not be empty") if @service.empty?
      raise ArgumentError.new("Cannot sign requests: region must not be empty") if @region.empty?
      raise ArgumentError.new("Cannot sign requests: service must not contain '/'") if @service.includes?('/')
      raise ArgumentError.new("Cannot sign requests: region must not contain '/'") if @region.includes?('/')
      @key_mutex = Mutex.new
      @cached_key_date = ""
      @cached_key = Bytes.empty
    end

    # Sign *request* in place. *at* is the signing time (defaults to now) and is
    # ignored when the request already carries an `X-Amz-Date`. *exclude* adds
    # header names to `Canonical::DEFAULT_EXCLUDE` (case-insensitive).
    def sign(request : HTTP::Request, add_sha : Bool = true, at time : Time = Time.utc,
             exclude : Enumerable(String)? = nil) : Nil
      ensure_host!(request)
      apply_headers(request, add_sha, time)

      amz_date = request.headers["X-Amz-Date"]
      date = amz_date[0, 8]
      scope = Signature.credential_scope(date, @region, @service)
      path, query = split_target(request.resource)
      canonical_headers = Canonical.headers(request.headers, exclusions(exclude))
      canonical = Canonical.request(request.method, path, query, canonical_headers,
        payload_hash(request), normalize_path: @flavor.standard?)
      string_to_sign = Signature.string_to_sign(amz_date, scope, canonical)
      signature = Signature.sign(signing_key(date), string_to_sign)

      request.headers["Authorization"] = String.build(capacity: 128) do |io|
        io << ALGORITHM << " Credential=" << @access_key << '/' << scope
        io << ", SignedHeaders=" << canonical_headers[1] << ", Signature=" << signature
      end
    end

    # The canonical request of *request*, without applying any header setup: no
    # `X-Amz-Date`, `X-Amz-Security-Token` or `X-Amz-Content-Sha256` is added, so
    # the signed-headers list is the request's current one. The request is not
    # mutated, but an IO body is read and left rewound. *exclude* adds header
    # names to `Canonical::DEFAULT_EXCLUDE` (case-insensitive).
    def canonical_request(request : HTTP::Request, exclude : Enumerable(String)? = nil) : String
      ensure_host!(request)
      path, query = split_target(request.resource)
      Canonical.request(request.method, path, query, request.headers, payload_hash(request),
        exclusions(exclude), normalize_path: @flavor.standard?)
    end

    # The SHA-256 of the request body in hex, or the existing
    # `X-Amz-Content-Sha256` header when set. An IO body is rewound to its start
    # before and after hashing, so the digest always covers the bytes the request
    # will send, whatever position the caller left the IO at.
    def payload_hash(request : HTTP::Request) : String
      if existing = request.headers.get?("X-Amz-Content-Sha256")
        if existing.size > 1
          raise ArgumentError.new("Cannot sign request: multiple X-Amz-Content-Sha256 headers")
        end
        return existing.first
      end

      case body = request.body
      when Nil    then EMPTY_PAYLOAD_HASH
      when String then Digest::SHA256.hexdigest(body)
      when Bytes  then Digest::SHA256.hexdigest(body)
      else
        digest_body(body)
      end
    end

    EMPTY_PAYLOAD_HASH = Digest::SHA256.hexdigest("")

    private def digest_body(body : IO) : String
      rewind_body(body)
      digest = Digest::SHA256.new
      buffer = Bytes.new(PAYLOAD_BUFFER_SIZE)
      begin
        while (count = body.read(buffer)) > 0
          digest.update(buffer[0, count])
        end
      ensure
        rewind_body(body)
      end
      digest.final.hexstring
    end

    private def rewind_body(body : IO) : Nil
      body.rewind
    rescue ex : IO::Error
      raise IO::Error.new(
        "Cannot sign request: body IO cannot be rewound after computing its SHA256 " \
        "digest. For non-seekable streaming IOs, set the X-Amz-Content-Sha256 header " \
        "explicitly (e.g. to UNSIGNED-PAYLOAD).", cause: ex)
    end

    private def apply_headers(request : HTTP::Request, add_sha : Bool, time : Time) : Nil
      if token = @session_token
        request.headers["X-Amz-Security-Token"] = token
      end

      # AWS prefers X-Amz-Date; a plain Date header is dropped. Its value is
      # reused for X-Amz-Date only when it already is a valid X-Amz-Date value,
      # in which case that value - not *time* - is what gets signed.
      if dates = request.headers.get?("Date")
        if dates.size > 1
          raise ArgumentError.new("Cannot sign request: multiple Date headers")
        end
        date_header = dates.first
        request.headers.delete("Date")
        request.headers["X-Amz-Date"] ||= date_header if amz_date?(date_header)
      end

      case amz_dates = request.headers.get?("X-Amz-Date")
      when Nil
        request.headers["X-Amz-Date"] = time.to_utc.to_s(DATE_FORMAT)
      else
        if amz_dates.size > 1
          raise ArgumentError.new("Cannot sign request: multiple X-Amz-Date headers")
        end
        existing = amz_dates.first
        raise ArgumentError.new(
          "Cannot sign request: X-Amz-Date must be in #{DATE_FORMAT} format, " \
          "got #{existing.inspect}") unless amz_date?(existing)
      end

      if add_sha
        request.headers["X-Amz-Content-Sha256"] ||= payload_hash(request)
      end
    end

    # SigV4 signs every header present, and every AWS service requires a signed
    # Host header; a request without one would be signed fine but rejected
    # server-side with an opaque error.
    private def ensure_host!(request : HTTP::Request) : Nil
      if host = request.headers["Host"]?
        return unless host.strip.empty?
      end
      raise ArgumentError.new(
        "Cannot sign request: the Host header is missing or empty. Every AWS service " \
        "requires the Host header to be signed; set it before calling sign (for an " \
        "absolute-form request target, the URI's host).")
    end

    # Whether *value* is a well-formed `%Y%m%dT%H%M%SZ` timestamp with
    # in-range month/day/hour/minute/second fields.
    private def amz_date?(value : String) : Bool
      return false unless value.bytesize == 16
      return false unless value.byte_at(8) == 'T'.ord && value.byte_at(15) == 'Z'.ord
      return false unless (0...8).all? { |index| digit?(value.byte_at(index)) }
      return false unless (9...15).all? { |index| digit?(value.byte_at(index)) }

      month = number_at(value, 4, 2)
      day = number_at(value, 6, 2)
      hour = number_at(value, 9, 2)
      minute = number_at(value, 11, 2)
      second = number_at(value, 13, 2)
      return false unless 1 <= month <= 12
      return false unless 1 <= day <= DAYS_PER_MONTH[month]
      hour <= 23 && minute <= 59 && second <= 59
    end

    # Days per month, February being given its leap-year maximum.
    private DAYS_PER_MONTH = {0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

    private def number_at(value : String, offset : Int32, length : Int32) : Int32
      result = 0
      length.times { |index| result = result * 10 + value.byte_at(offset + index) - '0'.ord }
      result
    end

    private def digit?(byte : UInt8) : Bool
      byte >= '0'.ord && byte <= '9'.ord
    end

    # The day-scoped signing key, cached per date: the four-step HMAC chain
    # only has to run once per day per signer.
    private def signing_key(date : String) : Bytes
      @key_mutex.synchronize do
        return @cached_key if date == @cached_key_date
        key = Signature.signing_key(@secret_key, date, @region, @service)
        @cached_key_date = date
        @cached_key = key
        key
      end
    end

    private def exclusions(extra : Enumerable(String)?) : Enumerable(String)
      return Canonical::DEFAULT_EXCLUDE if extra.nil?
      Canonical::DEFAULT_EXCLUDE.to_a + extra.map(&.downcase)
    end

    # Split a request target into its path and raw query string. Handles both
    # origin-form (`/path?query`) and absolute-form (`https://host/path?query`)
    # targets, coercing a relative path to the absolute form SigV4 requires.
    private def split_target(resource : String) : {String, String}
      if resource.matches?(ABSOLUTE_FORM)
        uri = URI.parse(resource)
        {absolute_path(uri.path), uri.query || ""}
      else
        path, _, query = resource.partition('?')
        {absolute_path(path), query}
      end
    end

    private def absolute_path(path : String) : String
      return "/" if path.empty?
      path.starts_with?('/') ? path : "/#{path}"
    end
  end
end
