require "http/request"

module KrikriAwsSigner
  # Signs a Crystal `HTTP::Request` with AWS Signature Version 4, mutating the
  # request's headers the way AWS SDKs do:
  #
  # * `X-Amz-Security-Token` is set when the signer has a session token.
  # * `X-Amz-Date` is kept if already present (and must be in the
  #   `%Y%m%dT%H%M%SZ` format, or `ArgumentError` is raised); a plain `Date`
  #   header is dropped - its value is used only when it is itself a valid
  #   `X-Amz-Date` value, otherwise the signing time is used, like botocore.
  # * `X-Amz-Content-Sha256` is set to the body's SHA-256 unless *add_sha* is
  #   false or the header is already present.
  # * `Authorization` carries the signature over every request header except
  #   `Authorization` itself. The request must carry a `Host` header (every
  #   AWS service requires it to be signed), or `ArgumentError` is raised.
  #
  # A `Signer` caches its derived signing key per day, so signing many
  # requests does not repeat the four-step HMAC chain.
  #
  # ```
  # signer = KrikriAwsSigner::Signer.new("secretsmanager", "us-east-1", access_key, secret_key, session_token)
  # signer.sign(request)
  # ```
  class Signer
    DATE_FORMAT = "%Y%m%dT%H%M%SZ"

    def initialize(@service : String, @region : String, @access_key : String,
                   @secret_key : String, @session_token : String? = nil)
      @key_mutex = Mutex.new
      @cached_key_date = ""
      @cached_key = Bytes.empty
    end

    # Sign *request* in place. *at* is the signing time (defaults to now) and
    # is ignored when the request already carries an `X-Amz-Date`.
    def sign(request : HTTP::Request, add_sha : Bool = true, at time : Time = Time.utc) : Nil
      ensure_host!(request)
      apply_headers(request, add_sha, time)

      amz_date = request.headers["X-Amz-Date"]
      date = amz_date[0, 8]
      scope = Signature.credential_scope(date, @region, @service)
      path, query = split_target(request.resource)
      canonical_headers = Canonical.headers(request.headers)
      canonical = Canonical.request(request.method, path, query, canonical_headers, payload_hash(request))
      string_to_sign = Signature.string_to_sign(amz_date, scope, canonical)
      signature = OpenSSL::HMAC.hexdigest(:sha256, signing_key(date), string_to_sign)

      request.headers["Authorization"] =
        "#{ALGORITHM} Credential=#{@access_key}/#{scope}, " \
        "SignedHeaders=#{canonical_headers[1]}, Signature=#{signature}"
    end

    # The canonical request of *request* as `sign` would compute it (after
    # header setup). Pure: the request is not mutated.
    def canonical_request(request : HTTP::Request) : String
      ensure_host!(request)
      path, query = split_target(request.resource)
      Canonical.request(request.method, path, query, request.headers, payload_hash(request))
    end

    # The SHA-256 of the request body in hex, or the existing
    # `X-Amz-Content-Sha256` header when set.
    def payload_hash(request : HTTP::Request) : String
      if existing = request.headers["X-Amz-Content-Sha256"]?
        return existing
      end

      case body = request.body
      when Nil    then EMPTY_PAYLOAD_HASH
      when String then Digest::SHA256.hexdigest(body)
      when Bytes  then Digest::SHA256.hexdigest(body)
      else
        digest = Digest::SHA256.new
        buffer = Bytes.new(16_384)
        while (count = body.read(buffer)) > 0
          digest.update(buffer[0, count])
        end
        begin
          body.rewind
        rescue ex
          raise IO::Error.new(
            "Cannot sign request: body IO cannot be rewound after computing its SHA256 " \
            "digest. For non-seekable streaming IOs, set the X-Amz-Content-Sha256 header " \
            "explicitly (e.g. to UNSIGNED-PAYLOAD).", cause: ex)
        end
        digest.final.hexstring
      end
    end

    EMPTY_PAYLOAD_HASH = Digest::SHA256.hexdigest("")

    private def apply_headers(request : HTTP::Request, add_sha : Bool, time : Time) : Nil
      if token = @session_token
        request.headers["X-Amz-Security-Token"] = token
      end

      # AWS prefers X-Amz-Date; a plain Date header is dropped (like botocore,
      # which never signs it). Its value is reused for X-Amz-Date only when it
      # already is a valid X-Amz-Date value.
      if dates = request.headers.get?("Date")
        if dates.size > 1
          raise ArgumentError.new("Cannot sign request: multiple Date headers")
        end
        request.headers.delete("Date")
        request.headers["X-Amz-Date"] ||= dates.first if amz_date?(dates.first)
      end
      if existing = request.headers["X-Amz-Date"]?
        raise ArgumentError.new(
          "Cannot sign request: X-Amz-Date must be in #{DATE_FORMAT} format, " \
          "got #{existing.inspect}") unless amz_date?(existing)
      else
        request.headers["X-Amz-Date"] = time.to_utc.to_s(DATE_FORMAT)
      end

      if add_sha
        request.headers["X-Amz-Content-Sha256"] ||= payload_hash(request)
      end
    end

    # SigV4 signs every header present, and every AWS service requires a
    # signed Host header; a request without one would be signed fine but
    # rejected server-side with an opaque error.
    private def ensure_host!(request : HTTP::Request) : Nil
      return if request.headers["Host"]?
      raise ArgumentError.new(
        "Cannot sign request: no Host header present. Every AWS service requires " \
        "the Host header to be signed; set it before calling sign (for an " \
        "absolute-form request target, the URI's host).")
    end

    # Whether *value* is a well-formed `%Y%m%dT%H%M%SZ` timestamp.
    private def amz_date?(value : String) : Bool
      return false unless value.bytesize == 16
      return false unless value.byte_at(8) == 'T'.ord && value.byte_at(15) == 'Z'.ord
      (0...8).all? { |i| digit?(value.byte_at(i)) } &&
        (9...15).all? { |i| digit?(value.byte_at(i)) }
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

    # Split a request target into its decoded path and raw query string.
    # Handles both origin-form (`/path?query`) and absolute-form
    # (`https://host/path?query`) targets.
    private def split_target(resource : String) : {String, String}
      if resource.starts_with?("http://") || resource.starts_with?("https://")
        uri = URI.parse(resource)
        {uri.path, uri.query || ""}
      else
        path, _, query = resource.partition('?')
        {path, query}
      end
    end
  end
end
