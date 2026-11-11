require "http/request"

module KrikriAwsSigner
  # Signs a Crystal `HTTP::Request` with AWS Signature Version 4, mutating the
  # request's headers the way AWS SDKs do:
  #
  # * `X-Amz-Security-Token` is set when the signer has a session token.
  # * A `Date` header is dropped in favor of `X-Amz-Date` (which is kept if
  #   already present, otherwise set to the signing time).
  # * `X-Amz-Content-Sha256` is set to the body's SHA-256 unless *add_sha* is
  #   false or the header is already present.
  # * `Authorization` carries the signature over every request header except
  #   `Authorization` itself.
  #
  # ```
  # signer = KrikriAwsSigner::Signer.new("secretsmanager", "us-east-1", access_key, secret_key, session_token)
  # signer.sign(request)
  # ```
  class Signer
    DATE_FORMAT = "%Y%m%dT%H%M%SZ"

    def initialize(@service : String, @region : String, @access_key : String,
                   @secret_key : String, @session_token : String? = nil)
    end

    # Sign *request* in place. *at* is the signing time (defaults to now) and
    # is ignored when the request already carries an `X-Amz-Date`.
    def sign(request : HTTP::Request, add_sha : Bool = true, at time : Time = Time.utc) : Nil
      apply_headers(request, add_sha, time)

      amz_date = request.headers["X-Amz-Date"]
      date = amz_date[0, 8]
      scope = Signature.credential_scope(date, @region, @service)
      canonical = canonical_request(request)
      string_to_sign = Signature.string_to_sign(amz_date, scope, canonical)
      signature = Signature.signature(@secret_key, date, @region, @service, string_to_sign)

      _, signed_headers = Canonical.headers(request.headers)
      request.headers["Authorization"] =
        "#{ALGORITHM} Credential=#{@access_key}/#{scope}, " \
        "SignedHeaders=#{signed_headers}, Signature=#{signature}"
    end

    # The canonical request of *request* as `sign` would compute it (after
    # header setup). Pure: the request is not mutated.
    def canonical_request(request : HTTP::Request) : String
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
        begin
          while (count = body.read(buffer)) > 0
            digest.update(buffer[0, count])
          end
          body.rewind
        rescue
          raise ArgumentError.new(
            "Cannot sign request: body IO cannot be rewound after computing its SHA256 " \
            "digest. For non-seekable streaming IOs, set the X-Amz-Content-Sha256 header " \
            "explicitly (e.g. to UNSIGNED-PAYLOAD).")
        end
        digest.final.hexstring
      end
    end

    EMPTY_PAYLOAD_HASH = Digest::SHA256.hexdigest("")

    private def apply_headers(request : HTTP::Request, add_sha : Bool, time : Time) : Nil
      if token = @session_token
        request.headers["X-Amz-Security-Token"] = token
      end

      # AWS prefers X-Amz-Date; a plain Date header is folded into it.
      if date = request.headers.delete("Date")
        request.headers["X-Amz-Date"] ||= date
      else
        request.headers["X-Amz-Date"] ||= time.to_utc.to_s(DATE_FORMAT)
      end

      if add_sha
        request.headers["X-Amz-Content-Sha256"] ||= payload_hash(request)
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
