require "digest"
require "openssl/hmac"

module KrikriAwsSigner
  # The HMAC-SHA256 chain of the Signature Version 4 signing process:
  # canonical request -> string to sign -> signing key -> signature.
  module Signature
    extend self

    # `date/region/service/aws4_request`
    def credential_scope(date : String, region : String, service : String) : String
      "#{date}/#{region}/#{service}/aws4_request"
    end

    # The "String to Sign".
    def string_to_sign(amz_date : String, scope : String, canonical_request : String) : String
      String.build do |io|
        io << KrikriAwsSigner::ALGORITHM << '\n'
        io << amz_date << '\n'
        io << scope << '\n'
        io << Digest::SHA256.hexdigest(canonical_request)
      end
    end

    # `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`
    def signing_key(secret : String, date : String, region : String, service : String) : Bytes
      key = OpenSSL::HMAC.digest(:sha256, "AWS4#{secret}", date)
      key = OpenSSL::HMAC.digest(:sha256, key, region)
      key = OpenSSL::HMAC.digest(:sha256, key, service)
      OpenSSL::HMAC.digest(:sha256, key, "aws4_request")
    end

    # Lowercase hex HMAC-SHA256 of *string_to_sign* under the derived key.
    def signature(secret : String, date : String, region : String, service : String, string_to_sign : String) : String
      OpenSSL::HMAC.hexdigest(:sha256, signing_key(secret, date, region, service), string_to_sign)
    end
  end
end
