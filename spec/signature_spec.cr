require "./spec_helper"

describe KrikriAwsSigner::Signature do
  it "builds the credential scope" do
    assert_equal "20150830/us-east-1/service/aws4_request",
      KrikriAwsSigner::Signature.credential_scope("20150830", "us-east-1", "service")
  end

  it "lays out the string to sign" do
    canonical_request = "GET\n/\n\n\n\n"
    expected = String.build do |io|
      io << "AWS4-HMAC-SHA256\n"
      io << "20150830T123600Z\n"
      io << "20150830/us-east-1/service/aws4_request\n"
      io << Digest::SHA256.hexdigest(canonical_request)
    end
    assert_equal expected, KrikriAwsSigner::Signature.string_to_sign(
      "20150830T123600Z", "20150830/us-east-1/service/aws4_request", canonical_request)
  end

  it "derives a 32-byte signing key through the four-step HMAC chain" do
    key = KrikriAwsSigner::Signature.signing_key(SpecHelpers::SECRET_KEY, "20150830", "us-east-1", "service")
    assert_equal 32, key.size

    step = OpenSSL::HMAC.digest(:sha256, "AWS4#{SpecHelpers::SECRET_KEY}", "20150830")
    step = OpenSSL::HMAC.digest(:sha256, step, "us-east-1")
    step = OpenSSL::HMAC.digest(:sha256, step, "service")
    expected = OpenSSL::HMAC.digest(:sha256, step, "aws4_request")
    assert_equal expected, key
  end

  it "signs the string to sign to lowercase hex" do
    signature = KrikriAwsSigner::Signature.signature(
      SpecHelpers::SECRET_KEY, "20150830", "us-east-1", "service", "string-to-sign")
    assert_equal 64, signature.size
    assert_match(/^[0-9a-f]{64}$/, signature)
  end
end
