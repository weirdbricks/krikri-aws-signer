require "./spec_helper"

# Vectors derived from botocore 1.37.9 (AWS's own SDK) for the cases the public
# SigV4 test suite does not pin down, each one chosen to lock a rule the suite
# leaves ambiguous:
#
# * S3 paths: S3 signs the request path verbatim, so `/a/../b` and `//a//b` stay
#   as sent instead of being normalized (`botocore.auth.S3SigV4Auth`).
# * Query strings: components are signed exactly as they appear on the wire -
#   a literal `+` stays `+`, `%7E` stays percent-encoded, lowercase hex escapes
#   stay lowercase (`botocore.auth.SigV4Auth._canonical_query_string_url`).
# * Header blacklist: `User-Agent`, `Expect`, `Transfer-Encoding` and
#   `X-Amzn-Trace-Id` are never signed (`SIGNED_HEADERS_BLACKLIST`).
#
# Every expected signature below was produced by botocore, never by this
# implementation. Credentials and time are the suite's own: AKIDEXAMPLE /
# wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY at 2015-08-30T12:36:00Z, region
# us-east-1 (service "s3" for the S3 cases, "service" otherwise).
describe "botocore-derived parity vectors" do
  def s3_signer
    KrikriAwsSigner::Signer.new("s3", "us-east-1", SpecHelpers::ACCESS_KEY, SpecHelpers::SECRET_KEY,
      flavor: KrikriAwsSigner::Signer::Flavor::S3)
  end

  it "s3-path-dotdot" do
    request = make_request("GET", "/a/../b", HTTP::Headers{"Host" => "bucket.s3.amazonaws.com"})
    s3_signer.sign(request, at: SIGNING_TIME)
    assert_includes request.headers["Authorization"],
      "Signature=52394c03ba87b10fad9de416cd7c5097437cb1709c26ae2ff791ba14552594d0"
  end

  it "s3-path-double-slash" do
    request = make_request("GET", "//a//b", HTTP::Headers{"Host" => "bucket.s3.amazonaws.com"})
    s3_signer.sign(request, at: SIGNING_TIME)
    assert_includes request.headers["Authorization"],
      "Signature=990f632132e49207b95da7fb62f13ae76c71c51384678b35b9773cede02f42c0"
  end

  it "s3-path-encoded-slash" do
    request = make_request("GET", "/a%2Fb", HTTP::Headers{"Host" => "bucket.s3.amazonaws.com"})
    s3_signer.sign(request, at: SIGNING_TIME)
    assert_includes request.headers["Authorization"],
      "Signature=0f5f1e5c248d33906425ea25f4860a541260d4c26f2c9acdde95a27892fd6adb"
  end

  it "query-plus" do
    request = make_request("GET", "/?k+=v+", HTTP::Headers{"Host" => "example.amazonaws.com"})
    assert_equal "9932bdfd60d343d46ffe2db56767b9f16784748b5604de0b907265e4ff0f9dd5",
      signature_of(request)
  end

  it "query-percent-7e" do
    request = make_request("GET", "/?a=%7E&b=~", HTTP::Headers{"Host" => "example.amazonaws.com"})
    assert_equal "401c0042c87c6ab25a17b7215b8c32a811ccb94f7d2aae7d650853d3b40d43ee",
      signature_of(request)
  end

  it "query-lowercase-hex" do
    request = make_request("GET", "/?%e1%88%b4=bar", HTTP::Headers{"Host" => "example.amazonaws.com"})
    assert_equal "91474f6ca429636ced21e0526bae1380c0836925878124b2276e8f1a5d3a4c06",
      signature_of(request)
  end

  it "query-duplicate-keys" do
    request = make_request("GET", "/?a=2&a=1&b=1", HTTP::Headers{"Host" => "example.amazonaws.com"})
    assert_equal "fe5a07b3a1ef61fbbc167d2f7e8dd23c40712c6d289e1c192c8519582ca2a9c2",
      signature_of(request)
  end

  it "headers-sdk-blacklist" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"              => "example.amazonaws.com",
      "User-Agent"        => "krikri/1.0",
      "Expect"            => "100-continue",
      "Transfer-Encoding" => "chunked",
      "X-Amzn-Trace-Id"   => "Root=1-abc",
    })
    assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
      signature_of(request)
  end
end
