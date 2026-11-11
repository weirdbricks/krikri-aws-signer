require "./spec_helper"

describe KrikriAwsSigner::Signer do
  it "signs a request with the full Authorization format" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    assert_equal "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " \
                 "SignedHeaders=host;x-amz-date, " \
                 "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
      authorization_of(request)
  end

  it "sets X-Amz-Date from the signing time" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal "20150830T123600Z", request.headers["X-Amz-Date"]
  end

  it "keeps an existing X-Amz-Date and scopes the signature to it" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"       => "example.amazonaws.com",
      "X-Amz-Date" => "20160101T000000Z",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal "20160101T000000Z", request.headers["X-Amz-Date"]
    assert_includes request.headers["Authorization"], "Credential=AKIDEXAMPLE/20160101/"
  end

  it "folds a Date header into X-Amz-Date and drops it" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host" => "example.amazonaws.com",
      "Date" => "20150830T123600Z",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_nil request.headers["Date"]?
    assert_equal "20150830T123600Z", request.headers["X-Amz-Date"]
  end

  it "adds X-Amz-Content-Sha256 and signs it by default" do
    request = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, "Param1=value1")
    make_signer.sign(request, at: SIGNING_TIME)
    assert_equal Digest::SHA256.hexdigest("Param1=value1"), request.headers["X-Amz-Content-Sha256"]
    assert_includes request.headers["Authorization"], "SignedHeaders=host;x-amz-content-sha256;x-amz-date"
  end

  it "adds no X-Amz-Content-Sha256 when add_sha is false" do
    request = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, "Param1=value1")
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_nil request.headers["X-Amz-Content-Sha256"]?
  end

  it "respects a pre-set X-Amz-Content-Sha256 and uses it as the payload hash" do
    request = make_request("POST", "/", HTTP::Headers{
      "Host"                 => "example.amazonaws.com",
      "X-Amz-Content-Sha256" => "UNSIGNED-PAYLOAD",
    }, "Param1=value1")
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "\nUNSIGNED-PAYLOAD"
  end

  it "sets X-Amz-Security-Token and signs it when a session token is given" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer(session_token: "FAKETOKEN").sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal "FAKETOKEN", request.headers["X-Amz-Security-Token"]
    assert_includes request.headers["Authorization"], "SignedHeaders=host;x-amz-date;x-amz-security-token"
  end

  it "signs the same regardless of where the security token header sits" do
    before = make_request("GET", "/", HTTP::Headers{
      "Host"                 => "example.amazonaws.com",
      "X-Amz-Security-Token" => "FAKETOKEN",
      "X-Amz-Date"           => "20150830T123600Z",
    })
    after = make_request("GET", "/", HTTP::Headers{
      "Host"       => "example.amazonaws.com",
      "X-Amz-Date" => "20150830T123600Z",
    })
    assert_equal signature_of(before, session_token: "FAKETOKEN"), signature_of(after, session_token: "FAKETOKEN")
  end

  it "re-signing a signed request produces the same Authorization" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    first = authorization_of(request)
    assert_equal first, authorization_of(request)
  end

  it "hashes nil and empty bodies identically" do
    without_body = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    with_body = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, "")
    assert_equal signature_of(without_body), signature_of(with_body)
  end

  it "signs a rewindable IO body and leaves it rewound" do
    body = IO::Memory.new("Param1=value1")
    request = HTTP::Request.new("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, body)
    request.headers.delete("Content-Length")
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal Digest::SHA256.hexdigest("Param1=value1"),
      make_signer.canonical_request(request).split('\n').last
    assert_equal "Param1=value1", body.gets_to_end
  end

  it "rejects a non-rewindable body without a payload hash" do
    body = SpecNonRewindableIO.new("x")
    request = HTTP::Request.new("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, body)
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "X-Amz-Content-Sha256"
  end

  it "signs an absolute-form request target" do
    request = make_request("GET", "https://example.amazonaws.com/x?b=2&a=1",
      HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "\n/x\na=1&b=2\n"
  end

  it "canonical_request does not mutate the request" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer.canonical_request(request)
    assert_nil request.headers["Authorization"]?
    assert_nil request.headers["X-Amz-Date"]?
  end
end
