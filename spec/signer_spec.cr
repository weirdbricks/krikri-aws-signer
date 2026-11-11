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

  it "converts a non-UTC signing time to UTC" do
    tokyo = Time::Location.fixed(9 * 3600)
    signing_time = Time.local(2015, 8, 30, 21, 36, 0, location: tokyo)
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer.sign(request, add_sha: false, at: signing_time)
    assert_equal "20150830T123600Z", request.headers["X-Amz-Date"]
    assert_includes request.headers["Authorization"], "Credential=AKIDEXAMPLE/20150830/"
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
      "Date" => "20200101T000000Z",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_nil request.headers["Date"]?
    assert_equal "20200101T000000Z", request.headers["X-Amz-Date"]
    assert_includes request.headers["Authorization"], "Credential=AKIDEXAMPLE/20200101/"
  end

  it "drops a calendar-format Date header and stamps X-Amz-Date from the signing time" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host" => "example.amazonaws.com",
      "Date" => "Mon, 01 Jan 2024 00:00:00 GMT",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_nil request.headers["Date"]?
    assert_equal "20150830T123600Z", request.headers["X-Amz-Date"]
  end

  it "rejects a non-SigV4 X-Amz-Date instead of signing a garbage scope" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"       => "example.amazonaws.com",
      "X-Amz-Date" => "Mon, 01 Jan 2024 00:00:00 GMT",
    })
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "X-Amz-Date"
  end

  it "rejects a calendar-invalid X-Amz-Date" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"       => "example.amazonaws.com",
      "X-Amz-Date" => "20159999T999999Z",
    })
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "X-Amz-Date"
  end

  it "rejects multiple Date headers" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    request.headers.add("Date", "Mon, 01 Jan 2024 00:00:00 GMT")
    request.headers.add("Date", "Tue, 02 Jan 2024 00:00:00 GMT")
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "multiple Date headers"
  end

  it "rejects multiple X-Amz-Date headers" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    request.headers.add("X-Amz-Date", "20150830T123600Z")
    request.headers.add("X-Amz-Date", "20160101T000000Z")
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "multiple X-Amz-Date headers"
  end

  it "rejects multiple X-Amz-Content-Sha256 headers" do
    request = make_request("POST", "/", HTTP::Headers{
      "Host" => "example.amazonaws.com",
    }, "Param1=value1")
    request.headers.add("X-Amz-Content-Sha256", "aaa")
    request.headers.add("X-Amz-Content-Sha256", "bbb")
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: true, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "multiple X-Amz-Content-Sha256 headers"
  end

  it "refuses to sign a request without a Host header" do
    request = make_request("GET", "/")
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "Host"
    ex = assert_raises(ArgumentError) do
      make_signer.canonical_request(request)
    end
    assert_includes ex.message.to_s, "Host"
  end

  it "refuses to sign a request with an empty Host header" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => ""})
    ex = assert_raises(ArgumentError) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "Host"
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

  it "keeps a pre-set X-Amz-Content-Sha256 when signing with add_sha" do
    request = make_request("POST", "/", HTTP::Headers{
      "Host"                 => "example.amazonaws.com",
      "X-Amz-Content-Sha256" => "UNSIGNED-PAYLOAD",
    }, "Param1=value1")
    make_signer.sign(request, add_sha: true, at: SIGNING_TIME)
    assert_equal "UNSIGNED-PAYLOAD", request.headers["X-Amz-Content-Sha256"]
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

  it "keeps a preset security token when the signer has none" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"                 => "example.amazonaws.com",
      "X-Amz-Security-Token" => "PRESETTOKEN",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal "PRESETTOKEN", request.headers["X-Amz-Security-Token"]
    assert_includes request.headers["Authorization"], "x-amz-security-token"
  end

  it "replaces the security token when re-signing with another one" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer(session_token: "FIRST").sign(request, add_sha: false, at: SIGNING_TIME)
    make_signer(session_token: "SECOND").sign(request, add_sha: false, at: SIGNING_TIME)
    assert_equal "SECOND", request.headers["X-Amz-Security-Token"]
    assert_equal ["SECOND"], request.headers.get?("X-Amz-Security-Token")
  end

  it "re-signing a request with the same signer is idempotent" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    signer = make_signer
    signer.sign(request, add_sha: false, at: SIGNING_TIME)
    first = request.headers["Authorization"]
    signer.sign(request, add_sha: false, at: SIGNING_TIME + 1.hour)
    assert_equal first, request.headers["Authorization"]
    assert_equal "20150830T123600Z", request.headers["X-Amz-Date"]
  end

  it "does not sign the headers the AWS SDKs skip" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"              => "example.amazonaws.com",
      "User-Agent"        => "krikri/1.0",
      "Expect"            => "100-continue",
      "Transfer-Encoding" => "chunked",
      "X-Amzn-Trace-Id"   => "Root=1-abc",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    assert_includes request.headers["Authorization"], "SignedHeaders=host;x-amz-date,"
    assert_equal "krikri/1.0", request.headers["User-Agent"]
  end

  it "excludes additional caller-supplied headers" do
    request = make_request("GET", "/", HTTP::Headers{
      "Host"     => "example.amazonaws.com",
      "X-Custom" => "1",
    })
    make_signer.sign(request, add_sha: false, at: SIGNING_TIME, exclude: ["x-custom"])
    assert_includes request.headers["Authorization"], "SignedHeaders=host;x-amz-date,"
    assert_equal "1", request.headers["X-Custom"]
  end

  it "hashes nil and empty bodies identically" do
    without_body = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    with_body = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, "")
    assert_equal signature_of(without_body), signature_of(with_body)
  end

  it "hashes a Bytes body" do
    request = make_request("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    request.body = "Param1=value1".to_slice
    assert_equal Digest::SHA256.hexdigest("Param1=value1"), make_signer.payload_hash(request)
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

  it "adds X-Amz-Content-Sha256 for an IO body when add_sha is true" do
    body = IO::Memory.new("Param1=value1")
    request = HTTP::Request.new("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, body)
    request.headers.delete("Content-Length")
    make_signer.sign(request, add_sha: true, at: SIGNING_TIME)
    assert_equal Digest::SHA256.hexdigest("Param1=value1"), request.headers["X-Amz-Content-Sha256"]
    assert_equal "Param1=value1", body.gets_to_end
  end

  it "hashes the whole IO body even when it was partially read" do
    body = IO::Memory.new("0123456789")
    body.pos = 4
    request = HTTP::Request.new("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, body)
    request.headers.delete("Content-Length")
    make_signer.sign(request, add_sha: true, at: SIGNING_TIME)
    assert_equal Digest::SHA256.hexdigest("0123456789"), request.headers["X-Amz-Content-Sha256"]
    assert_equal 0, body.pos
    assert_equal "0123456789", body.gets_to_end
  end

  it "rejects a non-rewindable body without a payload hash" do
    body = SpecNonRewindableIO.new("x")
    request = HTTP::Request.new("POST", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}, body)
    request.headers.delete("Content-Length")
    ex = assert_raises(IO::Error) do
      make_signer.sign(request, add_sha: false, at: SIGNING_TIME)
    end
    assert_includes ex.message.to_s, "X-Amz-Content-Sha256"
    assert ex.cause.is_a?(IO::Error)
  end

  it "signs an absolute-form request target" do
    request = make_request("GET", "https://example.amazonaws.com/x?b=2&a=1",
      HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "\n/x\na=1&b=2\n"
  end

  it "signs an absolute-form request target with an uppercase scheme" do
    request = make_request("GET", "HTTPS://example.amazonaws.com/x?b=2&a=1",
      HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "\n/x\na=1&b=2\n"
  end

  it "maps an absolute-form target with no path to /" do
    request = make_request("GET", "https://example.amazonaws.com", HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "GET\n/\n\n"
  end

  it "prepends the missing leading slash to a relative target" do
    request = make_request("GET", "example/x", HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "GET\n/example/x\n"
  end

  it "signs the query string exactly as it appears on the wire" do
    request = make_request("GET", "/?k+=v+", HTTP::Headers{"Host" => "example.amazonaws.com"})
    canonical = make_signer.canonical_request(request)
    assert_includes canonical, "\n/\nk+=v+\n"
  end

  it "signs an S3 request path verbatim" do
    signer = KrikriAwsSigner::Signer.new("s3", "us-east-1", ACCESS_KEY, SECRET_KEY,
      flavor: KrikriAwsSigner::Signer::Flavor::S3)
    request = make_request("GET", "/a/../b", HTTP::Headers{"Host" => "bucket.s3.amazonaws.com"})
    assert_includes signer.canonical_request(request), "GET\n/a/../b\n"
  end

  it "normalizes the path for the standard flavor" do
    request = make_request("GET", "/a/../b", HTTP::Headers{"Host" => "bucket.s3.amazonaws.com"})
    assert_includes make_signer.canonical_request(request), "GET\n/b\n"
  end

  it "rejects an empty service or region" do
    ex = assert_raises(ArgumentError) do
      KrikriAwsSigner::Signer.new("", "us-east-1", ACCESS_KEY, SECRET_KEY)
    end
    assert_includes ex.message.to_s, "service"
    ex = assert_raises(ArgumentError) do
      KrikriAwsSigner::Signer.new("ec2", "", ACCESS_KEY, SECRET_KEY)
    end
    assert_includes ex.message.to_s, "region"
  end

  it "canonical_request does not mutate the request" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    make_signer.canonical_request(request)
    assert_nil request.headers["Authorization"]?
    assert_nil request.headers["X-Amz-Date"]?
  end

  it "exposes a semantic version" do
    assert_match(/^\d+\.\d+\.\d+$/, KrikriAwsSigner::VERSION)
  end

  it "re-signing a request on a different day uses that day's signing key" do
    request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    signer = make_signer
    signer.sign(request, add_sha: false, at: SIGNING_TIME)
    first = request.headers["Authorization"].split("Signature=")[1]
    request2 = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
    signer.sign(request2, add_sha: false, at: SIGNING_TIME + 1.day)
    second = request2.headers["Authorization"].split("Signature=")[1]
    refute_equal first, second
    assert_includes request2.headers["Authorization"], "Credential=AKIDEXAMPLE/20150831/"
  end

  it "signs concurrently from many fibers with one signer" do
    signer = make_signer
    days = (0..3).map { |offset| SIGNING_TIME + offset.days }
    expected = days.to_h do |time|
      {time, signature_of(make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"}),
        at: time)}
    end

    failures = Channel(Int32).new
    8.times do |worker|
      spawn do
        mismatches = 0
        100.times do |iteration|
          time = days[(worker + iteration) % days.size]
          request = make_request("GET", "/", HTTP::Headers{"Host" => "example.amazonaws.com"})
          signer.sign(request, add_sha: false, at: time)
          actual = request.headers["Authorization"].split("Signature=")[1]
          mismatches += 1 if actual != expected[time]
        end
        failures.send(mismatches)
      end
    end
    total = 0
    8.times { total += failures.receive }
    assert_equal 0, total
  end
end
