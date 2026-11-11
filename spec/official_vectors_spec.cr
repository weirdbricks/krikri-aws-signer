require "./spec_helper"

# Signature vectors from AWS's public "Test Suite for Signature Version 4".
#
# Provenance of the expected signatures:
# * The get-*/post-* vectors below are the suite's own expected signatures,
#   as reproduced in awscr-signer's MIT-licensed spec
#   (spec/awscr-signer/signers/v4_amazon_spec.cr). Every one of them was
#   independently re-derived with botocore 1.37.9 (AWS's own SDK) before
#   being pinned here; where the two disagreed, the disagreement was run
#   down to the exact canonicalization rule and the suite's expectation
#   won (see spec/canonical_spec.cr for those rules in isolation).
# * The `post-sts-header-*` and `post-vanilla-query-space` vectors are
#   derived: AWS's suite cases for them were left `pending` (empty) in
#   awscr-signer's port, so the expected signatures here were computed
#   independently with botocore 1.37.9 and a separate reference
#   implementation, which agree to the byte.
#
# The signing credentials and time are the suite's own: AKIDEXAMPLE /
# wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY at 2015-08-30T12:36:00Z, service
# "service", region "us-east-1". All cases sign with add_sha: false, like
# the suite (no X-Amz-Content-Sha256 header participates).
describe "AWS SigV4 test-suite vectors" do
  def suite_signature(method : String, target : String, headers : HTTP::Headers = HTTP::Headers.new,
                      body : String? = nil, session_token : String? = nil) : String
    headers["Host"] = "example.amazonaws.com" unless headers.has_key?("Host")
    signature_of(make_request(method, target, headers, body), session_token: session_token)
  end

  describe "query strings" do
    it "get-vanilla" do
      assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        suite_signature("GET", "/")
    end

    it "get-vanilla-query" do
      assert_equal "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb",
        suite_signature("GET", "/?Param1=value1")
    end

    it "get-vanilla-query-order-key-case" do
      assert_equal "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
        suite_signature("GET", "/?Param1=value1&Param2=value2")
    end

    it "get-vanilla-query-unreserved" do
      unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      assert_equal "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
        suite_signature("GET", "/?#{unreserved}=#{unreserved}")
    end

    it "get-vanilla-utf8" do
      # wire form of /?ሴ=bar - HTTP::Request rejects raw non-ASCII targets
      assert_equal "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04",
        suite_signature("GET", "/?%E1%88%B4=bar")
    end

    it "post-vanilla-query-space (derived vector)" do
      assert_equal "4ec66db0beb82994d9722be7063a8d004c82a85b4a9800ef75e0059be81eb272",
        suite_signature("POST", "/?Param1=value1&Param2=va%20lue")
    end

    it "post-vanilla-query-nonunreserved" do
      # wire form of /?@#$%^&+=/,?><`";:\\|][{} - raw separators would
      # change the pair count, so the suite case travels encoded
      wire = "%40%23%24%25%5E%26%2B=%2F%2C%3F%3E%3C%60%22%3B%3A%5C%7C%5D%5B%7B%7D"
      assert_equal "88d3e39e4fa54b971f51c0a09140368e1a51aafb76c4652d9998f93cf3038074",
        suite_signature("POST", "/?#{wire}")
    end
  end

  describe "paths" do
    it "get-unreserved" do
      unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      assert_equal "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
        suite_signature("GET", "/#{unreserved}")
    end

    it "get-utf8" do
      # wire form of /ሴ - HTTP::Request rejects raw non-ASCII targets
      assert_equal "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
        suite_signature("GET", "/%E1%88%B4")
    end

    it "get-space" do
      # wire form of /example space/ - HTTP::Request rejects raw spaces
      assert_equal "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
        suite_signature("GET", "/example%20space/")
    end

    it "get-relative" do
      assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        suite_signature("GET", "/example/..")
    end

    it "get-relative-relative" do
      assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        suite_signature("GET", "/example1/example2/../..")
    end

    it "get-slash-dot-slash" do
      assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        suite_signature("GET", "/./")
    end

    it "get-slash-pointless-dot" do
      assert_equal "ef75d96142cf21edca26f06005da7988e4f8dc83a165a80865db7089db637ec5",
        suite_signature("GET", "/./example")
    end

    it "get-slash" do
      assert_equal "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        suite_signature("GET", "//")
    end

    it "get-slashes" do
      assert_equal "9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84",
        suite_signature("GET", "//example//")
    end
  end

  describe "headers" do
    it "get-header-key-duplicate" do
      headers = HTTP::Headers.new
      headers.add("My-Header1", "value2")
      headers.add("My-Header1", "value2")
      headers.add("My-Header1", "value1")
      assert_equal "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea",
        suite_signature("GET", "/", headers)
    end

    it "get-header-value-multiline" do
      # Crystal's HTTP::Headers (like any real HTTP stack) rejects newlines
      # in header values, so the folded value can only travel through the
      # canonicalization layer - which is exactly where the suite pins it.
      value = KrikriAwsSigner::Canonical.header_value("value1\n   \n  value2  \nvalue3")
      canonical_request = "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:#{value}\n" \
                          "x-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\n" \
                          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      scope = KrikriAwsSigner::Signature.credential_scope("20150830", "us-east-1", "service")
      string_to_sign = KrikriAwsSigner::Signature.string_to_sign("20150830T123600Z", scope, canonical_request)
      signature = KrikriAwsSigner::Signature.signature(SECRET_KEY, "20150830", "us-east-1", "service", string_to_sign)
      assert_equal "ba17b383a53190154eb5fa66a1b836cc297cc0a3d70a5d00705980573d8ff790", signature
    end

    it "get-header-value-order" do
      headers = HTTP::Headers.new
      headers.add("My-Header1", "value4")
      headers.add("My-Header1", "value1")
      headers.add("My-Header1", "value3")
      headers.add("My-Header1", "value2")
      assert_equal "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01",
        suite_signature("GET", "/", headers)
    end

    it "get-header-value-trim" do
      headers = HTTP::Headers{"My-Header1" => "value1", "My-Header2" => "\"a   b   c\""}
      assert_equal "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
        suite_signature("GET", "/", headers)
    end

    it "post-header-key-case" do
      headers = HTTP::Headers{"HOST" => "example.amazonaws.com", "x-amz-DATE" => "20150830T123600Z"}
      assert_equal "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
        suite_signature("POST", "/", headers)
    end

    it "post-header-key-sort" do
      headers = HTTP::Headers{"My-Header1" => "value1"}
      assert_equal "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c",
        suite_signature("POST", "/", headers)
    end

    it "post-header-value-case" do
      headers = HTTP::Headers{"My-Header1" => "VALUE1"}
      assert_equal "cdbc9802e29d2942e5e10b5bccfdd67c5f22c7c4e8ae67b53629efa58b974b7d",
        suite_signature("POST", "/", headers)
    end
  end

  describe "bodies" do
    it "post-vanilla" do
      assert_equal "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
        suite_signature("POST", "/")
    end

    it "post-x-www-form-urlencoded" do
      headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
      assert_equal "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
        suite_signature("POST", "/", headers, "Param1=value1")
    end

    it "post-x-www-form-urlencoded-parameters" do
      headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded; charset=utf8"}
      assert_equal "1a72ec8f64bd914b0e42e42607c7fbce7fb2c7465f63e3092b3b0d39fa77a6fe",
        suite_signature("POST", "/", headers, "Param1=value1")
    end
  end

  describe "with sts token" do
    it "post-sts-header-before (derived vector)" do
      headers = HTTP::Headers{"X-Amz-Security-Token" => "AQoDYXdzEJrZEXAMPLESESSIONTOKEN"}
      assert_equal "9ff98aa66a36d076e50df1249a484eebb0843a1d6baea4361ac8299397504a92",
        suite_signature("POST", "/", headers, session_token: "AQoDYXdzEJrZEXAMPLESESSIONTOKEN")
    end

    it "post-sts-header-after (derived vector)" do
      assert_equal "9ff98aa66a36d076e50df1249a484eebb0843a1d6baea4361ac8299397504a92",
        suite_signature("POST", "/", session_token: "AQoDYXdzEJrZEXAMPLESESSIONTOKEN")
    end
  end
end
