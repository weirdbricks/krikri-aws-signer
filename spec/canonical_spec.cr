require "./spec_helper"

describe KrikriAwsSigner::Canonical do
  describe ".path" do
    it "keeps a plain absolute path" do
      assert_equal "/example", KrikriAwsSigner::Canonical.path("/example")
    end

    it "maps an empty path to /" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("")
    end

    it "maps a bare slash to /" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("/")
    end

    it "removes single dot segments" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("/./")
      assert_equal "/example", KrikriAwsSigner::Canonical.path("/./example")
    end

    it "removes dot dot segments and the segments they cancel" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("/example/..")
      assert_equal "/", KrikriAwsSigner::Canonical.path("/example1/example2/../..")
      assert_equal "/example1", KrikriAwsSigner::Canonical.path("/example1/example2/..")
    end

    it "keeps a trailing slash only when segments remain" do
      assert_equal "/example/", KrikriAwsSigner::Canonical.path("/example/")
      assert_equal "/", KrikriAwsSigner::Canonical.path("/example/..")
    end

    it "collapses empty segments" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("//")
      assert_equal "/example/", KrikriAwsSigner::Canonical.path("//example//")
      assert_equal "/a/b", KrikriAwsSigner::Canonical.path("///a///b")
    end

    it "keeps relative paths relative" do
      assert_equal "example/x", KrikriAwsSigner::Canonical.path("example/x")
    end

    it "percent-encodes everything except unreserved characters" do
      assert_equal "/example%20space/", KrikriAwsSigner::Canonical.path("/example space/")
      assert_equal "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        KrikriAwsSigner::Canonical.path("/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
      assert_equal "/%E1%88%B4", KrikriAwsSigner::Canonical.path("/ሴ")
      assert_equal "/a%3Fb%23c", KrikriAwsSigner::Canonical.path("/a?b#c")
    end

    it "does not double-encode a wire-form path" do
      assert_equal "/%E1%88%B4", KrikriAwsSigner::Canonical.path("/%E1%88%B4")
      assert_equal "/foo%20bar/", KrikriAwsSigner::Canonical.path("/foo%20bar/")
      assert_equal "/a%2Fb", KrikriAwsSigner::Canonical.path("/a%2Fb")
    end

    it "treats a percent sign in the decoded path as data" do
      assert_equal "/100%25", KrikriAwsSigner::Canonical.path("/100%")
    end

    it "returns the path verbatim when normalization is off" do
      assert_equal "/a/../b", KrikriAwsSigner::Canonical.path("/a/../b", normalize: false)
      assert_equal "/a/./b", KrikriAwsSigner::Canonical.path("/a/./b", normalize: false)
      assert_equal "//a//b", KrikriAwsSigner::Canonical.path("//a//b", normalize: false)
      assert_equal "/a%2fb", KrikriAwsSigner::Canonical.path("/a%2fb", normalize: false)
      assert_equal "/a b", KrikriAwsSigner::Canonical.path("/a b", normalize: false)
    end

    it "maps an empty path to / with normalization off too" do
      assert_equal "/", KrikriAwsSigner::Canonical.path("", normalize: false)
    end
  end

  describe ".query" do
    it "keeps a simple pair" do
      assert_equal "Param1=value1", KrikriAwsSigner::Canonical.query("Param1=value1")
    end

    it "maps an empty query to an empty string" do
      assert_equal "", KrikriAwsSigner::Canonical.query("")
    end

    it "sorts by key" do
      assert_equal "a=1&b=2", KrikriAwsSigner::Canonical.query("b=2&a=1")
    end

    it "sorts duplicate keys by value" do
      assert_equal "a=1&a=2", KrikriAwsSigner::Canonical.query("a=2&a=1")
    end

    it "splits only on the first equals sign, keeping the rest as data" do
      assert_equal "a=b=c", KrikriAwsSigner::Canonical.query("a=b=c")
    end

    it "always emits key=value, even for bare keys and empty values" do
      assert_equal "flag=", KrikriAwsSigner::Canonical.query("flag")
      assert_equal "Param1=", KrikriAwsSigner::Canonical.query("Param1=")
    end

    it "skips empty components" do
      assert_equal "a=1&b=2", KrikriAwsSigner::Canonical.query("a=1&&b=2")
    end

    it "signs the wire form as it appears, like the AWS SDKs" do
      assert_equal "k+=v+", KrikriAwsSigner::Canonical.query("k+=v+")
      assert_equal "a=%7E&b=~", KrikriAwsSigner::Canonical.query("a=%7E&b=~")
      assert_equal "%e1%88%b4=bar", KrikriAwsSigner::Canonical.query("%e1%88%b4=bar")
      assert_equal "Param1=va%20lue", KrikriAwsSigner::Canonical.query("Param1=va%20lue")
      assert_equal "a=100%", KrikriAwsSigner::Canonical.query("a=100%")
    end

    it "encodes keys and values per RFC 3986 when asked" do
      assert_equal "%E1%88%B4=bar", KrikriAwsSigner::Canonical.query("ሴ=bar", encode: true)
      assert_equal "Param1=va%20lue", KrikriAwsSigner::Canonical.query("Param1=va lue", encode: true)
      assert_equal "k%2B=%2F%2C%3F", KrikriAwsSigner::Canonical.query("k+=/,?", encode: true)
      assert_equal "k%2B=v%2B", KrikriAwsSigner::Canonical.query("k+=v+", encode: true)
      assert_equal "%E1%88%B4=bar", KrikriAwsSigner::Canonical.query("%E1%88%B4=bar", encode: true)
      assert_equal "a=100%25", KrikriAwsSigner::Canonical.query("a=100%", encode: true)
    end
  end

  describe ".trim_all" do
    it "collapses whitespace runs and trims the ends" do
      assert_equal "a b", KrikriAwsSigner::Canonical.trim_all("  a   b  ")
      assert_equal "\"a b c\"", KrikriAwsSigner::Canonical.trim_all("\"a   b   c\"")
      assert_equal "a b c", KrikriAwsSigner::Canonical.trim_all("a\tb\r\nc")
    end

    it "maps an all-whitespace value to empty" do
      assert_equal "", KrikriAwsSigner::Canonical.trim_all("   \n  ")
    end

    it "returns a clean value as itself, without allocating" do
      clean = "value1"
      assert_same clean, KrikriAwsSigner::Canonical.trim_all(clean)
    end
  end

  describe ".header_value" do
    it "trims a single line" do
      assert_equal "value1", KrikriAwsSigner::Canonical.header_value(" value1 ")
    end

    it "comma-joins the Trimall'd lines of a folded value" do
      assert_equal "value1,value2,value3",
        KrikriAwsSigner::Canonical.header_value("value1\n   \n  value2  \nvalue3")
    end

    it "comma-joins CRLF-folded values too" do
      assert_equal "a,b", KrikriAwsSigner::Canonical.header_value("a\r\nb")
    end

    it "maps an empty value to empty" do
      assert_equal "", KrikriAwsSigner::Canonical.header_value("")
    end
  end

  describe ".headers" do
    it "lowercases names and sorts them" do
      headers = HTTP::Headers{"Zz" => "1", "Ab" => "2"}
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers)
      assert_equal "ab:2\nzz:1", canonical
      assert_equal "ab;zz", signed
    end

    it "comma-joins duplicate header values in order of appearance" do
      headers = HTTP::Headers.new
      headers.add("My-Header1", "value2")
      headers.add("My-Header1", "value2")
      headers.add("My-Header1", "value1")
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers)
      assert_equal "my-header1:value2,value2,value1", canonical
      assert_equal "my-header1", signed
    end

    it "excludes Authorization by default" do
      headers = HTTP::Headers{"Host" => "example.amazonaws.com", "Authorization" => "x"}
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers)
      assert_equal "host:example.amazonaws.com", canonical
      assert_equal "host", signed
    end

    it "excludes the headers the AWS SDKs never sign" do
      headers = HTTP::Headers{
        "Host"              => "example.amazonaws.com",
        "User-Agent"        => "krikri/1.0",
        "Expect"            => "100-continue",
        "Transfer-Encoding" => "chunked",
        "X-Amzn-Trace-Id"   => "Root=1-abc",
      }
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers)
      assert_equal "host:example.amazonaws.com", canonical
      assert_equal "host", signed
    end

    it "excludes caller-supplied names case-insensitively" do
      headers = HTTP::Headers{"Host" => "example.amazonaws.com", "X-Custom" => "1"}
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers, ["X-CUSTOM"])
      assert_equal "host:example.amazonaws.com", canonical
      assert_equal "host", signed
    end

    it "keeps empty-valued headers as empty values" do
      headers = HTTP::Headers{"X-Empty" => ""}
      canonical, signed = KrikriAwsSigner::Canonical.headers(headers)
      assert_equal "x-empty:", canonical
      assert_equal "x-empty", signed
    end
  end

  describe ".request" do
    it "lays out the canonical request" do
      headers = HTTP::Headers{"Host" => "example.amazonaws.com", "X-Amz-Date" => "20150830T123600Z"}
      canonical = KrikriAwsSigner::Canonical.request(
        "get", "/", "", headers, KrikriAwsSigner::Signer::EMPTY_PAYLOAD_HASH)
      assert_equal "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n" \
                   "\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonical
    end

    it "accepts a precomputed canonical-headers pair" do
      pair = {"host:example.amazonaws.com", "host"}
      canonical = KrikriAwsSigner::Canonical.request("get", "/", "", pair,
        KrikriAwsSigner::Signer::EMPTY_PAYLOAD_HASH)
      assert_equal "GET\n/\n\nhost:example.amazonaws.com\n\nhost\n" \
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonical
    end

    it "honors the path-normalization and query-encoding switches" do
      pair = {"host:example.amazonaws.com", "host"}
      payload = KrikriAwsSigner::Signer::EMPTY_PAYLOAD_HASH
      assert_includes KrikriAwsSigner::Canonical.request(
        "get", "/a/../b", "k+=v", pair, payload, normalize_path: false),
        "\n/a/../b\nk+=v\n"
      assert_includes KrikriAwsSigner::Canonical.request(
        "get", "/b", "k+=v", pair, payload, encode_query: true),
        "\n/b\nk%2B=v\n"
    end
  end

  describe ".encode and .decode" do
    it "encodes all bytes except unreserved ones" do
      assert_equal "aZ09-_.~", KrikriAwsSigner::Canonical.encode("aZ09-_.~")
      assert_equal "%2F%3D%2B%20", KrikriAwsSigner::Canonical.encode("/=+ ")
    end

    it "encodes into an existing IO" do
      io = IO::Memory.new
      KrikriAwsSigner::Canonical.encode_into(io, "a/b")
      assert_equal "a%2Fb", io.to_s
    end

    it "returns a clean value as itself, without allocating" do
      clean = "aZ09-_.~"
      assert_same clean, KrikriAwsSigner::Canonical.encode(clean)
    end

    it "encodes multi-byte characters per byte" do
      assert_equal "%E1%88%B4", KrikriAwsSigner::Canonical.encode("ሴ")
    end

    it "decodes percent escapes" do
      assert_equal "/a b", KrikriAwsSigner::Canonical.decode("/a%20b")
      assert_equal "ሴ", KrikriAwsSigner::Canonical.decode("%E1%88%B4")
    end

    it "keeps stray percent signs and plus signs as data" do
      assert_equal "100%", KrikriAwsSigner::Canonical.decode("100%")
      assert_equal "a+b", KrikriAwsSigner::Canonical.decode("a+b")
      assert_equal "%zz", KrikriAwsSigner::Canonical.decode("%zz")
    end

    it "keeps a truncated escape at the end of the value as data" do
      assert_equal "%4", KrikriAwsSigner::Canonical.decode("%4")
      assert_equal "a%2", KrikriAwsSigner::Canonical.decode("a%2")
    end

    it "round-trips through decode and encode" do
      {"", "a b", "a+b", "%", "ሴ", "/x?y=z"}.each do |value|
        assert_equal value, KrikriAwsSigner::Canonical.decode(KrikriAwsSigner::Canonical.encode(value))
      end
    end
  end
end
