require "minitest/autorun"
require "../src/krikri-aws-signer"

# Shared spec helpers. minitest assertion methods live on test classes,
# so helpers that assert must be instance methods of the test classes
# rather than top-level defs.
module SpecHelpers
  SIGNING_TIME = Time.utc(2015, 8, 30, 12, 36, 0)
  ACCESS_KEY   = "AKIDEXAMPLE"
  SECRET_KEY   = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

  def make_signer(service : String = "service", region : String = "us-east-1",
                  session_token : String? = nil) : KrikriAwsSigner::Signer
    KrikriAwsSigner::Signer.new(service, region, ACCESS_KEY, SECRET_KEY, session_token)
  end

  # Build a request the way the AWS test-suite cases do: only the listed
  # headers participate, so any Content-Length that HTTP::Request adds for
  # a body is dropped.
  def make_request(method : String, target : String,
                   headers : HTTP::Headers = HTTP::Headers.new,
                   body : String? = nil) : HTTP::Request
    request = HTTP::Request.new(method, target, headers, body)
    request.headers.delete("Content-Length")
    request
  end

  def signature_of(request : HTTP::Request, session_token : String? = nil,
                   add_sha : Bool = false, at time : Time = SIGNING_TIME) : String
    make_signer(session_token: session_token).sign(request, add_sha: add_sha, at: time)
    request.headers["Authorization"].split("Signature=")[1]
  end

  def authorization_of(request : HTTP::Request, session_token : String? = nil,
                       add_sha : Bool = false, at time : Time = SIGNING_TIME) : String
    make_signer(session_token: session_token).sign(request, add_sha: add_sha, at: time)
    request.headers["Authorization"]
  end
end

class Minitest::Spec
  include SpecHelpers
end

# An IO whose base-class `rewind` raises, for testing the non-seekable
# body path.
class SpecNonRewindableIO < IO
  def initialize(@content : String)
    @offset = 0
  end

  def read(slice : Bytes) : Int32
    count = Math.min(slice.size, @content.bytesize - @offset)
    return 0 if count <= 0
    slice.copy_from(@content.to_slice[@offset, count])
    @offset += count
    count
  end

  def write(slice : Bytes) : Nil
    raise IO::Error.new("read-only")
  end
end
