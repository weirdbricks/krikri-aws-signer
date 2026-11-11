# krikri-aws-signer

AWS [Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing.html)
request signing in pure Crystal, built on the stdlib (`OpenSSL::HMAC`,
`Digest::SHA256`) with no other dependencies.

## Provenance

Implemented from AWS's public "Signature Version 4 signing process"
documentation. The correctness bar is AWS's own tooling: the test suite pins
the expected signatures of AWS's public SigV4 test-suite vectors (every one
independently re-derived with botocore 1.37.9 before being pinned), plus
botocore-derived vectors for the cases that suite leaves ambiguous - STS session
tokens, S3 path handling, query strings that are already percent-encoded, and
the AWS SDKs' unsigned-header blacklist. See `spec/official_vectors_spec.cr` and
`spec/parity_vectors_spec.cr` for the full corpora and their provenance notes.

## Usage

```crystal
require "krikri-aws-signer"

signer = KrikriAwsSigner::Signer.new("ec2", "us-east-1", access_key, secret_key, session_token)
signer.sign(request) # mutates request.headers in place

# S3 signs the request path verbatim; other services normalize it.
s3 = KrikriAwsSigner::Signer.new("s3", "us-east-1", access_key, secret_key, nil,
  flavor: KrikriAwsSigner::Signer::Flavor::S3)
s3.sign(request)
```

`sign` sets `X-Amz-Date` (kept if already present - and then it must be a
well-formed `%Y%m%dT%H%M%SZ` timestamp with in-range fields, or `ArgumentError`
is raised; otherwise the signing time, converted to UTC), `X-Amz-Security-Token`
(when a session token is given), `X-Amz-Content-Sha256` (the body's SHA-256,
unless `add_sha: false` or the header is already set, e.g. to
`UNSIGNED-PAYLOAD`), and `Authorization` covering every request header except
`Authorization` itself and the headers the AWS SDKs never sign (`Expect`,
`Transfer-Encoding`, `User-Agent`, `X-Amzn-Trace-Id`; add more with the
`exclude:` argument). A plain `Date` header is dropped; its value is reused for
`X-Amz-Date` only when it already is a valid `X-Amz-Date` timestamp, in which
case that timestamp - not the `at:` argument - is what gets signed. The request
must carry a non-empty `Host` header (every AWS service requires it to be
signed) or `sign` raises `ArgumentError` rather than producing a signature the
service will reject.

The lower-level pieces are public too: `KrikriAwsSigner::Canonical`
(URI/query/header canonicalization) and `KrikriAwsSigner::Signature`
(string-to-sign, signing key, signature). A `Signer` caches its derived signing
key per day, so signing many requests runs the four-step HMAC chain only once a
day; the cache is mutex-protected, so one `Signer` can be shared between fibers
and threads.

Not implemented (yet):

- Query-string (presigned URL) signing.
- Chunked/streaming payload signing (`aws-chunked`).

## Status

- Full coverage of the header-based SigV4 signing path, including STS session
  tokens, multi-value header values, and the S3 variant that signs the request
  path verbatim (`Signer::Flavor::S3`).
- Query strings are signed exactly as they appear on the wire, which is what
  botocore and the AWS SDKs do: a literal `+` stays a plus (it is not treated as
  a space and not re-encoded), an already-encoded `%7E` stays encoded, and
  lowercase hex escapes stay lowercase. Build the request target with the exact
  bytes you are going to send; a target built with
  `URI.encode_www_form`/`HTTP::Params#to_s` is signed as sent, `+` included.
- Paths are normalized the way botocore's `remove_dot_segments` does: dot
  segments removed, empty segments collapsed, then each segment strictly
  percent-decoded and re-encoded per RFC 3986. S3 requests skip all of that.

Deliberate differences from botocore (verified against botocore 1.37.9):

- A percent-encoded path is signed in its single-encoded form (`/a%2Fb` stays
  `/a%2Fb`), while botocore quotes the already-quoted path again
  (`/a%252Fb`). Single encoding is what the AWS test suite expects and what
  `aws-sdk-go` sends.
- An empty query component (`?a=1&&b=2`) is skipped; botocore emits a bogus
  `=` pair for it.
- A caller's `X-Amz-Date` is kept, and a `Date` header is dropped rather than
  rewritten to RFC 822 as botocore does. Set `X-Amz-Date` explicitly when the
  timestamp matters.

## Development

```sh
shards install           # once
crystal spec             # the full test suite
just test                # same suite, 4 OS threads (minitest --parallel)
crystal spec spec/canonical_spec.cr   # one spec file
crystal lib/ameba/bin/ameba.cr        # lint (ameba is not on PATH)
crystal tool format src spec          # formatter; run before committing
```

CI runs the formatter check and ameba on Crystal 1.22, and the spec suite on
Crystal 1.22 and 1.10 (the floor `shard.yml` claims).
