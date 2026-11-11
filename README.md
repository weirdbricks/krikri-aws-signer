# krikri-aws-signer

AWS [Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing.html)
request signing in pure Crystal, built on the stdlib (`OpenSSL::HMAC`,
`Digest::SHA256`) with no other dependencies.

## Provenance

Implemented from AWS's public "Signature Version 4 signing process"
documentation. The correctness bar is AWS's own tooling: the test suite pins
the expected signatures of AWS's public SigV4 test-suite vectors (every one
independently re-derived with botocore 1.37.9 before being pinned), plus
derived vectors for the STS session-token and query-space cases that AWS's
suite leaves ambiguous. See `spec/official_vectors_spec.cr` for the full
corpus and its provenance notes.

## Usage

```crystal
require "krikri-aws-signer"

signer = KrikriAwsSigner::Signer.new("ec2", "us-east-1", access_key, secret_key, session_token)
signer.sign(request) # mutates request.headers in place
```

`sign` sets `X-Amz-Date` (kept if already present, otherwise the signing
time), `X-Amz-Security-Token` (when a session token is given),
`X-Amz-Content-Sha256` (the body's SHA-256, unless `add_sha: false` or the
header is already set, e.g. to `UNSIGNED-PAYLOAD`), and `Authorization`
covering every request header except `Authorization` itself. The lower-level
pieces are public too: `KrikriAwsSigner::Canonical` (URI/query/header
canonicalization) and `KrikriAwsSigner::Signature` (string-to-sign, signing
key, signature).

Not implemented (yet):

- Query-string (presigned URL) signing.
- Chunked/streaming payload signing (`aws-chunked`).

## Status

- Full coverage of the header-based SigV4 signing path, including STS
  session tokens and multi-value / folded header values.
- Canonicalization follows the rules AWS's own SDKs apply (verified against
  botocore): path dot-segment removal with empty-segment collapsing, RFC
  3986 encoding of query components with strict percent-decoding of the wire
  form (a literal `+` stays a plus), and Trimall'd comma-joined header
  values.

## Development

```sh
shards install           # once
crystal spec             # the full test suite (the only required check)
just test                # same suite, 4 real OS threads (minitest --parallel)
crystal spec spec/canonical_spec.cr   # one spec file
crystal lib/ameba/bin/ameba.cr        # lint (ameba is not on PATH)
crystal tool format src spec          # formatter; run before committing
```
