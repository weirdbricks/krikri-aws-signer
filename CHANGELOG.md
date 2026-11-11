# Changelog

## 0.3.0

- Sign S3 requests with `Signer::Flavor::S3`, which uses the request path
  verbatim instead of normalizing it. Normalizing changed the object a key
  containing `..` or `//` referred to.
- Sign query strings exactly as they appear on the wire, like botocore and the
  AWS SDKs (`+` stays a plus, `%7E` stays encoded). `Canonical.query(..., encode:
  true)` keeps the previous percent-decode-and-re-encode behavior.
- Do not sign the headers the AWS SDKs skip (`Expect`, `Transfer-Encoding`,
  `User-Agent`, `X-Amzn-Trace-Id`); `sign` and `canonical_request` accept
  `exclude:` to skip more.
- Hash IO bodies from their start and leave them rewound, so a partially read
  stream can no longer produce a payload hash that disagrees with the bytes sent.
- Reject empty `Host` values, duplicate `X-Amz-Date`/`X-Amz-Content-Sha256`
  headers, empty `service`/`region`, and `X-Amz-Date` values whose fields are out
  of range.
- Recognize absolute-form request targets case-insensitively, and coerce a
  relative target to the absolute form SigV4 requires.
- Canonicalization allocates less (no per-call header-name map copy or exclude
  normalization, pre-sized builders).

## 0.2.0

- Keep an existing `X-Amz-Date`, reject malformed ones, drop a plain `Date`
  header, and require a signed `Host` header.
- Cache the derived signing key per day.

## 0.1.0

- Initial release: header-based SigV4 with STS session tokens, proven against
  AWS's public test-suite vectors.
