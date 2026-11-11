# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

## What this project is

**krikri-aws-signer** is AWS Signature Version 4 request signing in pure
Crystal (stdlib only: `OpenSSL::HMAC`, `Digest::SHA256`). It exists to be a
small, fully-tested SigV4 signer with the STS session-token path proven
against test vectors - the gap that motivated extracting it from krikri.

The correctness bar is AWS's own tooling, not "looks right": every expected
signature in `spec/official_vectors_spec.cr` was independently re-derived
with botocore 1.37.9 (and the derived ones with two independent
implementations). When changing canonicalization, keep that property: any
new vector must be pinned with an independently derived expected signature,
never with whatever the implementation happens to output.

## Commands

```sh
shards install                        # needed once before specs/ameba
crystal spec                          # full test suite
just test                             # same suite, 4 real OS threads (minitest --parallel)
just test-serial                      # single-threaded run
crystal spec spec/canonical_spec.cr   # one spec file
crystal lib/ameba/bin/ameba.cr        # lint (ameba is not on PATH)
crystal tool format src spec          # formatter; run before committing
```

CI (`.github/workflows/ci.yml`) runs the formatter check, ameba and
`crystal spec` on `crystallang/crystal:1.22.2-alpine`. Crystal `>= 1.10.0`
per `shard.yml`. Tests use minitest.cr (`spec/` directory, `crystal spec`
runs them).

## Scope

Header-based SigV4 signing only. Query-string (presigned URL) signing and
chunked payload signing are explicitly out of scope until someone needs
them. Do not add dependencies - the zero-dependency runtime is the point.
