# AWS Signature Version 4 signing in pure Crystal.
#
# ```
# require "krikri-aws-signer"
#
# signer = KrikriAwsSigner::Signer.new("ec2", "us-east-1", access_key, secret_key, session_token)
# signer.sign(request) # mutates request.headers with Authorization, X-Amz-Date, ...
# ```
require "./krikri_aws_signer/canonical"
require "./krikri_aws_signer/signature"
require "./krikri_aws_signer/signer"

module KrikriAwsSigner
  VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify }}

  ALGORITHM = "AWS4-HMAC-SHA256"
end
