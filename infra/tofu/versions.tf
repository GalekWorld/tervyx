terraform {
  required_version = ">= 1.8.0"

  # Production init MUST supply a remote backend through backend.hcl. Keeping
  # this empty prevents a bucket, tenant, or credential from being guessed.
  backend "s3" {}
}
