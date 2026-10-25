# Changelog

## Unreleased

### Added

- Trailing-checksum uploads. PutObject and UploadPart accept the aws-chunked
  bodies that aws-cli and the AWS SDKs send by default since early 2025:
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` and
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`. Previously these uploads failed
  with a bare `500 InternalError`, and clients had to set
  `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` to work around it.
- Checksum verification. Every `x-amz-checksum-*` value the client sends, as a
  header or as an aws-chunked trailer, and `Content-MD5`, is checked against the
  bytes received. A mismatch is rejected with `400 BadDigest` and nothing is
  stored. This matters most for `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, where the
  trailing checksum is the body's only integrity check. Verified checksums are
  echoed in the PutObject/UploadPart response, as S3 does.
- Every 5xx response is logged at `WARN` with its S3 error code and reason.

### Changed

- Upgraded `s3s` from 0.11.1 to 0.17.0, which needs Rust 1.96 or newer.
- Malformed or truncated aws-chunked bodies now get `400 IncompleteBody`, and a
  bad chunk signature gets `403 SignatureDoesNotMatch`, instead of `500`.
