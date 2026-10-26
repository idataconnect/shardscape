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
- Multipart checksums. CreateMultipartUpload accepts `x-amz-checksum-algorithm`
  and `x-amz-checksum-type`, and every part is hashed with the declared
  algorithm. CompleteMultipartUpload builds the whole-object checksum from the
  verified part checksums, without re-reading the data: a `FULL_OBJECT` CRC
  (CRC32, CRC32C, CRC64NVME, made by combining the part CRCs) or a `COMPOSITE`
  checksum-of-checksums. It checks the result against any value the client
  sent, rejecting a mismatch with `BadDigest`, and returns it. ListParts and
  UploadPartCopy return the part checksums.
- Every 5xx response is logged at `WARN` with its S3 error code and reason.

### Fixed

- The multipart ETag suffix is the number of parts (`<md5>-<parts>`), as in S3.
  It used to be the number of internal storage blocks.
- CompleteMultipartUpload assembles exactly the parts the request lists, in
  order. Each listed part must exist (else `InvalidPart`), match its listed
  ETag and checksums (`InvalidPart`), and come in ascending order
  (`InvalidPartOrder`). `x-amz-mp-object-size` is checked against the total.
  Previously every uploaded part was used and the list was ignored.

### Changed

- Upgraded `s3s` from 0.11.1 to 0.17.0, which needs Rust 1.96 or newer.
- Malformed or truncated aws-chunked bodies now get `400 IncompleteBody`, and a
  bad chunk signature gets `403 SignatureDoesNotMatch`, instead of `500`.
- The metadata store adds checksum columns to `multipart_uploads` and `parts`
  (migrated automatically on startup). Uploads already in progress keep
  working, but get no whole-object checksum.
