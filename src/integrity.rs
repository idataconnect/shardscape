//! Upload integrity checks: `Content-MD5` and the flexible `x-amz-checksum-*`
//! values, whether sent as request headers or as aws-chunked trailers.
//!
//! s3s decodes aws-chunked bodies (and verifies the chunk/trailer signatures of
//! the signed modes) but deliberately leaves checksum verification to the S3
//! implementation. With `STREAMING-UNSIGNED-PAYLOAD-TRAILER` — the default for
//! current aws-cli and AWS SDKs — the trailing checksum is the only integrity
//! protection the body has, so every upload path feeds its bytes through a
//! [`BodyVerifier`] and rejects a mismatch with `BadDigest` before the object or
//! part is recorded.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::HeaderMap;
use s3s::checksum::ChecksumHasher;
use s3s::dto::{Checksum, ChecksumAlgorithm};
use s3s::{S3Error, S3ErrorCode, S3Result};

/// The checksum algorithms S3 defines, keyed by their `x-amz-checksum-*`
/// header name and `x-amz-sdk-checksum-algorithm` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algo {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
    Sha512,
    Md5,
    XxHash64,
    XxHash3,
    XxHash128,
}

const ALL: [Algo; 10] = [
    Algo::Crc32,
    Algo::Crc32c,
    Algo::Crc64Nvme,
    Algo::Sha1,
    Algo::Sha256,
    Algo::Sha512,
    Algo::Md5,
    Algo::XxHash64,
    Algo::XxHash3,
    Algo::XxHash128,
];

impl Algo {
    fn header(self) -> &'static str {
        match self {
            Algo::Crc32 => "x-amz-checksum-crc32",
            Algo::Crc32c => "x-amz-checksum-crc32c",
            Algo::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Algo::Sha1 => "x-amz-checksum-sha1",
            Algo::Sha256 => "x-amz-checksum-sha256",
            Algo::Sha512 => "x-amz-checksum-sha512",
            Algo::Md5 => "x-amz-checksum-md5",
            Algo::XxHash64 => "x-amz-checksum-xxhash64",
            Algo::XxHash3 => "x-amz-checksum-xxhash3",
            Algo::XxHash128 => "x-amz-checksum-xxhash128",
        }
    }

    /// Upper-case name as used in S3 error messages and
    /// `x-amz-sdk-checksum-algorithm`.
    fn name(self) -> &'static str {
        match self {
            Algo::Crc32 => ChecksumAlgorithm::CRC32,
            Algo::Crc32c => ChecksumAlgorithm::CRC32C,
            Algo::Crc64Nvme => ChecksumAlgorithm::CRC64NVME,
            Algo::Sha1 => ChecksumAlgorithm::SHA1,
            Algo::Sha256 => ChecksumAlgorithm::SHA256,
            Algo::Sha512 => ChecksumAlgorithm::SHA512,
            Algo::Md5 => ChecksumAlgorithm::MD5,
            Algo::XxHash64 => ChecksumAlgorithm::XXHASH64,
            Algo::XxHash3 => ChecksumAlgorithm::XXHASH3,
            Algo::XxHash128 => ChecksumAlgorithm::XXHASH128,
        }
    }

    fn enable(self, h: &mut ChecksumHasher) {
        use s3s::crypto::*;
        match self {
            Algo::Crc32 => h.crc32 = Some(Crc32::new()),
            Algo::Crc32c => h.crc32c = Some(Crc32c::new()),
            Algo::Crc64Nvme => h.crc64nvme = Some(Crc64Nvme::new()),
            Algo::Sha1 => h.sha1 = Some(Sha1::new()),
            Algo::Sha256 => h.sha256 = Some(Sha256::new()),
            Algo::Sha512 => h.sha512 = Some(Sha512::new()),
            Algo::Md5 => h.md5 = Some(Md5::new()),
            Algo::XxHash64 => h.xxhash64 = Some(XxHash64::new()),
            Algo::XxHash3 => h.xxhash3 = Some(XxHash3::new()),
            Algo::XxHash128 => h.xxhash128 = Some(XxHash128::new()),
        }
    }

    fn field(self, c: &Checksum) -> Option<&String> {
        match self {
            Algo::Crc32 => c.checksum_crc32.as_ref(),
            Algo::Crc32c => c.checksum_crc32c.as_ref(),
            Algo::Crc64Nvme => c.checksum_crc64nvme.as_ref(),
            Algo::Sha1 => c.checksum_sha1.as_ref(),
            Algo::Sha256 => c.checksum_sha256.as_ref(),
            Algo::Sha512 => c.checksum_sha512.as_ref(),
            Algo::Md5 => c.checksum_md5.as_ref(),
            Algo::XxHash64 => c.checksum_xxhash64.as_ref(),
            Algo::XxHash3 => c.checksum_xxhash3.as_ref(),
            Algo::XxHash128 => c.checksum_xxhash128.as_ref(),
        }
    }

    fn from_name(name: &str) -> Option<Algo> {
        ALL.into_iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
    }

    fn from_header(name: &str) -> Option<Algo> {
        ALL.into_iter()
            .find(|a| a.header().eq_ignore_ascii_case(name))
    }
}

/// What the client claims about the body, gathered before it is read.
#[derive(Default)]
pub struct Expected {
    /// `x-amz-checksum-*` values sent as ordinary request headers.
    pub headers: Checksum,
    /// `x-amz-sdk-checksum-algorithm`.
    pub algorithm: Option<ChecksumAlgorithm>,
    /// `Content-MD5` (base64).
    pub content_md5: Option<String>,
}

/// Hashes an upload body as it streams and checks it against every checksum
/// the client supplied once the body (and its trailers) has been read.
pub struct BodyVerifier {
    hasher: ChecksumHasher,
    expected: Expected,
    /// Checksums announced in `x-amz-trailer`, which must arrive as trailers.
    trailed: Vec<Algo>,
}

impl BodyVerifier {
    /// `request_headers` are the request's HTTP headers (for `x-amz-trailer`).
    pub fn new(request_headers: &HeaderMap, expected: Expected) -> Self {
        let trailed: Vec<Algo> = request_headers
            .get_all("x-amz-trailer")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|name| Algo::from_header(name.trim()))
            .collect();

        // Only hash with the algorithms the client actually asked about.
        let mut hasher = ChecksumHasher::default();
        for algo in ALL {
            let wanted = algo.field(&expected.headers).is_some()
                || trailed.contains(&algo)
                || expected
                    .algorithm
                    .as_ref()
                    .and_then(|a| Algo::from_name(a.as_str()))
                    == Some(algo);
            if wanted {
                algo.enable(&mut hasher);
            }
        }

        Self {
            hasher,
            expected,
            trailed,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Verify the body. `trailers` are the aws-chunked trailing headers (if the
    /// body had any) and `md5` the raw MD5 digest of the body, which the caller
    /// already computes for the ETag. Returns the computed checksums so they
    /// can be echoed back in the response, as S3 does.
    pub fn finish(self, trailers: Option<&HeaderMap>, md5: &[u8]) -> S3Result<Checksum> {
        if let Some(sent) = &self.expected.content_md5
            && *sent != BASE64.encode(md5)
        {
            return Err(S3Error::with_message(
                S3ErrorCode::BadDigest,
                "The Content-MD5 you specified did not match what we received.",
            ));
        }

        let computed = self.hasher.finalize();
        for algo in ALL {
            let from_trailer = trailers
                .and_then(|t| t.get(algo.header()))
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if from_trailer.is_none() && self.trailed.contains(&algo) {
                return Err(S3Error::with_message(
                    S3ErrorCode::IncompleteBody,
                    format!(
                        "The request declared trailer {} but did not send it.",
                        algo.header()
                    ),
                ));
            }
            let Some(sent) = from_trailer.or_else(|| algo.field(&self.expected.headers).cloned())
            else {
                continue;
            };
            let ok = match algo.field(&computed) {
                Some(actual) => *actual == sent.trim(),
                // A checksum the hasher was not set up for: only reachable if a
                // client trails a checksum it did not announce in x-amz-trailer.
                None => true,
            };
            if !ok {
                return Err(S3Error::with_message(
                    S3ErrorCode::BadDigest,
                    format!(
                        "The {} you specified did not match the calculated checksum.",
                        algo.name()
                    ),
                ));
            }
        }
        Ok(computed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use md5::{Digest, Md5};
    use s3s::crypto::Checksum as _;

    fn md5_of(data: &[u8]) -> Vec<u8> {
        Md5::digest(data).to_vec()
    }

    fn crc32c_b64(data: &[u8]) -> String {
        BASE64.encode(s3s::crypto::Crc32c::checksum(data))
    }

    fn trailer_headers(names: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-amz-trailer", HeaderValue::from_str(names).unwrap());
        h
    }

    #[test]
    fn no_checksums_means_nothing_to_check() {
        let mut v = BodyVerifier::new(&HeaderMap::new(), Expected::default());
        v.update(b"hello");
        let c = v.finish(None, &md5_of(b"hello")).unwrap();
        assert!(c.checksum_crc32.is_none() && c.checksum_crc64nvme.is_none());
    }

    #[test]
    fn header_checksum_match_and_mismatch() {
        let good = Expected {
            headers: Checksum {
                checksum_crc32c: Some(crc32c_b64(b"hello")),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut v = BodyVerifier::new(&HeaderMap::new(), good);
        v.update(b"hello");
        let c = v.finish(None, &md5_of(b"hello")).unwrap();
        assert_eq!(c.checksum_crc32c, Some(crc32c_b64(b"hello")));

        let bad = Expected {
            headers: Checksum {
                checksum_crc32c: Some(crc32c_b64(b"other")),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut v = BodyVerifier::new(&HeaderMap::new(), bad);
        v.update(b"hello");
        let err = v.finish(None, &md5_of(b"hello")).unwrap_err();
        assert_eq!(*err.code(), S3ErrorCode::BadDigest);
    }

    #[test]
    fn trailer_checksum_is_verified() {
        let req = trailer_headers("x-amz-checksum-crc32c");
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "x-amz-checksum-crc32c",
            HeaderValue::from_str(&crc32c_b64(b"abc")).unwrap(),
        );

        let mut v = BodyVerifier::new(&req, Expected::default());
        v.update(b"abc");
        v.finish(Some(&trailers), &md5_of(b"abc")).unwrap();

        let mut v = BodyVerifier::new(&req, Expected::default());
        v.update(b"abd");
        let err = v.finish(Some(&trailers), &md5_of(b"abd")).unwrap_err();
        assert_eq!(*err.code(), S3ErrorCode::BadDigest);
    }

    #[test]
    fn announced_trailer_that_never_arrives_is_rejected() {
        let req = trailer_headers("x-amz-checksum-crc64nvme");
        let mut v = BodyVerifier::new(&req, Expected::default());
        v.update(b"abc");
        let err = v.finish(None, &md5_of(b"abc")).unwrap_err();
        assert_eq!(*err.code(), S3ErrorCode::IncompleteBody);
    }

    #[test]
    fn content_md5_mismatch_is_bad_digest() {
        let e = Expected {
            content_md5: Some(BASE64.encode(md5_of(b"x"))),
            ..Default::default()
        };
        let mut v = BodyVerifier::new(&HeaderMap::new(), e);
        v.update(b"y");
        let err = v.finish(None, &md5_of(b"y")).unwrap_err();
        assert_eq!(*err.code(), S3ErrorCode::BadDigest);
    }

    #[test]
    fn every_algorithm_round_trips() {
        let data = b"the quick brown fox";
        for algo in ALL {
            // Compute the expected value with a hasher set up for just this algorithm.
            let mut h = ChecksumHasher::default();
            algo.enable(&mut h);
            h.update(data);
            let want = algo.field(&h.finalize()).cloned().unwrap();

            let req = trailer_headers(algo.header());
            let mut trailers = HeaderMap::new();
            trailers.insert(algo.header(), HeaderValue::from_str(&want).unwrap());
            let mut v = BodyVerifier::new(&req, Expected::default());
            v.update(data);
            v.finish(Some(&trailers), &md5_of(data))
                .unwrap_or_else(|e| panic!("{algo:?}: {e}"));
        }
    }
}
