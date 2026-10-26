//! End-to-end S3 wire tests: SigV4-signed HTTP requests, including the
//! aws-chunked bodies with trailing checksums that current aws-cli and AWS SDKs
//! send by default, through the s3s service (real auth) into a real metadata
//! store and local block store, then read back over the wire.

use crate::storage::{ShardscapeAuth, StorageBackend};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use hyper::{Method, Request, StatusCode};
use s3s::crypto::Checksum as _;
use s3s::service::{S3Service, S3ServiceBuilder};
use s3s::{Body, HttpResponse};
use s3s_sigv4::{
    AmzDate, Payload, calculate_signature, create_canonical_request, create_chunk_string_to_sign,
    create_string_to_sign, create_trailer_string_to_sign,
};
use std::sync::Arc;

const ACCESS_KEY: &str = "AKWIRETEST";
const SECRET_KEY: &str = "wire-test-secret";
const REGION: &str = "us-east-1";
/// aws-chunked chunk size, smaller than the bodies so they span several chunks.
const CHUNK: usize = 64 * 1024;

struct Harness {
    svc: S3Service,
    blocks_dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.blocks_dir);
    }
}

async fn harness() -> Harness {
    let blocks_dir = std::env::temp_dir().join(format!("ss-wire-{}", uuid::Uuid::new_v4()));
    let mut config = crate::config::Config::default();
    config.server.noise_private_key = crate::noise_transport::generate_private_key().unwrap();
    config.storage.backend = crate::config::BlockBackend::Local {
        path: blocks_dir.to_string_lossy().into_owned(),
    };
    config.storage.min_free_bytes = None;
    // Small blocks so every object spans several blocks.
    config.storage.chunking = crate::config::ChunkingConfig::Fixed {
        max_block_size: 100 * 1024,
    };

    let clock = Arc::new(crate::clock::ClusterClock::new(0));
    let db = Arc::new(
        crate::store::Store::new(":memory:", "test-site".to_string(), clock)
            .await
            .unwrap(),
    );
    let allow_all = crate::db::Policy {
        statements: vec![crate::db::PolicyStatement {
            effect: "Allow".to_string(),
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
        }],
    };
    db.create_user(ACCESS_KEY, SECRET_KEY, &allow_all)
        .await
        .unwrap();

    let backend = StorageBackend::new(Arc::clone(&db), config);
    let mut builder = S3ServiceBuilder::new(backend);
    builder.set_auth(ShardscapeAuth { db });
    Harness {
        svc: builder.build(),
        blocks_dir,
    }
}

/// The current time as an `x-amz-date` (`YYYYMMDDTHHMMSSZ`); s3s rejects
/// requests too far from now.
fn amz_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant), proleptic Gregorian.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(s3s::crypto::Sha256::checksum(data))
}

fn crc64nvme(data: &[u8]) -> String {
    BASE64.encode(s3s::crypto::Crc64Nvme::checksum(data))
}

fn crc32c(data: &[u8]) -> String {
    BASE64.encode(s3s::crypto::Crc32c::checksum(data))
}

/// How the request body is framed and signed.
enum Wire {
    /// A plain body with its SHA-256 in `x-amz-content-sha256`.
    Plain(Vec<u8>),
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: aws-cli's default since 2025.
    UnsignedTrailer {
        data: Vec<u8>,
        trailer: (&'static str, String),
    },
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: signed chunks and trailer.
    SignedTrailer {
        data: Vec<u8>,
        trailer: (&'static str, String),
    },
}

/// Build a SigV4-signed request the way an AWS SDK would.
fn request(
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    extra: &[(&str, &str)],
    body: Wire,
) -> s3s::HttpRequest {
    let amz_date = amz_now();
    let date = AmzDate::parse(&amz_date).unwrap();
    let date8 = &amz_date[..8];

    let (content_sha256, decoded_len, trailer_name) = match &body {
        Wire::Plain(d) => (sha256_hex(d), None, None),
        Wire::UnsignedTrailer { data, trailer } => (
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".to_string(),
            Some(data.len()),
            Some(trailer.0),
        ),
        Wire::SignedTrailer { data, trailer } => (
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".to_string(),
            Some(data.len()),
            Some(trailer.0),
        ),
    };

    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), "localhost".into()),
        ("x-amz-content-sha256".into(), content_sha256.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    if let Some(len) = decoded_len {
        headers.push(("content-encoding".into(), "aws-chunked".into()));
        headers.push(("x-amz-decoded-content-length".into(), len.to_string()));
    }
    if let Some(name) = trailer_name {
        headers.push(("x-amz-trailer".into(), name.into()));
    }
    for (k, v) in extra {
        headers.push((k.to_string(), v.to_string()));
    }
    headers.sort();

    let payload = match &body {
        Wire::Plain(_) => Payload::SingleChunk(&content_sha256),
        Wire::UnsignedTrailer { .. } => Payload::UnsignedMultipleChunksWithTrailer,
        Wire::SignedTrailer { .. } => Payload::MultipleChunksWithTrailer,
    };
    let signed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let canonical = create_canonical_request(method.as_str(), path, query, &signed, payload);
    let sts = create_string_to_sign(&canonical, &date, REGION, "s3");
    let seed = calculate_signature(&sts, SECRET_KEY, &date, REGION, "s3");
    let signed_names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{date8}/{REGION}/s3/aws4_request, SignedHeaders={}, Signature={seed}",
        signed_names.join(";")
    );

    let wire: Vec<u8> = match body {
        Wire::Plain(d) => d,
        Wire::UnsignedTrailer { data, trailer } => {
            let mut out = Vec::new();
            for chunk in data.chunks(CHUNK) {
                out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(format!("0\r\n{}:{}\r\n\r\n", trailer.0, trailer.1).as_bytes());
            out
        }
        Wire::SignedTrailer { data, trailer } => {
            let mut out = Vec::new();
            let mut prev = seed.clone();
            for chunk in data.chunks(CHUNK) {
                let sts = create_chunk_string_to_sign(&date, REGION, "s3", &prev, &[chunk]);
                prev = calculate_signature(&sts, SECRET_KEY, &date, REGION, "s3");
                out.extend_from_slice(
                    format!("{:x};chunk-signature={prev}\r\n", chunk.len()).as_bytes(),
                );
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
            let empty: [&[u8]; 0] = [];
            let sts = create_chunk_string_to_sign(&date, REGION, "s3", &prev, &empty);
            prev = calculate_signature(&sts, SECRET_KEY, &date, REGION, "s3");
            out.extend_from_slice(format!("0;chunk-signature={prev}\r\n").as_bytes());
            let canonical_trailers = format!("{}:{}\n", trailer.0, trailer.1);
            let sts = create_trailer_string_to_sign(
                &date,
                REGION,
                "s3",
                &prev,
                canonical_trailers.as_bytes(),
            );
            let trailer_sig = calculate_signature(&sts, SECRET_KEY, &date, REGION, "s3");
            out.extend_from_slice(
                format!(
                    "{}:{}\r\nx-amz-trailer-signature:{trailer_sig}\r\n\r\n",
                    trailer.0, trailer.1
                )
                .as_bytes(),
            );
            out
        }
    };

    let qs: Vec<String> = query
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    let uri = if qs.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", qs.join("&"))
    };
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", authorization);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    req.header("content-length", wire.len().to_string())
        .body(Body::from(wire))
        .unwrap()
}

async fn call(h: &Harness, req: s3s::HttpRequest) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let res: HttpResponse = h.svc.call(req).await.expect("s3s produced no response");
    let (parts, mut body) = res.into_parts();
    let bytes = body.store_all_limited(64 * 1024 * 1024).await.unwrap();
    (parts.status, parts.headers, bytes)
}

fn s3_code(body: &[u8]) -> String {
    crate::storage::xml_text(&String::from_utf8_lossy(body), "Code")
        .unwrap_or_default()
        .to_string()
}

async fn get(h: &Harness, path: &str) -> (StatusCode, Bytes) {
    let (status, _, body) =
        call(h, request(Method::GET, path, &[], &[], Wire::Plain(vec![]))).await;
    (status, body)
}

/// Deterministic, non-repeating test bytes (so a chunk-order mixup can't pass).
fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[tokio::test]
async fn unsigned_trailer_put_stores_and_reads_back_intact() {
    let h = harness().await;
    let body = data(300 * 1024 + 17, 1);
    let crc = crc64nvme(&body);
    let req = request(
        Method::PUT,
        "/bucket/backups/db.sql.gz",
        &[],
        &[("x-amz-sdk-checksum-algorithm", "CRC64NVME")],
        Wire::UnsignedTrailer {
            data: body.clone(),
            trailer: ("x-amz-checksum-crc64nvme", crc.clone()),
        },
    );
    let (status, headers, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
    // S3 echoes the verified checksum and a quoted MD5 ETag.
    assert_eq!(
        headers.get("x-amz-checksum-crc64nvme").unwrap(),
        crc.as_str()
    );
    let md5 = hex::encode(<md5::Md5 as md5::Digest>::digest(&body));
    assert_eq!(
        headers.get("etag").unwrap().to_str().unwrap(),
        format!("\"{md5}\"")
    );

    let (status, got) = get(&h, "/bucket/backups/db.sql.gz").await;
    assert_eq!(status, StatusCode::OK);
    assert!(got == body, "downloaded bytes differ from uploaded");
}

#[tokio::test]
async fn signed_trailer_put_stores_and_reads_back_intact() {
    let h = harness().await;
    let body = data(200 * 1024 + 5, 2);
    let crc = crc32c(&body);
    let req = request(
        Method::PUT,
        "/bucket/signed.bin",
        &[],
        &[],
        Wire::SignedTrailer {
            data: body.clone(),
            trailer: ("x-amz-checksum-crc32c", crc.clone()),
        },
    );
    let (status, headers, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(headers.get("x-amz-checksum-crc32c").unwrap(), crc.as_str());

    let (status, got) = get(&h, "/bucket/signed.bin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(got == body, "downloaded bytes differ from uploaded");
}

#[tokio::test]
async fn unsigned_trailer_checksum_mismatch_is_rejected_and_not_stored() {
    let h = harness().await;
    let body = data(150 * 1024, 3);
    let wrong = crc64nvme(b"not the body");
    let req = request(
        Method::PUT,
        "/bucket/corrupt",
        &[],
        &[],
        Wire::UnsignedTrailer {
            data: body,
            trailer: ("x-amz-checksum-crc64nvme", wrong),
        },
    );
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(s3_code(&resp), "BadDigest");

    let (status, _) = get(&h, "/bucket/corrupt").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a rejected upload must not be visible"
    );
}

#[tokio::test]
async fn signed_trailer_checksum_mismatch_is_rejected() {
    // The trailer is correctly signed, so this is the checksum check, not the
    // signature check, doing the rejecting.
    let h = harness().await;
    let body = data(70 * 1024, 4);
    let req = request(
        Method::PUT,
        "/bucket/corrupt-signed",
        &[],
        &[],
        Wire::SignedTrailer {
            data: body,
            trailer: ("x-amz-checksum-crc32c", crc32c(b"other")),
        },
    );
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(s3_code(&resp), "BadDigest");
}

#[tokio::test]
async fn header_checksum_mismatch_is_rejected() {
    // Non-streaming upload with the checksum as a plain header (what clients
    // send when chunked encoding is off, e.g. when_required + explicit algorithm).
    let h = harness().await;
    let body = data(1000, 5);
    let bad = BASE64.encode(s3s::crypto::Crc32::checksum(b"x"));
    let req = request(
        Method::PUT,
        "/bucket/h",
        &[],
        &[("x-amz-checksum-crc32", &bad)],
        Wire::Plain(body.clone()),
    );
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(s3_code(&resp), "BadDigest");

    let good = BASE64.encode(s3s::crypto::Crc32::checksum(&body));
    let req = request(
        Method::PUT,
        "/bucket/h",
        &[],
        &[("x-amz-checksum-crc32", &good)],
        Wire::Plain(body.clone()),
    );
    let (status, _, _) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(get(&h, "/bucket/h").await.1 == body);
}

#[tokio::test]
async fn plain_put_without_checksums_still_works() {
    let h = harness().await;
    let body = data(4096, 6);
    let (status, _, _) = call(
        &h,
        request(
            Method::PUT,
            "/bucket/plain",
            &[],
            &[],
            Wire::Plain(body.clone()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(get(&h, "/bucket/plain").await.1 == body);
}

#[tokio::test]
async fn multipart_upload_with_trailing_checksums_round_trips() {
    let h = harness().await;
    let path = "/bucket/big/archive.tar";

    let (status, _, resp) = call(
        &h,
        request(
            Method::POST,
            path,
            &[("uploads", "")],
            &[],
            Wire::Plain(vec![]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
    let upload_id = crate::storage::xml_text(&String::from_utf8_lossy(&resp), "UploadId")
        .unwrap()
        .to_string();

    // Part 1 unsigned-trailer (aws-cli's default), part 2 signed-trailer.
    let part1 = data(256 * 1024, 7);
    let part2 = data(100 * 1024 + 3, 8);
    let req = request(
        Method::PUT,
        path,
        &[("partNumber", "1"), ("uploadId", &upload_id)],
        &[],
        Wire::UnsignedTrailer {
            data: part1.clone(),
            trailer: ("x-amz-checksum-crc64nvme", crc64nvme(&part1)),
        },
    );
    let (status, headers1, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(
        headers1.get("x-amz-checksum-crc64nvme").unwrap(),
        crc64nvme(&part1).as_str()
    );

    // A corrupted retry of part 2 is rejected...
    let req = request(
        Method::PUT,
        path,
        &[("partNumber", "2"), ("uploadId", &upload_id)],
        &[],
        Wire::UnsignedTrailer {
            data: part2.clone(),
            trailer: ("x-amz-checksum-crc64nvme", crc64nvme(&part1)),
        },
    );
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(s3_code(&resp), "BadDigest");

    // ...and the good one accepted.
    let req = request(
        Method::PUT,
        path,
        &[("partNumber", "2"), ("uploadId", &upload_id)],
        &[],
        Wire::SignedTrailer {
            data: part2.clone(),
            trailer: ("x-amz-checksum-crc32c", crc32c(&part2)),
        },
    );
    let (status, headers2, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));

    let etag = |h: &hyper::HeaderMap| h.get("etag").unwrap().to_str().unwrap().to_string();
    let complete = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag(&headers1),
        etag(&headers2)
    );
    let req = request(
        Method::POST,
        path,
        &[("uploadId", &upload_id)],
        &[],
        Wire::Plain(complete.into_bytes()),
    );
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));

    let (status, got) = get(&h, path).await;
    assert_eq!(status, StatusCode::OK);
    let mut want = part1;
    want.extend_from_slice(&part2);
    assert!(
        got == want,
        "multipart object differs from the concatenated parts"
    );
}

#[tokio::test]
async fn server_errors_pass_through_logging_unchanged() {
    let xml = "<?xml version=\"1.0\"?><Error><Code>InternalError</Code><Message>disk on fire</Message></Error>";
    let res = hyper::Response::builder()
        .status(500)
        .body(Body::from(xml.to_string()))
        .unwrap();
    let res =
        crate::storage::log_server_error(&Method::PUT, &hyper::Uri::from_static("/b/k"), res).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let (_, mut body) = res.into_parts();
    assert_eq!(body.store_all_limited(1024).await.unwrap(), xml.as_bytes());
    assert_eq!(
        crate::storage::xml_text(xml, "Message"),
        Some("disk on fire")
    );
}

/// Rebuild `req` with its wire body changed by `f`.
async fn with_wire_body(req: s3s::HttpRequest, f: impl FnOnce(&mut Vec<u8>)) -> s3s::HttpRequest {
    let (mut parts, mut body) = req.into_parts();
    let mut wire = body
        .store_all_limited(64 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    f(&mut wire);
    parts.headers.insert("content-length", wire.len().into());
    Request::from_parts(parts, Body::from(wire))
}

#[tokio::test]
async fn tampered_signed_chunk_is_rejected_as_signature_mismatch() {
    let h = harness().await;
    let body = data(100 * 1024, 9);
    let req = request(
        Method::PUT,
        "/bucket/tampered",
        &[],
        &[],
        Wire::SignedTrailer {
            data: body.clone(),
            trailer: ("x-amz-checksum-crc32c", crc32c(&body)),
        },
    );
    // Flip one payload byte inside the first chunk (past its header line).
    let req = with_wire_body(req, |w| w[200] ^= 0xFF).await;
    let (status, _, resp) = call(&h, req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(s3_code(&resp), "SignatureDoesNotMatch");
    assert_eq!(get(&h, "/bucket/tampered").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn truncated_chunked_body_is_a_client_error_not_a_500() {
    let h = harness().await;
    let body = data(100 * 1024, 10);
    let req = request(
        Method::PUT,
        "/bucket/truncated",
        &[],
        &[],
        Wire::UnsignedTrailer {
            data: body.clone(),
            trailer: ("x-amz-checksum-crc64nvme", crc64nvme(&body)),
        },
    );
    let req = with_wire_body(req, |w| w.truncate(w.len() / 2)).await;
    let (status, _, resp) = call(&h, req).await;
    assert!(
        status.is_client_error(),
        "got {status}: {}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(get(&h, "/bucket/truncated").await.0, StatusCode::NOT_FOUND);
}

// ── multipart checksums ─────────────────────────────────────────────────────

/// Returns (status, upload id, response XML, `x-amz-checksum-type` header).
async fn create_upload(
    h: &Harness,
    path: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, String, String, String) {
    let (status, headers, resp) = call(
        h,
        request(
            Method::POST,
            path,
            &[("uploads", "")],
            extra,
            Wire::Plain(vec![]),
        ),
    )
    .await;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let id = crate::storage::xml_text(&text, "UploadId")
        .unwrap_or_default()
        .to_string();
    let checksum_type = headers
        .get("x-amz-checksum-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, id, text, checksum_type)
}

/// Upload a part with an unsigned trailing checksum; returns its quoted ETag.
async fn upload_part(
    h: &Harness,
    path: &str,
    id: &str,
    n: u32,
    body: &[u8],
    trailer: (&'static str, String),
) -> String {
    let n = n.to_string();
    let req = request(
        Method::PUT,
        path,
        &[("partNumber", &n), ("uploadId", id)],
        &[],
        Wire::UnsignedTrailer {
            data: body.to_vec(),
            trailer,
        },
    );
    let (status, headers, resp) = call(h, req).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
    headers.get("etag").unwrap().to_str().unwrap().to_string()
}

/// A part as listed in CompleteMultipartUpload: (part number, quoted ETag,
/// optional (XML element, checksum)).
type ListedPart<'a> = (u32, &'a str, Option<(&'a str, &'a str)>);

async fn complete(
    h: &Harness,
    path: &str,
    id: &str,
    parts: &[ListedPart<'_>],
    extra: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (n, etag, checksum) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag>"
        ));
        if let Some((element, value)) = checksum {
            xml.push_str(&format!("<{element}>{value}</{element}>"));
        }
        xml.push_str("</Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    let req = request(
        Method::POST,
        path,
        &[("uploadId", id)],
        extra,
        Wire::Plain(xml.into_bytes()),
    );
    let (status, _, resp) = call(h, req).await;
    (status, String::from_utf8_lossy(&resp).into_owned())
}

fn md5_raw(data: &[u8]) -> Vec<u8> {
    <md5::Md5 as md5::Digest>::digest(data).to_vec()
}

#[tokio::test]
async fn multipart_full_object_crc64nvme_like_aws_cli() {
    // aws-cli's flow: CreateMultipartUpload declares CRC64NVME, each part
    // trails its CRC64NVME, Complete lists each part's checksum and the size.
    let h = harness().await;
    let path = "/bucket/full.bin";
    let (status, id, text, checksum_type) =
        create_upload(&h, path, &[("x-amz-checksum-algorithm", "CRC64NVME")]).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(checksum_type, "FULL_OBJECT");

    let (p1, p2) = (data(300 * 1024, 11), data(50 * 1024 + 9, 12));
    let (c1, c2) = (crc64nvme(&p1), crc64nvme(&p2));
    let e1 = upload_part(
        &h,
        path,
        &id,
        1,
        &p1,
        ("x-amz-checksum-crc64nvme", c1.clone()),
    )
    .await;
    let e2 = upload_part(
        &h,
        path,
        &id,
        2,
        &p2,
        ("x-amz-checksum-crc64nvme", c2.clone()),
    )
    .await;
    let whole = [p1.as_slice(), p2.as_slice()].concat();
    let size = whole.len().to_string();

    // A part checksum in the Complete list that doesn't match the upload.
    let parts_bad = [
        (1, e1.as_str(), Some(("ChecksumCRC64NVME", c2.as_str()))),
        (2, e2.as_str(), None),
    ];
    let (status, text) = complete(&h, path, &id, &parts_bad, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(s3_code(text.as_bytes()), "InvalidPart");

    let parts = [
        (1, e1.as_str(), Some(("ChecksumCRC64NVME", c1.as_str()))),
        (2, e2.as_str(), Some(("ChecksumCRC64NVME", c2.as_str()))),
    ];
    // A wrong whole-object checksum is BadDigest.
    let wrong = crc64nvme(b"something else");
    let (status, text) = complete(
        &h,
        path,
        &id,
        &parts,
        &[("x-amz-checksum-crc64nvme", &wrong)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(s3_code(text.as_bytes()), "BadDigest");

    let want = crc64nvme(&whole);
    let (status, text) = complete(
        &h,
        path,
        &id,
        &parts,
        &[
            ("x-amz-checksum-crc64nvme", &want),
            ("x-amz-mp-object-size", &size),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumCRC64NVME"),
        Some(want.as_str())
    );
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumType"),
        Some("FULL_OBJECT")
    );
    // ETag is MD5(md5(p1) || md5(p2))-2, with the part count (not the block
    // count: these parts span 4 blocks) as the suffix.
    let etag = hex::encode(md5_raw(&[md5_raw(&p1), md5_raw(&p2)].concat()));
    assert_eq!(
        crate::storage::xml_text(&text, "ETag"),
        Some(format!("\"{etag}-2\"").as_str())
    );

    assert!(get(&h, path).await.1 == whole);
}

#[tokio::test]
async fn multipart_composite_crc32c_and_full_object_crc32() {
    let h = harness().await;
    let (p1, p2) = (data(120 * 1024, 13), data(1000, 14));

    // CRC32C defaults to COMPOSITE: base64(CRC32C(raw1 || raw2))-2.
    let path = "/bucket/composite.bin";
    let (_, id, _, _) = create_upload(&h, path, &[("x-amz-checksum-algorithm", "CRC32C")]).await;
    let e1 = upload_part(
        &h,
        path,
        &id,
        1,
        &p1,
        ("x-amz-checksum-crc32c", crc32c(&p1)),
    )
    .await;
    let e2 = upload_part(
        &h,
        path,
        &id,
        2,
        &p2,
        ("x-amz-checksum-crc32c", crc32c(&p2)),
    )
    .await;
    let raw = [
        s3s::crypto::Crc32c::checksum(&p1),
        s3s::crypto::Crc32c::checksum(&p2),
    ]
    .concat();
    let want = format!("{}-2", crc32c(&raw));
    let (status, text) = complete(&h, path, &id, &[(1, &e1, None), (2, &e2, None)], &[]).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumCRC32C"),
        Some(want.as_str())
    );
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumType"),
        Some("COMPOSITE")
    );

    // CRC32 with FULL_OBJECT requested: the CRC32 of the whole object, even
    // though the parts were sent with CRC64NVME (the declared CRC32 is
    // computed for every part regardless).
    let path = "/bucket/full-crc32.bin";
    let (status, id, text, _) = create_upload(
        &h,
        path,
        &[
            ("x-amz-checksum-algorithm", "CRC32"),
            ("x-amz-checksum-type", "FULL_OBJECT"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let e1 = upload_part(
        &h,
        path,
        &id,
        1,
        &p1,
        ("x-amz-checksum-crc64nvme", crc64nvme(&p1)),
    )
    .await;
    let e2 = upload_part(
        &h,
        path,
        &id,
        2,
        &p2,
        ("x-amz-checksum-crc64nvme", crc64nvme(&p2)),
    )
    .await;
    let whole = [p1.as_slice(), p2.as_slice()].concat();
    let want = BASE64.encode(s3s::crypto::Crc32::checksum(&whole));
    let (status, text) = complete(&h, path, &id, &[(1, &e1, None), (2, &e2, None)], &[]).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumCRC32"),
        Some(want.as_str())
    );
    assert_eq!(
        crate::storage::xml_text(&text, "ChecksumType"),
        Some("FULL_OBJECT")
    );

    // SHA256 cannot be FULL_OBJECT.
    let (status, _, text, _) = create_upload(
        &h,
        "/bucket/nope",
        &[
            ("x-amz-checksum-algorithm", "SHA256"),
            ("x-amz-checksum-type", "FULL_OBJECT"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
}

#[tokio::test]
async fn multipart_complete_assembles_only_the_listed_parts() {
    let h = harness().await;
    let path = "/bucket/subset.bin";
    let (_, id, _, _) = create_upload(&h, path, &[]).await;
    let parts: Vec<Vec<u8>> = (0..3).map(|i| data(40 * 1024 + i, 20 + i as u64)).collect();
    let mut etags = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        etags.push(
            upload_part(
                &h,
                path,
                &id,
                i as u32 + 1,
                p,
                ("x-amz-checksum-crc64nvme", crc64nvme(p)),
            )
            .await,
        );
    }
    let (status, text) = complete(
        &h,
        path,
        &id,
        &[(1, &etags[0], None), (3, &etags[2], None)],
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(get(&h, path).await.1 == [parts[0].as_slice(), parts[2].as_slice()].concat());
}
