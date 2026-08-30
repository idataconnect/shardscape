use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::{Buf, BufMut, BytesMut};
use snow::Builder;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
// 2-byte big-endian length prefix for each noise frame
const FRAME_LEN_SIZE: usize = 2;
const MAX_NOISE_MSG: usize = 65535;
// ChaCha20-Poly1305 authentication tag appended to every transport message.
const TAG_LEN: usize = 16;

/// Generate a new Curve25519 keypair and return the private key as base64.
pub fn generate_private_key() -> Result<String> {
    let builder = Builder::new(PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    Ok(B64.encode(&keypair.private))
}

/// Decode a base64 Curve25519 private key from config. A valid key is exactly
/// 32 bytes; an empty or wrong-length value is rejected rather than silently
/// accepted (base64 of "" decodes to an empty Vec, which would otherwise pass).
pub fn decode_private_key(b64: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| anyhow!("Invalid noise private key (not base64): {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid noise private key: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Derive a 32-byte PSK from the cluster secret string.
///
/// Uses BLAKE3 (already a dependency); its digest is exactly 32 bytes, which is
/// the PSK length Noise requires, so no truncation is involved. The cluster
/// secret itself never goes on the wire — only this derived key authenticates
/// the handshake.
pub fn derive_psk(cluster_secret: &str) -> [u8; 32] {
    let hash = blake3::hash(cluster_secret.as_bytes());
    *hash.as_bytes()
}

/// A framed async stream that wraps an underlying `AsyncRead + AsyncWrite`
/// and encrypts/decrypts all traffic using a completed Noise transport state.
///
/// Wire format: each message is prefixed with a 2-byte big-endian length,
/// followed by the encrypted noise frame.
///
/// `snow`'s `TransportState` keeps a strict, separate nonce counter for each
/// direction: frames must be decrypted in the exact order they were encrypted,
/// and a frame must never be encrypted twice. We therefore keep three fully
/// independent buffers and a partial-write invariant (see `poll_write`):
///
/// * `read_plain`   — decrypted plaintext already produced, not yet handed out.
/// * `read_cipher`  — inbound wire bytes accumulating toward one full frame.
/// * `write_cipher` — outbound encrypted bytes awaiting flush to the wire.
///
/// Aliasing any two of these (as an earlier version did, reusing the write
/// buffer as read scratch) corrupts the stream the moment reads and writes
/// interleave — which hyper does freely while streaming a request body and
/// response concurrently.
pub struct NoiseStream<S> {
    inner: S,
    transport: snow::TransportState,
    read_plain: BytesMut,
    read_cipher: BytesMut,
    write_cipher: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseStream<S> {
    /// Perform the Noise_XXpsk3 handshake as the **responder** (server side).
    pub async fn accept(mut stream: S, private_key: &[u8], psk: &[u8; 32]) -> Result<Self> {
        let mut noise = Builder::new(PATTERN.parse()?)
            .local_private_key(private_key)?
            .psk(3, psk)?
            .build_responder()?;

        let mut buf = vec![0u8; MAX_NOISE_MSG];

        // <- e
        let msg = recv_frame(&mut stream).await?;
        noise.read_message(&msg, &mut buf)?;

        // -> e, ee, s, es
        let len = noise.write_message(&[], &mut buf)?;
        send_frame(&mut stream, &buf[..len]).await?;

        // <- s, se, psk
        let msg = recv_frame(&mut stream).await?;
        noise.read_message(&msg, &mut buf)?;

        let transport = noise.into_transport_mode()?;
        Ok(Self::from_transport(stream, transport))
    }

    /// Perform the Noise_XXpsk3 handshake as the **initiator** (client side).
    pub async fn connect(mut stream: S, private_key: &[u8], psk: &[u8; 32]) -> Result<Self> {
        let mut noise = Builder::new(PATTERN.parse()?)
            .local_private_key(private_key)?
            .psk(3, psk)?
            .build_initiator()?;

        let mut buf = vec![0u8; MAX_NOISE_MSG];

        // -> e
        let len = noise.write_message(&[], &mut buf)?;
        send_frame(&mut stream, &buf[..len]).await?;

        // <- e, ee, s, es
        let msg = recv_frame(&mut stream).await?;
        noise.read_message(&msg, &mut buf)?;

        // -> s, se, psk
        let len = noise.write_message(&[], &mut buf)?;
        send_frame(&mut stream, &buf[..len]).await?;

        let transport = noise.into_transport_mode()?;
        Ok(Self::from_transport(stream, transport))
    }

    fn from_transport(inner: S, transport: snow::TransportState) -> Self {
        Self {
            inner,
            transport,
            read_plain: BytesMut::new(),
            read_cipher: BytesMut::new(),
            write_cipher: BytesMut::new(),
        }
    }
}

async fn recv_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_frame<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| anyhow!("Noise frame too large"))?;
    stream.write_u16(len).await?;
    stream.write_all(data).await?;
    Ok(())
}

impl<S: AsyncRead + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Hand out any already-decrypted plaintext first.
            if !this.read_plain.is_empty() {
                let to_copy = out.remaining().min(this.read_plain.len());
                out.put_slice(&this.read_plain[..to_copy]);
                this.read_plain.advance(to_copy);
                return Poll::Ready(Ok(()));
            }

            // 2. If we have a complete frame buffered, decrypt it and loop to
            //    serve the resulting plaintext.
            if let Some(plaintext) = this.try_decrypt_one_frame()? {
                this.read_plain.extend_from_slice(&plaintext);
                continue;
            }

            // 3. Otherwise pull more ciphertext from the wire. Read into a
            //    dedicated inbound buffer that is never aliased with the
            //    write path.
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // Clean EOF: nothing more will arrive. If a partial
                        // frame is stranded in read_cipher the peer truncated
                        // us mid-frame; surface that rather than silently
                        // treating it as a clean close.
                        if this.read_cipher.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed mid-frame",
                        )));
                    }
                    this.read_cipher.extend_from_slice(filled);
                    // Loop back: we may now have a full frame.
                }
            }
        }
    }
}

impl<S> NoiseStream<S> {
    /// If `read_cipher` holds at least one complete length-prefixed frame,
    /// consume it, decrypt it, and return the plaintext. Returns `Ok(None)`
    /// when more wire bytes are needed.
    fn try_decrypt_one_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.read_cipher.len() < FRAME_LEN_SIZE {
            return Ok(None);
        }
        let frame_len = u16::from_be_bytes([self.read_cipher[0], self.read_cipher[1]]) as usize;
        if self.read_cipher.len() < FRAME_LEN_SIZE + frame_len {
            return Ok(None);
        }

        self.read_cipher.advance(FRAME_LEN_SIZE);
        let ciphertext = self.read_cipher.split_to(frame_len);

        // Plaintext is at most `frame_len` (it's shorter by the 16-byte tag).
        let mut plaintext = vec![0u8; frame_len];
        let n = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        plaintext.truncate(n);
        Ok(Some(plaintext))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Invariant: a frame is encrypted exactly once. `snow` advances its
        // send-nonce on every `write_message`, so re-encrypting an already
        // buffered payload (which the previous implementation did whenever a
        // mid-flush `Pending` bounced the same `buf` back to us) would emit a
        // duplicate frame under the next nonce and desynchronise the peer
        // permanently.
        //
        // So: if ciphertext from a prior call is still pending, drain it first
        // and do NOT touch `buf` until the buffer is empty. Only then encrypt.
        if !this.write_cipher.is_empty() {
            match this.flush_write_cipher(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // Still backpressured — we have not consumed any of `buf`.
                Poll::Pending => return Poll::Pending,
            }
        }

        debug_assert!(this.write_cipher.is_empty());

        // Encrypt the whole payload into one or more frames. After this point
        // the caller's bytes are durably captured in `write_cipher`, so we can
        // honestly report them all as accepted even if the flush below stalls.
        let max_payload = MAX_NOISE_MSG - TAG_LEN;
        let mut encrypted = vec![0u8; MAX_NOISE_MSG];
        for chunk in buf.chunks(max_payload) {
            let n = this
                .transport
                .write_message(chunk, &mut encrypted)
                .map_err(std::io::Error::other)?;
            this.write_cipher.put_u16(n as u16);
            this.write_cipher.extend_from_slice(&encrypted[..n]);
        }

        // Best-effort flush. Whether it completes or returns Pending, the data
        // is safely buffered; a later poll_write/poll_flush will finish it.
        match this.flush_write_cipher(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_write_cipher(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_write_cipher(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> NoiseStream<S> {
    /// Push as much of `write_cipher` to the wire as the inner stream accepts.
    /// Returns `Ready(Ok(()))` only once the buffer is fully drained.
    fn flush_write_cipher(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.write_cipher.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_cipher) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "underlying stream accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_cipher.advance(n);
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn test_keys() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let initiator = decode_private_key(&generate_private_key().unwrap()).unwrap();
        let responder = decode_private_key(&generate_private_key().unwrap()).unwrap();
        let psk = derive_psk("unit-test-cluster-secret");
        (initiator, responder, psk)
    }

    /// Establish a connected initiator/responder NoiseStream pair over an
    /// in-memory duplex pipe. The optional wrapper lets a test interpose a
    /// throttling/misbehaving adapter on the initiator's transport.
    async fn connected_pair() -> (NoiseStream<DuplexStream>, NoiseStream<DuplexStream>) {
        let (i_io, r_io) = duplex(64 * 1024);
        let (i_key, r_key, psk) = test_keys();

        let responder = tokio::spawn(async move {
            NoiseStream::accept(r_io, &r_key, &psk).await.unwrap()
        });
        let initiator = NoiseStream::connect(i_io, &i_key, &psk).await.unwrap();
        let responder = responder.await.unwrap();
        (initiator, responder)
    }

    #[tokio::test]
    async fn handshake_then_simple_round_trip() {
        let (mut client, mut server) = connected_pair().await;

        client.write_all(b"hello over noise").await.unwrap();
        client.flush().await.unwrap();

        let mut buf = [0u8; 16];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello over noise");
    }

    #[tokio::test]
    async fn wrong_psk_fails_handshake() {
        let (i_io, r_io) = duplex(64 * 1024);
        let (i_key, r_key, _) = test_keys();
        let psk_a = derive_psk("secret-a");
        let psk_b = derive_psk("secret-b");

        let responder = tokio::spawn(async move {
            NoiseStream::accept(r_io, &r_key, &psk_b).await
        });
        let client = NoiseStream::connect(i_io, &i_key, &psk_a).await;
        let server = responder.await.unwrap();

        // At least one side must reject the mismatched PSK.
        assert!(
            client.is_err() || server.is_err(),
            "handshake with mismatched PSK must fail"
        );
    }

    /// Large payload spanning many noise frames must round-trip byte-for-byte.
    /// This exercises the frame-splitting path (payloads larger than a single
    /// 65519-byte noise message) and the receiver's frame reassembly.
    #[tokio::test]
    async fn large_multi_frame_payload_round_trips() {
        let (mut client, mut server) = connected_pair().await;

        // ~600 KB: forces ~10 noise frames. Use a non-trivial pattern so a
        // dropped/duplicated/reordered frame can't accidentally pass.
        let payload: Vec<u8> = (0..600_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let expected = payload.clone();

        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected, "payload corrupted across frame boundaries");
        });

        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        reader.await.unwrap();
    }

    // ── Backpressure / partial-write adapter ─────────────────────────────────

    /// Wraps an inner stream and (a) accepts at most `max_write` bytes per
    /// poll_write, (b) returns Pending on every other write attempt. This
    /// reproduces a slow/backpressured socket — the exact condition under which
    /// the old poll_write re-encrypted an already-buffered frame, duplicating it
    /// on the wire and desynchronising snow's send-nonce.
    struct Throttle<S> {
        inner: S,
        max_write: usize,
        pending_toggle: Arc<AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Throttle<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Throttle<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // Force a Pending on every other call to stress the resumption path.
            if self.pending_toggle.fetch_add(1, Ordering::Relaxed).is_multiple_of(2) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(self.max_write);
            Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Regression test for the re-encryption-on-Pending bug (C1). The sender's
    /// underlying stream dribbles bytes out a few at a time and stalls
    /// constantly; if poll_write ever re-encrypts a buffered frame, snow's
    /// nonce desynchronises and the receiver's read_message fails the AEAD tag.
    #[tokio::test]
    async fn round_trips_through_a_backpressured_stream() {
        let (i_io, r_io) = duplex(64 * 1024);
        let (i_key, r_key, psk) = test_keys();

        let throttled = Throttle {
            inner: i_io,
            max_write: 7, // tiny: most frames need many poll_write calls
            pending_toggle: Arc::new(AtomicUsize::new(0)),
        };

        let psk_r = psk;
        let responder = tokio::spawn(async move {
            NoiseStream::accept(r_io, &r_key, &psk_r).await.unwrap()
        });
        let mut client = NoiseStream::connect(throttled, &i_key, &psk).await.unwrap();
        let mut server = responder.await.unwrap();

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i ^ (i >> 7)) as u8).collect();
        let expected = payload.clone();

        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected, "data corrupted through backpressured stream");
        });

        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        reader.await.unwrap();
    }

    /// Regression test for the aliased-buffer bug (C2). Both endpoints write and
    /// read concurrently, the way hyper streams a request body while the
    /// response arrives. If the read path and write path share a buffer, the
    /// interleaved ciphertext corrupts and one side's decrypt fails.
    #[tokio::test]
    async fn concurrent_bidirectional_traffic_does_not_corrupt() {
        let (a, b) = connected_pair().await;

        let a_to_b: Vec<u8> = (0..150_000u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
        let b_to_a: Vec<u8> = (0..150_000u32).map(|i| (i.wrapping_mul(17).wrapping_add(5)) as u8).collect();

        // Split each endpoint into independent read/write halves so a single
        // NoiseStream is genuinely read from and written to at the same time —
        // the scenario that surfaced the aliased-buffer corruption.
        let (mut a_rd, mut a_wr) = tokio::io::split(a);
        let (mut b_rd, mut b_wr) = tokio::io::split(b);

        let a_send = a_to_b.clone();
        let b_expect = a_to_b.clone();
        let b_send = b_to_a.clone();
        let a_expect = b_to_a.clone();

        let a_writer = tokio::spawn(async move {
            a_wr.write_all(&a_send).await.unwrap();
            a_wr.flush().await.unwrap();
        });
        let b_writer = tokio::spawn(async move {
            b_wr.write_all(&b_send).await.unwrap();
            b_wr.flush().await.unwrap();
        });
        let a_reader = tokio::spawn(async move {
            let mut got = vec![0u8; a_expect.len()];
            a_rd.read_exact(&mut got).await.unwrap();
            assert_eq!(got, a_expect, "A received corrupted data");
        });
        let b_reader = tokio::spawn(async move {
            let mut got = vec![0u8; b_expect.len()];
            b_rd.read_exact(&mut got).await.unwrap();
            assert_eq!(got, b_expect, "B received corrupted data");
        });

        a_writer.await.unwrap();
        b_writer.await.unwrap();
        a_reader.await.unwrap();
        b_reader.await.unwrap();
    }

    /// Many small writes followed by reads, exercising the per-frame nonce
    /// counter over a long sequence. A single skipped/duplicated frame would
    /// desync the stream and fail decryption partway through.
    #[tokio::test]
    async fn many_small_messages_preserve_order_and_integrity() {
        let (mut client, mut server) = connected_pair().await;

        let writer = tokio::spawn(async move {
            for i in 0u32..500 {
                let msg = format!("msg-{i:04}");
                client.write_all(msg.as_bytes()).await.unwrap();
            }
            client.flush().await.unwrap();
        });

        let mut all = Vec::new();
        // 500 messages * 8 bytes ("msg-0000") = 4000 bytes.
        let mut buf = vec![0u8; 4000];
        server.read_exact(&mut buf).await.unwrap();
        all.extend_from_slice(&buf);
        writer.await.unwrap();

        let text = String::from_utf8(all).unwrap();
        for i in 0u32..500 {
            assert!(text.contains(&format!("msg-{i:04}")), "missing msg-{i:04}");
        }
        // Order must be preserved.
        assert!(text.starts_with("msg-0000msg-0001"), "ordering broken: {}", &text[..32]);
    }

    // ── decode_private_key validation (H1) ───────────────────────────────────

    #[test]
    fn decode_private_key_rejects_empty() {
        assert!(decode_private_key("").is_err(), "empty key must be rejected");
    }

    #[test]
    fn decode_private_key_rejects_wrong_length() {
        // base64 of 3 bytes — valid base64, wrong key length.
        let short = B64.encode([1u8, 2, 3]);
        assert!(decode_private_key(&short).is_err(), "wrong-length key must be rejected");
    }

    #[test]
    fn decode_private_key_rejects_non_base64() {
        assert!(decode_private_key("not valid base64 !!!").is_err());
    }

    #[test]
    fn generated_key_round_trips_through_decode() {
        let key = generate_private_key().unwrap();
        let decoded = decode_private_key(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn derive_psk_is_deterministic_and_secret_dependent() {
        assert_eq!(derive_psk("same"), derive_psk("same"));
        assert_ne!(derive_psk("a"), derive_psk("b"));
        assert_eq!(derive_psk("x").len(), 32);
    }
}
