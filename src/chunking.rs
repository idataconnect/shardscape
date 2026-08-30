use bytes::{Bytes, BytesMut};

pub trait ChunkingStrategy: Send + Sync {
    /// Processes incoming data and returns a vector of completed chunks.
    /// Any incomplete data remains in the buffer.
    fn process(&self, buffer: &mut BytesMut) -> Vec<Bytes>;

    /// Finalizes the process and returns the final chunk if any data remains.
    fn finalize(&self, buffer: &mut BytesMut) -> Option<Bytes>;
}

pub struct FixedSizeStrategy {
    pub chunk_size: usize,
}

impl ChunkingStrategy for FixedSizeStrategy {
    fn process(&self, buffer: &mut BytesMut) -> Vec<Bytes> {
        let mut completed_chunks = Vec::new();
        while buffer.len() >= self.chunk_size {
            completed_chunks.push(buffer.split_to(self.chunk_size).freeze());
        }
        completed_chunks
    }

    fn finalize(&self, buffer: &mut BytesMut) -> Option<Bytes> {
        if !buffer.is_empty() {
            Some(buffer.split().freeze())
        } else {
            None
        }
    }
}

pub struct DynamicCDCStrategy {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
}

impl ChunkingStrategy for DynamicCDCStrategy {
    fn process(&self, buffer: &mut BytesMut) -> Vec<Bytes> {
        let mut completed_chunks = Vec::new();

        loop {
            // We only process if we have at least min_size or more than max_size to avoid tiny overhead
            if buffer.len() < self.min_size {
                break;
            }

            let mut chunker = fastcdc::v2020::FastCDC::new(
                &buffer[..],
                self.min_size.try_into().unwrap(),
                self.avg_size.try_into().unwrap(),
                self.max_size.try_into().unwrap(),
            );

            // Get the first chunk cut point
            let chunk = chunker.next();

            match chunk {
                Some(chunk) => {
                    let end = chunk.offset + chunk.length;
                    // If the chunker consumed EVERYTHING, it might be an incomplete chunk at the tail.
                    // We only consume it if it hit max_size (enforced cut) or it literally isn't the whole buffer anymore.
                    if end < buffer.len() || chunk.length >= self.max_size {
                        let data = buffer.split_to(end).freeze();
                        completed_chunks.push(data);
                    } else {
                        // This bit is potentially the start of a much larger chunk, wait for more data.
                        break;
                    }
                }
                None => break,
            }
        }

        completed_chunks
    }

    fn finalize(&self, buffer: &mut BytesMut) -> Option<Bytes> {
        if !buffer.is_empty() {
            Some(buffer.split().freeze())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(data: &[u8]) -> BytesMut {
        BytesMut::from(data)
    }

    // ── FixedSizeStrategy ────────────────────────────────────────────────────

    #[test]
    fn fixed_exact_multiple_produces_correct_chunks() {
        let s = FixedSizeStrategy { chunk_size: 4 };
        let mut buf = make_buf(b"abcdefgh"); // 8 bytes → 2 chunks of 4
        let chunks = s.process(&mut buf);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].as_ref(), b"abcd");
        assert_eq!(chunks[1].as_ref(), b"efgh");
        assert!(buf.is_empty());
        assert!(s.finalize(&mut buf).is_none());
    }

    #[test]
    fn fixed_remainder_held_in_buffer() {
        let s = FixedSizeStrategy { chunk_size: 4 };
        let mut buf = make_buf(b"abcde"); // 5 bytes → 1 full chunk + 1 remainder
        let chunks = s.process(&mut buf);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref(), b"abcd");
        assert_eq!(buf.as_ref(), b"e");
    }

    #[test]
    fn fixed_finalize_flushes_remainder() {
        let s = FixedSizeStrategy { chunk_size: 4 };
        let mut buf = make_buf(b"abc");
        let chunks = s.process(&mut buf);
        assert!(chunks.is_empty());
        let tail = s.finalize(&mut buf).expect("should have remainder");
        assert_eq!(tail.as_ref(), b"abc");
        assert!(buf.is_empty());
    }

    #[test]
    fn fixed_empty_input_produces_nothing() {
        let s = FixedSizeStrategy { chunk_size: 4 };
        let mut buf = make_buf(b"");
        assert!(s.process(&mut buf).is_empty());
        assert!(s.finalize(&mut buf).is_none());
    }

    #[test]
    fn fixed_single_byte_chunk_size() {
        let s = FixedSizeStrategy { chunk_size: 1 };
        let mut buf = make_buf(b"xyz");
        let chunks = s.process(&mut buf);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].as_ref(), b"x");
        assert_eq!(chunks[1].as_ref(), b"y");
        assert_eq!(chunks[2].as_ref(), b"z");
    }

    #[test]
    fn fixed_chunk_larger_than_input_yields_nothing_from_process() {
        let s = FixedSizeStrategy { chunk_size: 1000 };
        let mut buf = make_buf(b"small");
        assert!(s.process(&mut buf).is_empty());
        assert_eq!(buf.as_ref(), b"small");
        let tail = s.finalize(&mut buf).unwrap();
        assert_eq!(tail.as_ref(), b"small");
    }

    #[test]
    fn fixed_process_then_finalize_concatenates_to_original() {
        let s = FixedSizeStrategy { chunk_size: 3 };
        let original = b"abcdefghij"; // 10 bytes → 3+3+3 from process, 1 from finalize
        let mut buf = make_buf(original);
        let mut result: Vec<u8> = Vec::new();
        for chunk in s.process(&mut buf) {
            result.extend_from_slice(&chunk);
        }
        if let Some(tail) = s.finalize(&mut buf) {
            result.extend_from_slice(&tail);
        }
        assert_eq!(result.as_slice(), original.as_ref());
    }

    #[test]
    fn fixed_incremental_feeding_matches_bulk() {
        // Simulate streaming: feed 2 bytes at a time into chunk_size=4.
        let s = FixedSizeStrategy { chunk_size: 4 };
        let original = b"abcdefghij";
        let mut all_chunks: Vec<Bytes> = Vec::new();
        let mut buf = BytesMut::new();
        for byte in original.iter() {
            buf.extend_from_slice(&[*byte]);
            all_chunks.extend(s.process(&mut buf));
        }
        if let Some(tail) = s.finalize(&mut buf) {
            all_chunks.push(tail);
        }
        let reassembled: Vec<u8> = all_chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(reassembled, original);
    }

    // ── DynamicCDCStrategy ───────────────────────────────────────────────────

    fn cdc() -> DynamicCDCStrategy {
        DynamicCDCStrategy {
            min_size: 512,
            avg_size: 1024,
            max_size: 2048,
        }
    }

    #[test]
    fn cdc_empty_input_produces_nothing() {
        let s = cdc();
        let mut buf = make_buf(b"");
        assert!(s.process(&mut buf).is_empty());
        assert!(s.finalize(&mut buf).is_none());
    }

    #[test]
    fn cdc_small_input_below_min_not_flushed_by_process() {
        let s = cdc();
        let mut buf = make_buf(&[0xAB; 100]); // below min_size=512
        assert!(s.process(&mut buf).is_empty());
        assert_eq!(buf.len(), 100, "buffer should be unchanged");
    }

    #[test]
    fn cdc_finalize_flushes_sub_min_remainder() {
        let s = cdc();
        let mut buf = make_buf(&[0xCD; 100]);
        s.process(&mut buf);
        let tail = s.finalize(&mut buf).expect("finalize should return remainder");
        assert_eq!(tail.len(), 100);
    }

    #[test]
    fn cdc_large_input_respects_max_size() {
        let s = cdc();
        // 10 KB of data; every chunk must be ≤ max_size.
        let data = vec![0x42u8; 10 * 1024];
        let mut buf = BytesMut::from(data.as_slice());
        let mut chunks = s.process(&mut buf);
        if let Some(tail) = s.finalize(&mut buf) {
            chunks.push(tail);
        }
        for chunk in &chunks {
            assert!(
                chunk.len() <= s.max_size,
                "chunk of {} bytes exceeds max_size {}",
                chunk.len(),
                s.max_size
            );
        }
    }

    #[test]
    fn cdc_large_input_reassembles_to_original() {
        let s = cdc();
        let original: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
        let mut buf = BytesMut::from(original.as_slice());
        let mut chunks = s.process(&mut buf);
        if let Some(tail) = s.finalize(&mut buf) {
            chunks.push(tail);
        }
        let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(reassembled, original);
    }

    #[test]
    fn cdc_identical_content_produces_identical_chunk_boundaries() {
        let s = cdc();
        let data: Vec<u8> = (0u8..=255).cycle().take(5 * 1024).collect();

        let mut buf1 = BytesMut::from(data.as_slice());
        let mut c1 = s.process(&mut buf1);
        if let Some(t) = s.finalize(&mut buf1) { c1.push(t); }

        let mut buf2 = BytesMut::from(data.as_slice());
        let mut c2 = s.process(&mut buf2);
        if let Some(t) = s.finalize(&mut buf2) { c2.push(t); }

        assert_eq!(c1.len(), c2.len(), "chunk count must be deterministic");
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a, b, "chunk boundaries must be identical for identical input");
        }
    }
}
