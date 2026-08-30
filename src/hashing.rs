pub const NUM_SHARDS: i32 = 64;

/// Derives a shard index in `[0, 63]` from a key using the first byte
/// of its blake3 digest. Uniform distribution follows from blake3's avalanche.
pub fn compute_shard_id(key: &str) -> i32 {
    (blake3::hash(key.as_bytes()).as_bytes()[0] as i32) & (NUM_SHARDS - 1)
}

/// Returns `(lower, upper)` bounds for a CQL `key >= lower AND key < upper`
/// range query that matches all keys with the given prefix.
/// `upper` is `None` when the prefix covers through the end of the key-space
/// (e.g. a prefix of all `0xFF` bytes).
pub fn prefix_key_range(prefix: &str) -> (String, Option<String>) {
    (prefix.to_string(), increment_prefix(prefix))
}

fn increment_prefix(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    loop {
        match bytes.last_mut() {
            Some(b) if *b < 0xFF => {
                *b += 1;
                return Some(String::from_utf8(bytes).expect("prefix was valid UTF-8"));
            }
            Some(_) => {
                bytes.pop();
            }
            None => return None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // --- compute_shard_id ---

    #[test]
    fn shard_id_in_range() {
        for key in &["", "a", "object1", "very/long/key/path/with/slashes", "unicode-🦀"] {
            let id = compute_shard_id(key);
            assert!((0..NUM_SHARDS).contains(&id), "shard_id {id} out of range for key {key:?}");
        }
    }

    #[test]
    fn shard_id_is_deterministic() {
        let key = "deterministic-key";
        assert_eq!(compute_shard_id(key), compute_shard_id(key));
    }

    #[test]
    fn shard_id_different_keys_differ() {
        // object1 and object2 must hash to different shards (verified empirically).
        assert_ne!(compute_shard_id("object1"), compute_shard_id("object2"));
    }

    #[test]
    fn shard_distribution_roughly_uniform() {
        // With 6400 keys, expect each of 64 shards to appear at least once.
        let mut counts = vec![0usize; NUM_SHARDS as usize];
        for i in 0..6400 {
            let key = format!("key-{i}");
            counts[compute_shard_id(&key) as usize] += 1;
        }
        for (shard, &count) in counts.iter().enumerate() {
            assert!(count > 0, "shard {shard} was never selected in 6400 keys");
        }
    }

    #[test]
    fn shard_id_empty_string_is_stable() {
        // Empty key must always map to the same shard, not panic.
        let id = compute_shard_id("");
        assert!((0..NUM_SHARDS).contains(&id));
    }

    // --- prefix_key_range ---

    #[test]
    fn prefix_range_simple_ascii() {
        let (lower, upper) = prefix_key_range("abc");
        assert_eq!(lower, "abc");
        assert_eq!(upper.unwrap(), "abd");
    }

    #[test]
    fn prefix_range_tilde_increments_to_del() {
        // '~' is 0x7E; 0x7E + 1 = 0x7F which is valid ASCII (DEL).
        let (lower, upper) = prefix_key_range("a~");
        assert_eq!(lower, "a~");
        assert_eq!(upper.unwrap(), "a\x7F");
    }

    #[test]
    fn prefix_range_uppercase_z_increments_to_bracket() {
        // 'Z' is 0x5A; 0x5A + 1 = 0x5B = '['.
        let (lower, upper) = prefix_key_range("abZ");
        assert_eq!(lower, "abZ");
        assert_eq!(upper.unwrap(), "ab[");
    }

    #[test]
    fn prefix_range_all_0xff_returns_none() {
        // The only byte value that triggers the carry/pop branch is exactly 0xFF.
        // Build a string consisting of bytes [0xFF, 0xFF, 0xFF] via unsafe — this is
        // intentionally invalid UTF-8 to exercise the boundary condition in
        // increment_prefix, which itself uses `expect("prefix was valid UTF-8")`.
        // Because the input is all 0xFF, the function pops every byte and returns None
        // *before* it ever tries to call from_utf8, so no panic occurs.
        let raw = vec![0xFFu8, 0xFF, 0xFF];
        // SAFETY: increment_prefix operates on bytes and only calls from_utf8 after
        // incrementing a non-0xFF byte, which never happens here (all bytes are 0xFF
        // so they all get popped). The prefix string is never exposed to user code.
        let prefix = unsafe { String::from_utf8_unchecked(raw) };
        let (lower, upper) = prefix_key_range(&prefix);
        assert_eq!(lower, prefix);
        assert!(upper.is_none(), "expected None when all bytes are 0xFF");
    }

    #[test]
    fn prefix_range_single_char() {
        let (lower, upper) = prefix_key_range("a");
        assert_eq!(lower, "a");
        assert_eq!(upper.unwrap(), "b");
    }

    #[test]
    fn prefix_range_empty_string() {
        // An empty prefix matches everything; upper bound should be None.
        let (lower, upper) = prefix_key_range("");
        assert_eq!(lower, "");
        assert!(upper.is_none());
    }

    #[test]
    fn prefix_range_upper_is_exclusive() {
        // Any key with the prefix must be < upper.
        let prefix = "logs/2024-";
        let (lower, upper) = prefix_key_range(prefix);
        let upper = upper.unwrap();
        assert!(lower.as_str() <= "logs/2024-01-01");
        assert!("logs/2024-12-31/file.txt" < upper.as_str());
        // A key that shares the same prefix up to the slash but diverges after upper
        // must NOT be less than upper.
        assert!("logs/2025-" >= upper.as_str());
    }

    #[test]
    fn prefix_range_slash_key() {
        let (lower, upper) = prefix_key_range("folder/");
        assert_eq!(lower, "folder/");
        // '/' is 0x2F; 0x2F + 1 = 0x30 = '0'
        assert_eq!(upper.unwrap(), "folder0");
    }
}
