//! Shared metadata types + the policy engine.
//!
//! The metadata store itself now lives in `store.rs` (embedded SQLite). This
//! module keeps the provider-agnostic pieces — the IAM-style policy engine, the
//! replication-queue entry type, and a few shared constants — and re-exports the
//! store under the historical name `Db` so the rest of the codebase keeps
//! referring to `crate::db::Db`.

use serde::{Deserialize, Serialize};

/// The embedded store, exported under its historical name. `storage.rs` and
/// `main.rs` reference `crate::db::Db`; that contract is preserved.
pub use crate::store::Store as Db;

// Blocks that have failed this many replication attempts are surfaced as "stuck"
// for operator visibility. Used by the store's `get_stuck_replications`.
pub(crate) const REPLICATION_STUCK_ATTEMPTS: i32 = 10;

/// One pending block replication for the local site, as read from the queue.
#[derive(Debug, Clone)]
pub struct ReplicationEntry {
    pub hash: Vec<u8>,
    /// Clustering component; retained for API compatibility with callers that
    /// pass it back on dequeue. Drives backoff ordering.
    pub next_attempt_at: i64,
    /// Prior failure count, drives the backoff schedule.
    pub attempts: i32,
    /// Original enqueue time (ms epoch); preserved across reschedules and
    /// surfaced by get_stuck_replications. Not read on the drain path itself.
    #[allow(dead_code)]
    pub enqueued_at: i64,
}

// ── Policy engine ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub statements: Vec<PolicyStatement>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyStatement {
    pub effect: String,         // "Allow" or "Deny"
    pub actions: Vec<String>,   // e.g. "s3:GetObject"
    pub resources: Vec<String>, // e.g. "arn:ss:bucket:::my-bucket/*"
}

impl Policy {
    pub fn is_allowed(&self, action: &str, resource: &str) -> bool {
        let mut allowed = false;
        for stmt in &self.statements {
            if stmt.matches(action, resource) {
                if stmt.effect == "Deny" {
                    return false;
                }
                if stmt.effect == "Allow" {
                    allowed = true;
                }
            }
        }
        allowed
    }
}

impl PolicyStatement {
    pub fn matches(&self, action: &str, resource: &str) -> bool {
        let action_match = self.actions.iter().any(|a| wildcard_match(a, action));
        let resource_match = self.resources.iter().any(|r| wildcard_match(r, resource));
        action_match && resource_match
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── wildcard_match ────────────────────────────────────────────────────────

    #[test]
    fn wildcard_star_matches_anything() {
        assert!(wildcard_match("*", "s3:GetObject"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "arn:ss:bucket:::my-bucket/key"));
    }

    #[test]
    fn wildcard_exact_match() {
        assert!(wildcard_match("s3:GetObject", "s3:GetObject"));
        assert!(!wildcard_match("s3:GetObject", "s3:PutObject"));
        assert!(!wildcard_match("s3:GetObject", ""));
    }

    #[test]
    fn wildcard_prefix_star() {
        assert!(wildcard_match("s3:*", "s3:GetObject"));
        assert!(wildcard_match("s3:*", "s3:PutObject"));
        assert!(wildcard_match("s3:*", "s3:"));
        assert!(!wildcard_match("s3:*", "iam:GetUser"));
    }

    #[test]
    fn wildcard_arn_prefix() {
        assert!(wildcard_match("arn:ss:bucket:::my-bucket*", "arn:ss:bucket:::my-bucket/key"));
        assert!(wildcard_match("arn:ss:bucket:::my-bucket*", "arn:ss:bucket:::my-bucket"));
        assert!(!wildcard_match("arn:ss:bucket:::my-bucket*", "arn:ss:bucket:::other-bucket"));
    }

    #[test]
    fn wildcard_empty_pattern_only_matches_empty() {
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "anything"));
    }

    #[test]
    fn wildcard_star_only_in_prefix_position_does_not_match_suffix() {
        // Only suffix wildcards are supported; mid-string ones never match.
        assert!(!wildcard_match("s3:Get*Object", "s3:GetObject"));
    }

    // ── PolicyStatement::matches ──────────────────────────────────────────────

    fn stmt(effect: &str, actions: &[&str], resources: &[&str]) -> PolicyStatement {
        PolicyStatement {
            effect: effect.to_string(),
            actions: actions.iter().map(|s| s.to_string()).collect(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn statement_matches_exact_action_and_resource() {
        let s = stmt("Allow", &["s3:GetObject"], &["arn:ss:bucket:::my-bucket/key"]);
        assert!(s.matches("s3:GetObject", "arn:ss:bucket:::my-bucket/key"));
    }

    #[test]
    fn statement_does_not_match_wrong_action() {
        let s = stmt("Allow", &["s3:GetObject"], &["arn:ss:bucket:::my-bucket/key"]);
        assert!(!s.matches("s3:PutObject", "arn:ss:bucket:::my-bucket/key"));
    }

    #[test]
    fn statement_does_not_match_wrong_resource() {
        let s = stmt("Allow", &["s3:GetObject"], &["arn:ss:bucket:::my-bucket/key"]);
        assert!(!s.matches("s3:GetObject", "arn:ss:bucket:::other-bucket/key"));
    }

    #[test]
    fn statement_wildcard_action_matches_all() {
        let s = stmt("Allow", &["*"], &["arn:ss:bucket:::my-bucket"]);
        assert!(s.matches("s3:GetObject", "arn:ss:bucket:::my-bucket"));
        assert!(s.matches("s3:DeleteObject", "arn:ss:bucket:::my-bucket"));
    }

    #[test]
    fn statement_wildcard_resource_matches_all() {
        let s = stmt("Allow", &["s3:GetObject"], &["*"]);
        assert!(s.matches("s3:GetObject", "arn:ss:bucket:::any-bucket/any-key"));
    }

    #[test]
    fn statement_multiple_actions_any_can_match() {
        let s = stmt("Allow", &["s3:GetObject", "s3:HeadObject"], &["*"]);
        assert!(s.matches("s3:GetObject", "*"));
        assert!(s.matches("s3:HeadObject", "*"));
        assert!(!s.matches("s3:PutObject", "*"));
    }

    // ── Policy::is_allowed ────────────────────────────────────────────────────

    fn allow_all() -> Policy {
        Policy { statements: vec![stmt("Allow", &["*"], &["*"])] }
    }

    fn deny_all() -> Policy {
        Policy { statements: vec![stmt("Deny", &["*"], &["*"])] }
    }

    #[test]
    fn policy_allow_all_permits_any_action() {
        let p = allow_all();
        assert!(p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
        assert!(p.is_allowed("s3:DeleteBucket", "arn:ss:bucket:::b"));
    }

    #[test]
    fn policy_deny_all_rejects_any_action() {
        let p = deny_all();
        assert!(!p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
    }

    #[test]
    fn policy_empty_statements_denies_everything() {
        let p = Policy { statements: vec![] };
        assert!(!p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
    }

    #[test]
    fn policy_deny_takes_precedence_over_allow() {
        let p = Policy {
            statements: vec![
                stmt("Allow", &["*"], &["*"]),
                stmt("Deny", &["s3:DeleteObject"], &["*"]),
            ],
        };
        assert!(p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
        assert!(!p.is_allowed("s3:DeleteObject", "arn:ss:bucket:::b/k"));
    }

    #[test]
    fn policy_deny_evaluated_regardless_of_order() {
        let p = Policy {
            statements: vec![
                stmt("Deny", &["s3:DeleteBucket"], &["*"]),
                stmt("Allow", &["*"], &["*"]),
            ],
        };
        assert!(!p.is_allowed("s3:DeleteBucket", "arn:ss:bucket:::b"));
        assert!(p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
    }

    #[test]
    fn policy_allow_specific_bucket_denies_other() {
        let p = Policy {
            statements: vec![stmt("Allow", &["*"], &["arn:ss:bucket:::allowed-bucket*"])],
        };
        assert!(p.is_allowed("s3:GetObject", "arn:ss:bucket:::allowed-bucket/key"));
        assert!(!p.is_allowed("s3:GetObject", "arn:ss:bucket:::forbidden-bucket/key"));
    }

    #[test]
    fn policy_read_only_allows_get_denies_put() {
        let p = Policy {
            statements: vec![stmt(
                "Allow",
                &["s3:GetObject", "s3:HeadObject", "s3:ListBucket"],
                &["*"],
            )],
        };
        assert!(p.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
        assert!(p.is_allowed("s3:ListBucket", "arn:ss:bucket:::b"));
        assert!(!p.is_allowed("s3:PutObject", "arn:ss:bucket:::b/k"));
    }

    #[test]
    fn policy_json_round_trip() {
        let original = Policy {
            statements: vec![
                stmt("Allow", &["s3:GetObject", "s3:ListBucket"], &["arn:ss:bucket:::my-bucket*"]),
                stmt("Deny", &["s3:DeleteObject"], &["*"]),
            ],
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: Policy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            serde_json::to_value(&original).unwrap(),
            serde_json::to_value(&restored).unwrap()
        );
    }

    #[test]
    fn policy_json_invalid_is_error() {
        let result: Result<Policy, _> = serde_json::from_str("not-json");
        assert!(result.is_err());
    }
}
