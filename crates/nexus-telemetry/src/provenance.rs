use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detailed 5W1H incident minutiae
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentMinutiae {
    pub duration_ps: u64,
    pub hosts_discovered: usize,
    pub open_ports_found: usize,
    pub safety_tier: String,
    pub dry_run: bool,
    pub status_code: u16,
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl Default for IncidentMinutiae {
    fn default() -> Self {
        Self {
            duration_ps: 0,
            hosts_discovered: 0,
            open_ports_found: 0,
            safety_tier: "Tier1".to_string(),
            dry_run: false,
            status_code: 200,
            extra: HashMap::new(),
        }
    }
}

/// 5W1H Micro-Provenance Incident Timeline Event Schema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentProvenance {
    pub timestamp_utc: String,
    pub who: String,
    pub from: String,
    pub to: String,
    pub what: String,
    pub how: String,
    pub minutiae: IncidentMinutiae,
}

impl IncidentProvenance {
    pub fn new(
        who: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        what: impl Into<String>,
        how: impl Into<String>,
        minutiae: IncidentMinutiae,
    ) -> Self {
        Self {
            timestamp_utc: Utc::now().to_rfc3339(),
            who: who.into(),
            from: from.into(),
            to: to.into(),
            what: what.into(),
            how: how.into(),
            minutiae,
        }
    }

    pub fn compute_payload_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let serialized = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hex::encode(hasher.finalize())
    }
}
