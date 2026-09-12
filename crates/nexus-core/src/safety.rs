use crate::error::{NexusError, Result};
use serde::{Deserialize, Serialize};

/// 4-Tier Security Matrix for Incident Response Actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyTier {
    /// Tier 1: Passive Recon / Status Queries (Read-only, no auth needed)
    Tier1ReadOnly,
    /// Tier 2: Active Subnet Scan / Port Probes (Requires auth token)
    Tier2SafeScan,
    /// Tier 3: State Modification / Host Tagging (Requires auth token + dry-run mode)
    Tier3StateModify,
    /// Tier 4: Destructive Action / Host Isolation / Port Kill (Requires auth token + explicit danger_code)
    Tier4Destructive,
}

/// Enumeration of all operational actions in NexusRecon
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NexusAction {
    QueryHosts,
    GenerateReport,
    ActiveSubnetScan,
    PortProbe,
    TagHostStatus,
    PurgeSnapshots,
    IsolateHost,
    KillPortConnection,
}

impl NexusAction {
    pub fn required_tier(&self) -> SafetyTier {
        match self {
            NexusAction::QueryHosts | NexusAction::GenerateReport => SafetyTier::Tier1ReadOnly,
            NexusAction::ActiveSubnetScan | NexusAction::PortProbe => SafetyTier::Tier2SafeScan,
            NexusAction::TagHostStatus | NexusAction::PurgeSnapshots => SafetyTier::Tier3StateModify,
            NexusAction::IsolateHost | NexusAction::KillPortConnection => SafetyTier::Tier4Destructive,
        }
    }
}

/// Cryptographic Safety Gatekeeper
#[derive(Debug, Clone)]
pub struct NexusSafetyMatrix {
    auth_token: String,
    danger_code: String,
}

impl NexusSafetyMatrix {
    pub fn new(auth_token: impl Into<String>, danger_code: impl Into<String>) -> Self {
        Self {
            auth_token: auth_token.into(),
            danger_code: danger_code.into(),
        }
    }

    pub fn evaluate_action(
        &self,
        action: NexusAction,
        provided_token: Option<&str>,
        provided_danger_code: Option<&str>,
        dry_run: bool,
    ) -> Result<()> {
        let tier = action.required_tier();

        match tier {
            SafetyTier::Tier1ReadOnly => Ok(()),

            SafetyTier::Tier2SafeScan => {
                let token = provided_token.ok_or(NexusError::Unauthorized("Auth token required for active scans".to_string()))?;
                if token != self.auth_token {
                    return Err(NexusError::Unauthorized("Invalid auth token".to_string()));
                }
                Ok(())
            }

            SafetyTier::Tier3StateModify => {
                let token = provided_token.ok_or(NexusError::Unauthorized("Auth token required for state modifications".to_string()))?;
                if token != self.auth_token {
                    return Err(NexusError::Unauthorized("Invalid auth token".to_string()));
                }
                if dry_run {
                    return Err(NexusError::DryRunBlocked("State change blocked by Dry-Run mode".to_string()));
                }
                Ok(())
            }

            SafetyTier::Tier4Destructive => {
                let token = provided_token.ok_or(NexusError::Unauthorized("Auth token required for destructive actions".to_string()))?;
                if token != self.auth_token {
                    return Err(NexusError::Unauthorized("Invalid auth token".to_string()));
                }
                let code = provided_danger_code.ok_or(NexusError::DestructiveActionBlocked("Missing danger confirmation code".to_string()))?;
                if code != self.danger_code {
                    return Err(NexusError::DestructiveActionBlocked("Invalid danger confirmation code".to_string()));
                }
                Ok(())
            }
        }
    }
}
