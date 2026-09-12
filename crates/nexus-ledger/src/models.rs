use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LedgerSummaryStats {
    pub total_hosts: usize,
    pub active_hosts: usize,
    pub rogue_hosts: usize,
    pub stale_hosts: usize,
    pub total_open_ports: usize,
    pub total_snapshots: usize,
    pub total_blocks: usize,
}
