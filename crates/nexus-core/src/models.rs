use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use crate::error::{NexusError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Active,
    Stale,
    Rogue,
    Trusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: HostStatus,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub open: bool,
    pub service_name: Option<String>,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetAuditSnapshot {
    pub id: String,
    pub subnet_cidr: String,
    pub timestamp: DateTime<Utc>,
    pub total_hosts_scanned: usize,
    pub active_hosts_count: usize,
    pub rogue_hosts_count: usize,
    pub hosts: Vec<HostRecord>,
    pub signature: String,
}

impl SubnetAuditSnapshot {
    pub fn new(
        subnet_cidr: &str,
        total_hosts_scanned: usize,
        hosts: Vec<HostRecord>,
        secret: &str,
    ) -> Self {
        let timestamp = Utc::now();
        let id = format!("snap-{}-{}", subnet_cidr.replace('/', "-"), timestamp.timestamp());
        let active_hosts_count = hosts.iter().filter(|h| h.status == HostStatus::Active || h.status == HostStatus::Trusted).count();
        let rogue_hosts_count = hosts.iter().filter(|h| h.status == HostStatus::Rogue).count();

        let signature = Self::compute_signature(secret, &id, subnet_cidr, &timestamp, total_hosts_scanned, &hosts);

        Self {
            id,
            subnet_cidr: subnet_cidr.to_string(),
            timestamp,
            total_hosts_scanned,
            active_hosts_count,
            rogue_hosts_count,
            hosts,
            signature,
        }
    }

    pub fn compute_signature(
        secret: &str,
        id: &str,
        subnet_cidr: &str,
        timestamp: &DateTime<Utc>,
        total_hosts: usize,
        hosts: &[HostRecord],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(id.as_bytes());
        hasher.update(subnet_cidr.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(&total_hosts.to_be_bytes());

        for h in hosts {
            hasher.update(h.ip.to_string().as_bytes());
            if let Some(m) = &h.mac {
                hasher.update(m.as_bytes());
            }
            if let Some(name) = &h.hostname {
                hasher.update(name.as_bytes());
            }
            if let Some(v) = &h.vendor {
                hasher.update(v.as_bytes());
            }
            for p in &h.open_ports {
                hasher.update(&p.to_be_bytes());
            }
            hasher.update(format!("{:?}", h.status).as_bytes());
            hasher.update(&h.latency_ms.to_be_bytes());
        }

        hex::encode(hasher.finalize())
    }

    pub fn verify_signature(&self, secret: &str) -> Result<()> {
        let expected = Self::compute_signature(
            secret,
            &self.id,
            &self.subnet_cidr,
            &self.timestamp,
            self.total_hosts_scanned,
            &self.hosts,
        );

        if self.signature == expected {
            Ok(())
        } else {
            Err(NexusError::IntegrityMismatch {
                expected,
                actual: self.signature.clone(),
            })
        }
    }
}
