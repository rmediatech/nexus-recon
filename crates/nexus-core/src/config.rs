use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use crate::error::{NexusError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusConfig {
    #[serde(default = "default_node_label")]
    pub node_label: String,

    #[serde(default = "default_subnet_cidr")]
    pub subnet_cidr: String,

    #[serde(default = "default_scan_ports")]
    pub scan_ports: Vec<u16>,

    #[serde(default = "default_db_path")]
    pub db_path: String,

    #[serde(default = "default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    #[serde(default = "default_secret_key")]
    pub secret_key: String,
}

fn default_node_label() -> String {
    "hyperion-prime".to_string()
}

fn default_subnet_cidr() -> String {
    "192.168.1.0/24".to_string()
}

fn default_scan_ports() -> Vec<u16> {
    vec![22, 53, 80, 443, 3000, 8080, 8084, 11434]
}

fn default_db_path() -> String {
    "nexus_ledger.db".to_string()
}

fn default_scan_interval_secs() -> u64 {
    60
}

fn default_secret_key() -> String {
    "nexus-secret-recon-key-99".to_string()
}

impl Default for NexusConfig {
    fn default() -> Self {
        Self {
            node_label: default_node_label(),
            subnet_cidr: default_subnet_cidr(),
            scan_ports: default_scan_ports(),
            db_path: default_db_path(),
            scan_interval_secs: default_scan_interval_secs(),
            secret_key: default_secret_key(),
        }
    }
}

impl NexusConfig {
    pub fn validate(&self) -> Result<()> {
        if self.node_label.trim().is_empty() {
            return Err(NexusError::Validation("node_label cannot be empty".into()));
        }

        if !self.subnet_cidr.contains('/') {
            return Err(NexusError::Validation("subnet_cidr must be valid CIDR notation (e.g. 192.168.1.0/24)".into()));
        }

        if self.db_path.contains("..") {
            return Err(NexusError::Validation("Path traversal characters '..' forbidden in db_path".into()));
        }

        if self.scan_ports.is_empty() {
            return Err(NexusError::Validation("scan_ports list cannot be empty".into()));
        }

        if self.scan_interval_secs == 0 {
            return Err(NexusError::Validation("scan_interval_secs must be greater than 0".into()));
        }

        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn discover_or_default(explicit_path: Option<&Path>) -> Result<(Self, PathBuf)> {
        if let Some(path) = explicit_path {
            if path.exists() {
                let config = Self::load_from_file(path)?;
                return Ok((config, path.to_path_buf()));
            } else {
                return Err(NexusError::Config(format!(
                    "Explicit config path does not exist: {}",
                    path.display()
                )));
            }
        }

        let candidates = vec![
            PathBuf::from("nexus-recon.toml"),
            dirs_next_config_path(),
            PathBuf::from("/etc/nexus-recon/nexus-recon.toml"),
        ];

        for candidate in candidates {
            if candidate.exists() {
                if let Ok(config) = Self::load_from_file(&candidate) {
                    return Ok((config, candidate));
                }
            }
        }

        let default_config = Self::default();
        Ok((default_config, PathBuf::from("in-memory-default")))
    }

    pub fn generate_default_template() -> String {
        r#"# ====================================================================
# 📡 NEXUS-RECON AIR-GAPPED SUBNET INCIDENT COMMANDER CONFIGURATION
# Inside-Out Subnet Reconnaissance & Radix Trie Mapper
# ====================================================================

node_label = "hyperion-prime"
subnet_cidr = "192.168.1.0/24"
scan_ports = [22, 53, 80, 443, 3000, 8080, 8084, 11434]
db_path = "nexus_ledger.db"
scan_interval_secs = 60
secret_key = "nexus-secret-recon-key-99"
"#
        .to_string()
    }
}

fn dirs_next_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/nexus-recon/nexus-recon.toml")
    } else {
        PathBuf::from("nexus-recon.toml")
    }
}
