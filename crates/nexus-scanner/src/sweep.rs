use crate::error::ScannerError;
use crate::tcp::{PortScanner, ScanTarget};
use chrono::Utc;
use ipnet::IpNet;
use nexus_core::models::{HostRecord, HostStatus};
use nexus_core::oui::OuiDatabase;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct SweepConfig {
    pub cidr: String,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            cidr: "192.168.1.0/24".to_string(),
            ports: vec![22, 80, 443, 554, 7880, 8080, 11434],
            concurrency: 50,
            timeout_ms: 250,
        }
    }
}

pub struct SubnetSweeper {
    config: SweepConfig,
    _oui: OuiDatabase,
}

impl SubnetSweeper {
    pub fn new(config: SweepConfig) -> Self {
        Self {
            config,
            _oui: OuiDatabase::new(),
        }
    }

    pub async fn execute_sweep(&self) -> Result<Vec<HostRecord>, ScannerError> {
        let net: IpNet = self.config.cidr.parse().map_err(|e| ScannerError::InvalidCidr(format!("{:?}", e)))?;
        let hosts_iter: Vec<IpAddr> = net.hosts().collect();

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut tasks = Vec::new();

        for ip in hosts_iter {
            let sem = Arc::clone(&semaphore);
            let ports = self.config.ports.clone();
            let timeout_ms = self.config.timeout_ms;

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let target = ScanTarget {
                    ip,
                    ports,
                    timeout_ms,
                };
                let port_results = PortScanner::scan_ports(&target, 10).await;
                (ip, port_results)
            }));
        }

        let mut discovered_hosts = Vec::new();

        for task in tasks {
            if let Ok((ip, port_results)) = task.await {
                let open_ports: Vec<u16> = port_results
                    .iter()
                    .filter(|r| r.open)
                    .map(|r| r.port)
                    .collect();

                // If any port is open or reachable, record host
                if !open_ports.is_empty() {
                    let avg_latency = port_results
                        .iter()
                        .filter(|r| r.open)
                        .map(|r| r.latency_ms)
                        .sum::<f64>()
                        / open_ports.len().max(1) as f64;

                    discovered_hosts.push(HostRecord {
                        ip,
                        mac: None,
                        vendor: None,
                        hostname: None,
                        open_ports,
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        status: HostStatus::Active,
                        latency_ms: avg_latency,
                    });
                }
            }
        }

        Ok(discovered_hosts)
    }
}
