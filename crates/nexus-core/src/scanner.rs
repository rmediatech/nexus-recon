use chrono::Utc;
use ipnet::Ipv4Net;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::error::{NexusError, Result};
use crate::models::{HostRecord, HostStatus, PortScanResult};
use crate::oui::OuiDatabase;

pub struct SubnetScanner {
    timeout_duration: Duration,
    oui_db: OuiDatabase,
}

impl SubnetScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms.max(10)),
            oui_db: OuiDatabase::new(),
        }
    }

    pub async fn check_port(&self, ip: IpAddr, port: u16) -> PortScanResult {
        let addr = SocketAddr::new(ip, port);
        let start = Instant::now();

        let open = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let service_name = if open {
            Some(Self::common_service_name(port))
        } else {
            None
        };

        PortScanResult {
            ip,
            port,
            open,
            service_name,
            latency_ms,
        }
    }

    pub fn common_service_name(port: u16) -> String {
        match port {
            22 => "SSH (Secure Shell)".to_string(),
            53 => "DNS (Domain Name System)".to_string(),
            80 => "HTTP (Web Server)".to_string(),
            443 => "HTTPS (TLS Web Server)".to_string(),
            3000 => "Node/React Dev Server".to_string(),
            8080 => "HTTP-Alt / Proxy".to_string(),
            8084 => "Conduit Sovereign Relay".to_string(),
            11434 => "Ollama Local AI Daemon".to_string(),
            _ => format!("Custom Port {}", port),
        }
    }

    pub fn simulate_subnet_scan(
        &self,
        cidr: &str,
        target_ports: &[u16],
    ) -> Result<Vec<HostRecord>> {
        let net = Ipv4Net::from_str(cidr).map_err(|e| NexusError::Network(e.to_string()))?;
        let mut hosts = Vec::new();
        let now = Utc::now();

        let mut count = 0;
        for ip in net.hosts().take(10) {
            count += 1;
            let (hostname, mac, open_ports, status, latency) = match count {
                1 => (Some("hyperion-prime".to_string()), Some("b8:27:eb:1a:2b:3c".to_string()), vec![22, 8084, 11434], HostStatus::Trusted, 0.38),
                2 => (Some("valkyrie-edge-02".to_string()), Some("ac:de:48:44:55:66".to_string()), vec![22, 80], HostStatus::Active, 1.22),
                3 => (Some("unauthorized-iot-sensor".to_string()), Some("24:a1:60:99:88:77".to_string()), vec![80], HostStatus::Rogue, 4.85),
                _ => (None, None, vec![], HostStatus::Stale, 0.0),
            };

            if status != HostStatus::Stale {
                let vendor = mac.as_ref().map(|m| self.oui_db.lookup(m));
                hosts.push(HostRecord {
                    ip: IpAddr::V4(ip),
                    mac,
                    vendor,
                    hostname,
                    open_ports: open_ports.into_iter().filter(|p| target_ports.contains(p) || target_ports.is_empty()).collect(),
                    first_seen: now - chrono::Duration::hours(2),
                    last_seen: now,
                    status,
                    latency_ms: latency,
                });
            }
        }

        Ok(hosts)
    }
}

impl Default for SubnetScanner {
    fn default() -> Self {
        Self::new(200)
    }
}
