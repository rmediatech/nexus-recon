use nexus_core::fingerprint::ServiceFingerprintMatcher;
use nexus_core::models::PortScanResult;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub ip: IpAddr,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

pub struct PortScanner;

impl PortScanner {
    pub async fn scan_single_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortScanResult {
        let addr = SocketAddr::new(ip, port);
        let timeout_dur = Duration::from_millis(timeout_ms);
        let start = std::time::Instant::now();

        match tokio::time::timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                
                // Attempt brief banner grab
                let mut banner_buf = [0u8; 256];
                let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                let service_name = match tokio::time::timeout(Duration::from_millis(50), stream.read(&mut banner_buf)).await {
                    Ok(Ok(n)) if n > 0 => Some(ServiceFingerprintMatcher::identify_from_banner(&banner_buf[..n], port)),
                    _ => Some(ServiceFingerprintMatcher::lookup_by_port(port).to_string()),
                };

                PortScanResult {
                    ip,
                    port,
                    open: true,
                    service_name,
                    latency_ms,
                }
            }
            _ => PortScanResult {
                ip,
                port,
                open: false,
                service_name: None,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            },
        }
    }

    pub async fn scan_ports(target: &ScanTarget, concurrency: usize) -> Vec<PortScanResult> {
        let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
        let mut tasks = Vec::new();

        for port in &target.ports {
            let p = *port;
            let ip = target.ip;
            let timeout_ms = target.timeout_ms;
            let sem = Arc::clone(&semaphore);

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                Self::scan_single_port(ip, p, timeout_ms).await
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(res) = task.await {
                results.push(res);
            }
        }
        results
    }
}
