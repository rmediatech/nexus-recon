use nexus_scanner::sweep::{SubnetSweeper, SweepConfig};
use nexus_scanner::tcp::{PortScanner, ScanTarget};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_rw_tcp_scanner_detects_open_and_closed_ports() {
    // Start local test TCP listener on an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();

    let target = ScanTarget {
        ip: "127.0.0.1".parse().unwrap(),
        ports: vec![local_port, 64998], // 64998 is closed
        timeout_ms: 200,
    };

    let results = PortScanner::scan_ports(&target, 10).await;
    assert_eq!(results.len(), 2);

    let open_res = results.iter().find(|r| r.port == local_port).unwrap();
    assert!(open_res.open);

    let closed_res = results.iter().find(|r| r.port == 64998).unwrap();
    assert!(!closed_res.open);
}

#[tokio::test]
async fn test_rw_subnet_sweeper_discovers_active_listeners() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();

    let config = SweepConfig {
        cidr: "127.0.0.1/32".to_string(),
        ports: vec![local_port],
        concurrency: 5,
        timeout_ms: 100,
    };

    let sweeper = SubnetSweeper::new(config);
    let hosts = sweeper.execute_sweep().await.unwrap();

    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip.to_string(), "127.0.0.1");
    assert_eq!(hosts[0].open_ports, vec![local_port]);
}

#[tokio::test]
async fn test_ec_scanner_timeout_on_unreachable_ip() {
    let target = ScanTarget {
        ip: "192.0.2.1".parse().unwrap(), // TEST-NET-1 (unroutable)
        ports: vec![80],
        timeout_ms: 50,
    };

    let results = PortScanner::scan_ports(&target, 5).await;
    assert_eq!(results.len(), 1);
    assert!(!results[0].open);
}
