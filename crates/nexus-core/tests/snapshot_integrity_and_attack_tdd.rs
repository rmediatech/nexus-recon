use chrono::Utc;
use nexus_core::{HostRecord, HostStatus, SubnetAuditSnapshot};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_rw_snapshot_signature_verification() {
    let secret = "recon-secret-key-123456";
    let hosts = vec![HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        mac: Some("74:83:c2:00:11:22".to_string()),
        vendor: Some("Ubiquiti Networks".to_string()),
        hostname: Some("gateway-router".to_string()),
        open_ports: vec![53, 80, 443],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.25,
    }];

    let snapshot = SubnetAuditSnapshot::new("192.168.1.0/24", 254, hosts, secret);
    assert_eq!(snapshot.active_hosts_count, 1);
    assert_eq!(snapshot.rogue_hosts_count, 0);
    assert!(snapshot.verify_signature(secret).is_ok());
}

#[test]
fn test_attack_snapshot_payload_tamper_detected() {
    let secret = "recon-secret-key-123456";
    let hosts = vec![HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        mac: Some("b8:27:eb:00:11:22".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("node-01".to_string()),
        open_ports: vec![22],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 0.5,
    }];

    let mut snapshot = SubnetAuditSnapshot::new("192.168.1.0/24", 254, hosts, secret);
    // Tamper with scanned count
    snapshot.total_hosts_scanned = 999;

    assert!(snapshot.verify_signature(secret).is_err(), "Tampered total_hosts_scanned must cause signature mismatch");
}

#[test]
fn test_attack_snapshot_host_injection_tamper() {
    let secret = "recon-secret-key-123456";
    let hosts = vec![HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        mac: Some("b8:27:eb:00:11:22".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("node-01".to_string()),
        open_ports: vec![22],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 0.5,
    }];

    let mut snapshot = SubnetAuditSnapshot::new("192.168.1.0/24", 254, hosts, secret);

    // Injected unauthorized rogue host
    snapshot.hosts.push(HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
        mac: Some("24:a1:60:99:99:99".to_string()),
        vendor: Some("Espressif Systems".to_string()),
        hostname: Some("injected-sniffer".to_string()),
        open_ports: vec![80],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Rogue,
        latency_ms: 3.2,
    });

    assert!(snapshot.verify_signature(secret).is_err(), "Injected host must trigger signature verification failure");
}
