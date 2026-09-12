use chrono::Utc;
use nexus_core::{HostRecord, HostStatus, SubnetAuditSnapshot};
use nexus_ledger::NexusLedger;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_rw_ledger_host_upsert_and_retrieve() {
    let ledger = NexusLedger::open_in_memory().expect("In-memory ledger must open");
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 57));

    let host = HostRecord {
        ip,
        mac: Some("b8:27:eb:01:02:03".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("hyperion-prime".to_string()),
        open_ports: vec![22, 8084],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.42,
    };

    ledger.upsert_host(&host).expect("Upsert should succeed");

    let hosts = ledger.list_hosts(100).expect("List should succeed");
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, ip);
    assert_eq!(hosts[0].hostname.as_deref(), Some("hyperion-prime"));
    assert_eq!(hosts[0].open_ports, vec![22, 8084]);
}

#[test]
fn test_rw_ledger_snapshot_persistence() {
    let ledger = NexusLedger::open_in_memory().expect("In-memory ledger must open");
    let host = HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        mac: Some("74:83:c2:00:11:22".to_string()),
        vendor: Some("Ubiquiti Networks".to_string()),
        hostname: Some("gateway".to_string()),
        open_ports: vec![53, 443],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.3,
    };

    let snapshot = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![host], "test-secret");
    ledger.record_snapshot(&snapshot).expect("Snapshot should record cleanly");

    let snapshots = ledger.list_snapshots(10).expect("Should list snapshots");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].subnet_cidr, "192.168.1.0/24");
    assert_eq!(snapshots[0].hosts.len(), 1);
}

#[test]
fn test_attack_sql_injection_defense() {
    let ledger = NexusLedger::open_in_memory().expect("In-memory ledger must open");
    let injection_host = HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        mac: Some("00:11:22:33:44:55".to_string()),
        vendor: Some("Generic'; DROP TABLE hosts; --".to_string()),
        hostname: Some("evil-host' OR '1'='1".to_string()),
        open_ports: vec![80],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Rogue,
        latency_ms: 5.0,
    };

    ledger.upsert_host(&injection_host).expect("Parameterized query must safely escape payload");

    let hosts = ledger.list_hosts(100).expect("Table must still exist and query cleanly");
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostname.as_deref(), Some("evil-host' OR '1'='1"));
}
