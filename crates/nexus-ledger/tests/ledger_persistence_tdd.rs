use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus, SubnetAuditSnapshot};
use nexus_ledger::repository::NexusLedger;
use tempfile::NamedTempFile;

fn make_sample_host(ip: &str, status: HostStatus) -> HostRecord {
    HostRecord {
        ip: ip.parse().unwrap(),
        mac: Some("00:50:56:c0:00:08".to_string()),
        vendor: Some("VMware, Inc.".to_string()),
        hostname: Some("vm-target".to_string()),
        open_ports: vec![22, 443],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status,
        latency_ms: 0.85,
    }
}

#[test]
fn test_rw_ledger_host_persistence_and_summary_stats() {
    let ledger = NexusLedger::open_in_memory().expect("Failed to open in-memory ledger");

    let h1 = make_sample_host("10.0.0.1", HostStatus::Trusted);
    let h2 = make_sample_host("10.0.0.2", HostStatus::Rogue);

    ledger.record_host(&h1).expect("Failed to record h1");
    ledger.record_host(&h2).expect("Failed to record h2");

    let hosts = ledger.list_hosts(50).expect("Failed to list hosts");
    assert_eq!(hosts.len(), 2);

    let stats = ledger.get_summary_stats().expect("Failed to get stats");
    assert_eq!(stats.total_hosts, 2);
    assert_eq!(stats.rogue_hosts, 1);
}

#[test]
fn test_ec_disk_persistence_across_reopens() {
    let temp_db = NamedTempFile::new().unwrap();
    let db_path = temp_db.path();

    {
        let ledger = NexusLedger::open(db_path).unwrap();
        let h = make_sample_host("172.16.0.5", HostStatus::Active);
        ledger.record_host(&h).unwrap();
    }

    {
        let ledger_reopened = NexusLedger::open(db_path).unwrap();
        let hosts = ledger_reopened.list_hosts(10).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip.to_string(), "172.16.0.5");
    }
}
