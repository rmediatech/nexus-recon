use chrono::Utc;
use nexus_core::diff::{NetworkDiff, SnapshotDiffEngine};
use nexus_core::models::{HostRecord, HostStatus, SubnetAuditSnapshot};
use nexus_core::safety::{NexusAction, NexusSafetyMatrix, SafetyTier};
use std::net::IpAddr;

fn make_test_host(ip_str: &str, ports: Vec<u16>, status: HostStatus) -> HostRecord {
    let ip: IpAddr = ip_str.parse().unwrap();
    HostRecord {
        ip,
        mac: Some("00:11:22:33:44:55".to_string()),
        vendor: Some("Cisco Systems".to_string()),
        hostname: Some(format!("host-{}", ip_str.replace('.', "-"))),
        open_ports: ports,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status,
        latency_ms: 1.25,
    }
}

#[test]
fn test_rw_safety_matrix_tier1_read_only_allowed() {
    let matrix = NexusSafetyMatrix::new("secret-recon-token", "DANGER-CONFIRM-99");
    assert!(matrix.evaluate_action(NexusAction::QueryHosts, None, None, false).is_ok());
    assert!(matrix.evaluate_action(NexusAction::GenerateReport, None, None, false).is_ok());
}

#[test]
fn test_rw_safety_matrix_tier2_active_scan_requires_token() {
    let matrix = NexusSafetyMatrix::new("secret-recon-token", "DANGER-CONFIRM-99");
    // Without token -> blocked
    assert!(matrix.evaluate_action(NexusAction::ActiveSubnetScan, None, None, false).is_err());
    // With valid token -> allowed
    assert!(matrix.evaluate_action(NexusAction::ActiveSubnetScan, Some("secret-recon-token"), None, false).is_ok());
}

#[test]
fn test_rw_safety_matrix_tier4_destructive_requires_danger_code() {
    let matrix = NexusSafetyMatrix::new("secret-recon-token", "DANGER-CONFIRM-99");
    // With token but without danger code -> blocked
    assert!(matrix.evaluate_action(NexusAction::IsolateHost, Some("secret-recon-token"), None, false).is_err());
    // With token and valid danger code -> allowed
    assert!(matrix.evaluate_action(NexusAction::IsolateHost, Some("secret-recon-token"), Some("DANGER-CONFIRM-99"), false).is_ok());
}

#[test]
fn test_rw_snapshot_diff_engine_detects_rogue_and_port_changes() {
    let h1 = make_test_host("192.168.1.10", vec![22, 80], HostStatus::Trusted);
    let h2 = make_test_host("192.168.1.20", vec![443], HostStatus::Active);

    let snap_a = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![h1.clone(), h2.clone()], "sec");

    // In Snapshot B:
    // - 192.168.1.10 opened port 8080
    // - 192.168.1.20 disappeared
    // - 192.168.1.99 appeared as ROGUE host with port 11434
    let mut h1_mod = h1.clone();
    h1_mod.open_ports = vec![22, 80, 8080];

    let h3_rogue = make_test_host("192.168.1.99", vec![11434], HostStatus::Rogue);

    let snap_b = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![h1_mod, h3_rogue], "sec");

    let diff: NetworkDiff = SnapshotDiffEngine::compute_diff(&snap_a, &snap_b);

    assert_eq!(diff.new_hosts.len(), 1);
    assert_eq!(diff.new_hosts[0].ip.to_string(), "192.168.1.99");
    assert_eq!(diff.new_hosts[0].status, HostStatus::Rogue);

    assert_eq!(diff.missing_hosts.len(), 1);
    assert_eq!(diff.missing_hosts[0].ip.to_string(), "192.168.1.20");

    assert_eq!(diff.opened_ports.len(), 1);
    assert_eq!(diff.opened_ports[0].port, 8080);
}
