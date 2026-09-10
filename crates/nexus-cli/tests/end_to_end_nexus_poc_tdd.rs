use nexus_core::{NexusConfig, SubnetAuditSnapshot, SubnetRadixTrie, SubnetScanner};
use nexus_ledger::NexusLedger;
use nexus_reports::{export_air_gapped_json, generate_html_dossier, import_air_gapped_json};

#[test]
fn test_poc_end_to_end_subnet_recon_and_dossier_flow() {
    // 1. Initialize config & in-memory SQLite WAL ledger
    let config = NexusConfig::default();
    let ledger = NexusLedger::open_in_memory().expect("Ledger must open");

    // 2. Scan subnet
    let scanner = SubnetScanner::default();
    let hosts = scanner
        .simulate_subnet_scan(&config.subnet_cidr, &config.scan_ports)
        .expect("Subnet scan simulation should succeed");

    assert!(!hosts.is_empty());

    // 3. Index into Radix Trie
    let mut trie = SubnetRadixTrie::new();
    for h in &hosts {
        trie.insert(h.clone());
        ledger.upsert_host(h).expect("Upsert should succeed");
    }

    let all_trie_hosts = trie.all_hosts();
    assert_eq!(all_trie_hosts.len(), hosts.len());

    // 4. Record Snapshot
    let snapshot = SubnetAuditSnapshot::new(&config.subnet_cidr, 254, hosts, &config.secret_key);
    ledger.record_snapshot(&snapshot).expect("Snapshot should record");

    // 5. Generate Zero-CDN HTML Dossier
    let html = generate_html_dossier(&snapshot, &config.node_label);
    assert!(html.contains("NEXUS-RECON : SUBNET AUDIT DOSSIER"));
    assert!(html.contains("<svg"));
    assert!(!html.contains("<script src=\"http"));
    assert!(!html.contains("cdn."));

    // 6. Air-gapped JSON export & import roundtrip
    let json_dump = export_air_gapped_json(&snapshot);
    let imported = import_air_gapped_json(&json_dump, &config.secret_key)
        .expect("Air-gapped JSON should import and verify signature");

    assert_eq!(imported.id, snapshot.id);
    assert_eq!(imported.hosts.len(), snapshot.hosts.len());
}
