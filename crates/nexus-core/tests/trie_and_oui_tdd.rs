use chrono::Utc;
use nexus_core::{HostRecord, HostStatus, OuiDatabase, SubnetRadixTrie};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_rw_radix_trie_insert_and_lookup() {
    let mut trie = SubnetRadixTrie::new();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 57));

    let record = HostRecord {
        ip,
        mac: Some("b8:27:eb:01:02:03".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("hyperion-prime".to_string()),
        open_ports: vec![22, 8084],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.45,
    };

    trie.insert(record.clone());

    let found = trie.lookup(&ip).expect("Must find inserted host in Radix Trie");
    assert_eq!(found.hostname.as_deref(), Some("hyperion-prime"));
    assert_eq!(found.open_ports, vec![22, 8084]);
    assert_eq!(trie.all_hosts().len(), 1);
}

#[test]
fn test_ec_radix_trie_non_existent_lookup() {
    let trie = SubnetRadixTrie::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(trie.lookup(&ip).is_none());
}

#[test]
fn test_rw_oui_database_lookups() {
    let db = OuiDatabase::new();
    assert_eq!(db.lookup("B8:27:EB:AA:BB:CC"), "Raspberry Pi Foundation");
    assert_eq!(db.lookup("ac-de-48-11-22-33"), "Apple, Inc.");
    assert_eq!(db.lookup("001a11ffeedd"), "Google LLC");
    assert_eq!(db.lookup("ffffffffffff"), "Unknown Vendor / Generic NIC");
}
