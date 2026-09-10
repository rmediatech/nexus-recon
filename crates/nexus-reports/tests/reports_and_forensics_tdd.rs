use chrono::Utc;
use nexus_core::{HostRecord, HostStatus, SubnetAuditSnapshot};
use nexus_reports::{export_air_gapped_json, generate_html_dossier, import_air_gapped_json};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_rw_html_dossier_zero_cdn_and_embedded_svg() {
    let host = HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 57)),
        mac: Some("b8:27:eb:01:02:03".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("hyperion-prime".to_string()),
        open_ports: vec![22, 8084],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.45,
    };

    let snapshot = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![host], "secret");
    let html = generate_html_dossier(&snapshot, "hyperion-prime");

    // Verify Zero-CDN Invariant (no external scripts or CDN links)
    assert!(!html.contains("<script src=\"http"), "Dossier must not load external scripts");
    assert!(!html.contains("<link href=\"http"), "Dossier must not load external stylesheets");
    assert!(!html.contains("cdn."), "Dossier must not load CDN assets");
    assert!(html.contains("<svg"), "Dossier must embed raw inline SVG");
    assert!(html.contains("hyperion-prime"));
    assert!(html.contains("Raspberry Pi Foundation"));
}

#[test]
fn test_rw_air_gapped_json_export_and_import() {
    let secret = "forensics-key-998877";
    let host = HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        mac: Some("ac:de:48:00:11:22".to_string()),
        vendor: Some("Apple, Inc.".to_string()),
        hostname: Some("macbook-air".to_string()),
        open_ports: vec![22],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 1.1,
    };

    let original = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![host], secret);
    let json_dump = export_air_gapped_json(&original);

    let imported = import_air_gapped_json(&json_dump, secret).expect("Signed JSON should import cleanly");
    assert_eq!(imported.id, original.id);
    assert_eq!(imported.hosts.len(), 1);
    assert_eq!(imported.hosts[0].hostname.as_deref(), Some("macbook-air"));
}

#[test]
fn test_attack_air_gapped_json_tamper_detected() {
    let secret = "forensics-key-998877";
    let host = HostRecord {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        mac: Some("ac:de:48:00:11:22".to_string()),
        vendor: Some("Apple, Inc.".to_string()),
        hostname: Some("macbook-air".to_string()),
        open_ports: vec![22],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 1.1,
    };

    let original = SubnetAuditSnapshot::new("192.168.1.0/24", 254, vec![host], secret);
    let json_dump = export_air_gapped_json(&original);

    // Tamper with payload
    let tampered_json = json_dump.replace("macbook-air", "trojan-macbook-exploit");

    let result = import_air_gapped_json(&tampered_json, secret);
    assert!(result.is_err(), "Tampered air-gapped JSON import must fail signature verification");
}

#[test]
fn test_ec_empty_hosts_report_rendering() {
    let snapshot = SubnetAuditSnapshot::new("10.0.0.0/24", 254, vec![], "secret");
    let html = generate_html_dossier(&snapshot, "hyperion-prime");
    assert!(html.contains("0 Hosts") || html.contains("254 Hosts"));
    assert!(html.contains("<svg"));
}
