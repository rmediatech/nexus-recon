use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus};
use nexus_reports::document::NexusReportDocument;
use nexus_reports::formatters::{AsciiFormatter, CsvFormatter, HtmlFormatter, JsonFormatter, JsonlFormatter, MarkdownFormatter};
use std::net::IpAddr;

fn sample_document() -> NexusReportDocument {
    let mut doc = NexusReportDocument::new("hyperion-recon", "192.168.1.0/24");
    doc.add_host(HostRecord {
        ip: "192.168.1.1".parse().unwrap(),
        mac: Some("00:1A:2B:3C:4D:5E".to_string()),
        vendor: Some("Ubiquiti Networks".to_string()),
        hostname: Some("gateway-ubnt".to_string()),
        open_ports: vec![22, 53, 443],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Trusted,
        latency_ms: 0.45,
    });
    doc.add_host(HostRecord {
        ip: "192.168.1.99".parse().unwrap(),
        mac: Some("B8:27:EB:01:02:03".to_string()),
        vendor: Some("Raspberry Pi Foundation".to_string()),
        hostname: Some("rogue-pi".to_string()),
        open_ports: vec![22, 11434],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Rogue,
        latency_ms: 1.82,
    });
    doc
}

#[test]
fn test_rw_html_formatter_native_and_responsive() {
    let doc = sample_document();
    let html = HtmlFormatter::render(&doc);

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("<html lang=\"en\">"));
    assert!(html.contains("NEXUS-RECON"));
    assert!(html.contains("gateway-ubnt"));
    assert!(html.contains("rogue-pi"));
    assert!(html.contains("data-action=\"copy-curl\""));
}

#[test]
fn test_rw_ascii_formatter_ansi_tables() {
    let doc = sample_document();
    let ascii = AsciiFormatter::render(&doc);

    assert!(ascii.contains("NEXUS-RECON"));
    assert!(ascii.contains("192.168.1.1"));
    assert!(ascii.contains("Ubiquiti Networks"));
    assert!(ascii.contains("192.168.1.99"));
}

#[test]
fn test_rw_markdown_formatter_github_flavor() {
    let doc = sample_document();
    let md = MarkdownFormatter::render(&doc);

    assert!(md.contains("# 🛡️ NEXUS-RECON"));
    assert!(md.contains("| IP | Hostname | MAC | Vendor | Ports | Status | Latency |"));
    assert!(md.contains("`192.168.1.99`"));
}

#[test]
fn test_rw_csv_formatter_rfc4180() {
    let doc = sample_document();
    let csv = CsvFormatter::render(&doc);

    assert!(csv.starts_with("ip,hostname,mac,vendor,open_ports,status,latency_ms"));
    assert!(csv.contains("\"192.168.1.1\",\"gateway-ubnt\""));
}

#[test]
fn test_rw_json_and_jsonl_formatters() {
    let doc = sample_document();
    let json = JsonFormatter::render(&doc);
    let jsonl = JsonlFormatter::render(&doc);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");
    assert_eq!(parsed["node_label"], "hyperion-recon");
    assert_eq!(jsonl.lines().count(), 2);
}
