use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus};
use nexus_reports::document::NexusReportDocument;
use nexus_reports::formatters::{CsvFormatter, HtmlFormatter};

#[test]
fn test_attack_csv_formula_injection_defense() {
    let mut doc = NexusReportDocument::new("node", "10.0.0.0/24");
    doc.add_host(HostRecord {
        ip: "10.0.0.1".parse().unwrap(),
        mac: Some("=cmd|' /C calc'!A0".to_string()),
        vendor: Some("+2+5+cmd".to_string()),
        hostname: Some("@SUM(1,2)".to_string()),
        open_ports: vec![80],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 1.0,
    });

    let csv = CsvFormatter::render(&doc);
    assert!(csv.contains("'\x3dcmd"));
    assert!(csv.contains("'+2+5"));
    assert!(csv.contains("'@SUM"));
}

#[test]
fn test_attack_html_xss_injection_sanitization() {
    let mut doc = NexusReportDocument::new("node", "10.0.0.0/24");
    doc.add_host(HostRecord {
        ip: "10.0.0.2".parse().unwrap(),
        mac: Some("<script>alert('xss')</script>".to_string()),
        vendor: Some("<img src=x onerror=alert(1)>".to_string()),
        hostname: Some("<b>bold-host</b>".to_string()),
        open_ports: vec![80],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 1.0,
    });

    let html = HtmlFormatter::render(&doc);
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&lt;img"));
}

#[test]
fn test_attack_strict_no_inline_css_or_js_attributes() {
    let mut doc = NexusReportDocument::new("node", "10.0.0.0/24");
    doc.add_host(HostRecord {
        ip: "10.0.0.1".parse().unwrap(),
        mac: None,
        vendor: None,
        hostname: None,
        open_ports: vec![22],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        status: HostStatus::Active,
        latency_ms: 1.0,
    });

    let html = HtmlFormatter::render(&doc);

    // Extract body contents to strictly test no inline styling or handlers
    let body_start = html.find("<body>").expect("Body tag missing");
    let body_end = html.find("</body>").expect("Body close tag missing");
    let body_content = &html[body_start..body_end];

    assert!(!body_content.contains("style="), "Found illegal inline style attribute in HTML body!");
    assert!(!body_content.contains("onclick="), "Found illegal inline onclick attribute in HTML body!");
    assert!(!body_content.contains("onload="), "Found illegal inline onload attribute in HTML body!");
    assert!(!body_content.contains("onchange="), "Found illegal inline onchange attribute in HTML body!");
}

#[test]
fn test_attack_strict_content_security_policy_enforcement() {
    let doc = NexusReportDocument::new("node", "10.0.0.0/24");
    let html = HtmlFormatter::render(&doc);

    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("default-src 'none'"));
}
