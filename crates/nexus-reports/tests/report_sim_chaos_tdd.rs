use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus};
use nexus_reports::document::NexusReportDocument;
use nexus_reports::formatters::HtmlFormatter;

#[test]
fn test_sim_chaos_100_hosts_pipeline() {
    let mut doc = NexusReportDocument::new("chaos-node", "10.0.0.0/16");

    for i in 1..=100 {
        let status = if i % 10 == 0 {
            HostStatus::Rogue
        } else if i % 5 == 0 {
            HostStatus::Stale
        } else {
            HostStatus::Active
        };

        doc.add_host(HostRecord {
            ip: format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap(),
            mac: Some(format!("00:1A:2B:3C:{:02X}:{:02X}", i / 256, i % 256)),
            vendor: Some(format!("Vendor-{}", i % 7)),
            hostname: Some(format!("srv-node-{}", i)),
            open_ports: vec![22, 80, 443, 8080],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            status,
            latency_ms: (i as f64) * 0.12,
        });
    }

    let html = HtmlFormatter::render(&doc);
    assert!(html.contains("srv-node-100"));
    assert_eq!(doc.hosts.len(), 100);
}
