use crate::document::NexusReportDocument;

pub struct AsciiFormatter;

impl AsciiFormatter {
    pub fn render(doc: &NexusReportDocument) -> String {
        let mut out = String::new();
        out.push_str("========================================================================================\n");
        out.push_str(&format!("🛡️  NEXUS-RECON : AIR-GAPPED SUBNET INCIDENT COMMANDER (Node: {})\n", doc.node_label));
        out.push_str(&format!("   Subnet Target: {} | Generated: {}\n", doc.subnet_cidr, doc.generated_at));
        out.push_str("========================================================================================\n");
        out.push_str(&format!("📋 EXECUTIVE SUMMARY:\n   {}\n\n", doc.executive_summary));
        out.push_str("┌─────────────────┬──────────────────────┬───────────────────┬──────────────────────────┬─────────────────┬──────────┬───────────┐\n");
        out.push_str("│ IP ADDRESS      │ HOSTNAME             │ MAC ADDRESS       │ HARDWARE VENDOR          │ OPEN PORTS      │ STATUS   │ LATENCY   │\n");
        out.push_str("├─────────────────┼──────────────────────┼───────────────────┼──────────────────────────┼─────────────────┼──────────┼───────────┤\n");

        if doc.hosts.is_empty() {
            out.push_str("│ No hosts discovered in this subnet sweep.                                                                     │\n");
        } else {
            for h in &doc.hosts {
                let hostname = h.hostname.as_deref().unwrap_or("-");
                let mac = h.mac.as_deref().unwrap_or("-");
                let vendor = h.vendor.as_deref().unwrap_or("-");
                let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
                let ports_str = if ports.is_empty() { "-".to_string() } else { ports.join(",") };

                out.push_str(&format!(
                    "│ {:<15.15} │ {:<20.20} │ {:<17.17} │ {:<24.24} │ {:<15.15} │ {:<8.8} │ {:>7.2}ms │\n",
                    h.ip.to_string(),
                    hostname,
                    mac,
                    vendor,
                    ports_str,
                    format!("{:?}", h.status),
                    h.latency_ms,
                ));
            }
        }
        out.push_str("└─────────────────┴──────────────────────┴───────────────────┴──────────────────────────┴─────────────────┴──────────┴───────────┘\n");
        out
    }
}
