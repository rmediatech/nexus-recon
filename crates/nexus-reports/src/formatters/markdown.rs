use crate::document::NexusReportDocument;

pub struct MarkdownFormatter;

impl MarkdownFormatter {
    pub fn render(doc: &NexusReportDocument) -> String {
        let mut out = String::new();
        out.push_str(&format!("# 🛡️ NEXUS-RECON : Air-Gapped Subnet Incident Report\n\n"));
        out.push_str(&format!("> **Node:** `{}` | **Target Subnet:** `{}` | **Generated:** `{}`\n\n", doc.node_label, doc.subnet_cidr, doc.generated_at));
        out.push_str("## 📋 Executive Summary\n\n");
        out.push_str(&format!("{}\n\n", doc.executive_summary));
        out.push_str("## 📊 Subnet Summary Scorecard\n\n");
        out.push_str(&format!("- **Total Assets:** `{}`\n", doc.metrics.total_hosts));
        out.push_str(&format!("- **Active Hosts:** `{}`\n", doc.metrics.active_hosts));
        out.push_str(&format!("- **Rogue Hosts:** `{}`\n", doc.metrics.rogue_hosts));
        out.push_str(&format!("- **Total Open Ports:** `{}`\n", doc.metrics.total_open_ports));
        out.push_str(&format!("- **Average Latency:** `{:.2}ms`\n\n", doc.metrics.avg_latency_ms));

        out.push_str("## 🖥️ Discovered Assets Inventory\n\n");
        out.push_str("| IP | Hostname | MAC | Vendor | Ports | Status | Latency |\n");
        out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for h in &doc.hosts {
            let hostname = h.hostname.as_deref().unwrap_or("-");
            let mac = h.mac.as_deref().unwrap_or("-");
            let vendor = h.vendor.as_deref().unwrap_or("-");
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            let ports_str = if ports.is_empty() { "-".to_string() } else { ports.join(", ") };

            out.push_str(&format!(
                "| `{}` | {} | `{}` | {} | `{}` | **{:?}** | `{:.2}ms` |\n",
                h.ip,
                hostname,
                mac,
                vendor,
                ports_str,
                h.status,
                h.latency_ms,
            ));
        }
        out
    }
}
