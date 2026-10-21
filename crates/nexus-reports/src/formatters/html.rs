use crate::document::NexusReportDocument;
use crate::formatters::html_template::{DASHBOARD_SCRIPT, DASHBOARD_STYLE};
use nexus_core::models::HostStatus;

pub struct HtmlFormatter;

impl HtmlFormatter {
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    pub fn render(doc: &NexusReportDocument) -> String {
        let mut rows = String::new();

        for h in &doc.hosts {
            let status_class = match h.status {
                HostStatus::Active => "badge-active",
                HostStatus::Trusted => "badge-trusted",
                HostStatus::Rogue => "badge-rogue",
                HostStatus::Stale => "badge-stale",
            };

            let hostname = h.hostname.as_deref().unwrap_or("-");
            let mac = h.mac.as_deref().unwrap_or("-");
            let vendor = h.vendor.as_deref().unwrap_or("-");
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            let ports_str = if ports.is_empty() { "-".to_string() } else { ports.join(", ") };

            rows.push_str(&format!(
                "<tr class=\"host-row\" data-status=\"{:?}\" data-search=\"{} {} {} {}\">\n\
                    <td><span class=\"code-pill\">{}</span></td>\n\
                    <td><strong>{}</strong></td>\n\
                    <td><span class=\"mono\">{}</span></td>\n\
                    <td>{}</td>\n\
                    <td><span class=\"ports-pill\">{}</span></td>\n\
                    <td><span class=\"badge {}\">{:?}</span></td>\n\
                    <td>{:.2}ms</td>\n\
                    <td><button class=\"action-btn\" data-action=\"copy-curl\" data-ip=\"{}\">Copy Probe</button></td>\n\
                </tr>\n",
                h.status,
                Self::escape_html(&h.ip.to_string()),
                Self::escape_html(hostname),
                Self::escape_html(mac),
                Self::escape_html(vendor),
                Self::escape_html(&h.ip.to_string()),
                Self::escape_html(hostname),
                Self::escape_html(mac),
                Self::escape_html(vendor),
                Self::escape_html(&ports_str),
                status_class,
                h.status,
                h.latency_ms,
                Self::escape_html(&h.ip.to_string()),
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
    <title>NEXUS-RECON : Incident Commander Dashboard</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-brand">
                <h1>🛡️ NEXUS-RECON</h1>
                <span class="badge badge-active">AIR-GAPPED COCKPIT</span>
            </div>
            <div class="header-meta">
                <span>Node: <strong>{}</strong> | Subnet: <strong>{}</strong> | Report ID: <code>{}</code></span>
            </div>
        </header>

        <section class="summary-box">
            <div class="card-title">Executive Forensics Summary</div>
            <p>{}</p>
        </section>

        <section class="scorecard-grid">
            <div class="card">
                <div class="card-title">Total Discovered Assets</div>
                <div class="card-value">{}</div>
            </div>
            <div class="card">
                <div class="card-title">Active Devices</div>
                <div class="card-value active">{}</div>
            </div>
            <div class="card">
                <div class="card-title">Rogue Alert Assets</div>
                <div class="card-value rogue">{}</div>
            </div>
            <div class="card">
                <div class="card-title">Total Open Services</div>
                <div class="card-value trusted">{}</div>
            </div>
            <div class="card">
                <div class="card-title">Average Latency</div>
                <div class="card-value">{:.2}ms</div>
            </div>
        </section>

        <section class="filter-bar">
            <input type="text" class="search-input" id="tableSearch" placeholder="Search IP, hostname, MAC, vendor, port...">
            <div class="tab-group">
                <button class="tab-btn active" data-filter="ALL">All ({})</button>
                <button class="tab-btn" data-filter="Active">Active</button>
                <button class="tab-btn" data-filter="Rogue">Rogue</button>
                <button class="tab-btn" data-filter="Trusted">Trusted</button>
            </div>
        </section>

        <section class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>MAC Address</th>
                        <th>Hardware Vendor</th>
                        <th>Open Ports</th>
                        <th>Status</th>
                        <th>Latency</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="hostsTbody">
                    {}
                </tbody>
            </table>
        </section>
    </div>

    <script>{}</script>
</body>
</html>"#,
            DASHBOARD_STYLE,
            Self::escape_html(&doc.node_label),
            Self::escape_html(&doc.subnet_cidr),
            Self::escape_html(&doc.report_id),
            Self::escape_html(&doc.executive_summary),
            doc.metrics.total_hosts,
            doc.metrics.active_hosts,
            doc.metrics.rogue_hosts,
            doc.metrics.total_open_ports,
            doc.metrics.avg_latency_ms,
            doc.metrics.total_hosts,
            rows,
            DASHBOARD_SCRIPT,
        )
    }
}
