use crate::document::NexusReportDocument;

pub struct CsvFormatter;

impl CsvFormatter {
    pub fn sanitize_field(field: &str) -> String {
        let trimmed = field.trim();
        if trimmed.starts_with('=')
            || trimmed.starts_with('+')
            || trimmed.starts_with('-')
            || trimmed.starts_with('@')
            || trimmed.starts_with('\t')
            || trimmed.starts_with('\r')
        {
            format!("'{}", trimmed.replace('"', "\"\""))
        } else {
            trimmed.replace('"', "\"\"")
        }
    }

    pub fn render(doc: &NexusReportDocument) -> String {
        let mut out = String::new();
        out.push_str("ip,hostname,mac,vendor,open_ports,status,latency_ms\n");

        for h in &doc.hosts {
            let ip = Self::sanitize_field(&h.ip.to_string());
            let hostname = Self::sanitize_field(h.hostname.as_deref().unwrap_or(""));
            let mac = Self::sanitize_field(h.mac.as_deref().unwrap_or(""));
            let vendor = Self::sanitize_field(h.vendor.as_deref().unwrap_or(""));
            let ports_str = h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(";");
            let ports = Self::sanitize_field(&ports_str);
            let status = format!("{:?}", h.status);

            out.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{:.2}\n",
                ip, hostname, mac, vendor, ports, status, h.latency_ms
            ));
        }
        out
    }
}
