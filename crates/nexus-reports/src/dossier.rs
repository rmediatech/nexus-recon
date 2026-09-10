use crate::svg::{render_latency_sparkline, render_status_donut_chart};
use nexus_core::{HostStatus, NexusError, Result, SubnetAuditSnapshot};

pub fn generate_html_dossier(snapshot: &SubnetAuditSnapshot, node_label: &str) -> String {
    let trusted = snapshot.hosts.iter().filter(|h| h.status == HostStatus::Trusted).count();
    let active = snapshot.hosts.iter().filter(|h| h.status == HostStatus::Active).count();
    let rogue = snapshot.hosts.iter().filter(|h| h.status == HostStatus::Rogue).count();
    let stale = snapshot.hosts.iter().filter(|h| h.status == HostStatus::Stale).count();

    let donut_svg = render_status_donut_chart(trusted, active, rogue, stale);
    let latencies: Vec<f64> = snapshot.hosts.iter().map(|h| h.latency_ms).collect();
    let sparkline_svg = render_latency_sparkline(&latencies);

    let mut rows = String::new();
    for h in &snapshot.hosts {
        let (status_badge, status_color) = match h.status {
            HostStatus::Trusted => ("TRUSTED", "#10b981"),
            HostStatus::Active => ("ACTIVE", "#3b82f6"),
            HostStatus::Rogue => ("ROGUE / ANOMALY", "#ef4444"),
            HostStatus::Stale => ("STALE", "#64748b"),
        };

        let ports_display = if h.open_ports.is_empty() {
            "None".to_string()
        } else {
            h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        };

        rows.push_str(&format!(
            r##"<tr>
  <td style="font-family: monospace; font-weight: bold; color: #38bdf8;">{}</td>
  <td style="font-family: monospace; color: #94a3b8;">{}</td>
  <td>{}</td>
  <td>{}</td>
  <td style="font-family: monospace;">{}</td>
  <td>{:.2} ms</td>
  <td><span style="background: {}; color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{}</span></td>
</tr>"##,
            h.ip,
            h.mac.as_deref().unwrap_or("N/A"),
            h.hostname.as_deref().unwrap_or("N/A"),
            h.vendor.as_deref().unwrap_or("Unknown"),
            ports_display,
            h.latency_ms,
            status_color,
            status_badge
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Nexus-Recon Subnet Audit Dossier - {}</title>
  <style>
    body {{ background: #0b0f19; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
    .badge {{ background: #0284c7; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; }}
    .card-title {{ font-size: 12px; color: #9ca3af; text-transform: uppercase; margin-bottom: 6px; }}
    .card-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
    .visual-pane {{ display: flex; gap: 24px; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; margin-bottom: 24px; align-items: center; }}
    table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; border: 1px solid #1f2937; }}
    th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1f2937; font-size: 13px; }}
    th {{ background: #1f2937; color: #9ca3af; text-transform: uppercase; font-size: 11px; }}
    .sig {{ font-family: monospace; font-size: 11px; color: #64748b; margin-top: 24px; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin: 0; font-size: 22px;">📡 NEXUS-RECON : SUBNET AUDIT DOSSIER</h1>
        <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">Node: <strong>{}</strong> | Subnet: <strong>{}</strong> | Timestamp: {}</div>
      </div>
      <span class="badge">ZERO-CDN SOVEREIGN AUDIT</span>
    </div>

    <div class="cards">
      <div class="card"><div class="card-title">Scanned Range</div><div class="card-val">{} Hosts</div></div>
      <div class="card"><div class="card-title">Active / Trusted</div><div class="card-val" style="color: #10b981;">{}</div></div>
      <div class="card"><div class="card-title">Rogue Anomaly</div><div class="card-val" style="color: #ef4444;">{}</div></div>
      <div class="card"><div class="card-title">Avg Latency</div><div class="card-val">{:.2} ms</div></div>
    </div>

    <div class="visual-pane">
      <div>{}</div>
      <div style="flex: 1;">
        <h3 style="margin: 0 0 8px 0; font-size: 15px;">Host Posture & Latency Distribution</h3>
        <p style="font-size: 13px; color: #94a3b8; margin: 0 0 12px 0;">Green: Trusted | Blue: Active | Red: Rogue | Gray: Stale</p>
        <div>{}</div>
      </div>
    </div>

    <table>
      <thead>
        <tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Vendor</th><th>Open Ports</th><th>RTT Latency</th><th>Status</th></tr>
      </thead>
      <tbody>
        {}
      </tbody>
    </table>

    <div class="sig">Cryptographic Audit Signature (SHA-256): {}</div>
  </div>
</body>
</html>"##,
        snapshot.subnet_cidr,
        node_label,
        snapshot.subnet_cidr,
        snapshot.timestamp.to_rfc3339(),
        snapshot.total_hosts_scanned,
        snapshot.active_hosts_count,
        snapshot.rogue_hosts_count,
        if latencies.is_empty() { 0.0 } else { latencies.iter().sum::<f64>() / latencies.len() as f64 },
        donut_svg,
        sparkline_svg,
        rows,
        snapshot.signature
    )
}

pub fn export_air_gapped_json(snapshot: &SubnetAuditSnapshot) -> String {
    serde_json::to_string_pretty(snapshot).unwrap_or_default()
}

pub fn import_air_gapped_json(json_str: &str, secret: &str) -> Result<SubnetAuditSnapshot> {
    let snapshot: SubnetAuditSnapshot = serde_json::from_str(json_str).map_err(NexusError::Json)?;
    snapshot.verify_signature(secret)?;
    Ok(snapshot)
}
