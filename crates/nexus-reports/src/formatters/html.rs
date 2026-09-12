use crate::document::NexusReportDocument;
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
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #131b2e;
            --bg-tertiary: #1f293d;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-purple: #8b5cf6;
            --border-color: #334155;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --radius-md: 8px;
            --radius-lg: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-family);
            line-height: 1.5;
            padding: 1.5rem;
        }}
        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            gap: 1rem;
        }}
        .header-brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .header-brand h1 {{
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--text-primary);
            letter-spacing: -0.025em;
        }}
        .header-meta {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        .scorecard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.25rem;
        }}
        .card-title {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }}
        .card-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .card-value.rogue {{ color: var(--accent-red); }}
        .card-value.active {{ color: var(--accent-green); }}
        .card-value.trusted {{ color: var(--accent-cyan); }}
        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: var(--radius-lg);
        }}
        .search-input {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            border-radius: var(--radius-md);
            font-size: 0.875rem;
            min-width: 280px;
        }}
        .tab-group {{
            display: flex;
            gap: 0.5rem;
        }}
        .tab-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        .tab-btn.active {{
            background: var(--accent-cyan);
            color: #000;
            border-color: var(--accent-cyan);
        }}
        .table-wrap {{
            overflow-x: auto;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.875rem;
        }}
        th, td {{
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-md);
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .badge-active {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }}
        .badge-trusted {{ background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }}
        .badge-rogue {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }}
        .badge-stale {{ background: rgba(100, 116, 139, 0.2); color: var(--text-muted); }}
        .code-pill {{
            background: var(--bg-tertiary);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--accent-cyan);
        }}
        .ports-pill {{
            background: var(--bg-tertiary);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
        }}
        .action-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.35rem 0.75rem;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .action-btn:hover {{
            background: var(--border-color);
        }}
        .summary-box {{
            margin-bottom: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-cyan);
            border-radius: var(--radius-lg);
            padding: 1.25rem;
        }}
        @media (max-width: 768px) {{
            body {{ padding: 1rem; }}
            .scorecard-grid {{ grid-template-columns: 1fr 1fr; }}
            .filter-bar {{ flex-direction: column; align-items: stretch; }}
            .search-input {{ min-width: 100%; }}
        }}
    </style>
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

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            var searchInput = document.getElementById('tableSearch');
            var rows = document.querySelectorAll('.host-row');
            var tabBtns = document.querySelectorAll('.tab-btn');
            var activeFilter = 'ALL';

            function filterRows() {{
                var query = searchInput.value.toLowerCase();
                rows.forEach(function(row) {{
                    var text = row.getAttribute('data-search').toLowerCase();
                    var status = row.getAttribute('data-status');
                    var matchesSearch = text.indexOf(query) !== -1;
                    var matchesStatus = (activeFilter === 'ALL' || status === activeFilter);

                    if (matchesSearch && matchesStatus) {{
                        row.style.display = '';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});
            }}

            if (searchInput) {{
                searchInput.addEventListener('input', filterRows);
            }}

            tabBtns.forEach(function(btn) {{
                btn.addEventListener('click', function() {{
                    tabBtns.forEach(function(b) {{ b.classList.remove('active'); }});
                    btn.classList.add('active');
                    activeFilter = btn.getAttribute('data-filter');
                    filterRows();
                }});
            }});

            document.querySelectorAll('[data-action="copy-curl"]').forEach(function(btn) {{
                btn.addEventListener('click', function() {{
                    var ip = btn.getAttribute('data-ip');
                    var cmd = 'curl -v http://' + ip + ':80';
                    navigator.clipboard.writeText(cmd).then(function() {{
                        var orig = btn.innerText;
                        btn.innerText = 'Copied!';
                        setTimeout(function() {{ btn.innerText = orig; }}, 1500);
                    }});
                }});
            }});
        }});
    </script>
</body>
</html>"#,
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
        )
    }
}
