pub const DASHBOARD_STYLE: &str = r#"
        :root {
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
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-family);
            line-height: 1.5;
            padding: 1.5rem;
        }
        .container { max-width: 1280px; margin: 0 auto; }
        header {
            display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
            padding-bottom: 1.5rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); gap: 1rem;
        }
        .header-brand { display: flex; align-items: center; gap: 1rem; }
        .header-brand h1 { font-size: 1.75rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.025em; }
        .header-meta { color: var(--text-secondary); font-size: 0.875rem; }
        .scorecard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 1.25rem; }
        .card-title { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.5rem; }
        .card-value { font-size: 1.75rem; font-weight: 700; color: var(--text-primary); }
        .card-value.rogue { color: var(--accent-red); }
        .card-value.active { color: var(--accent-green); }
        .card-value.trusted { color: var(--accent-cyan); }
        .filter-bar {
            display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; justify-content: space-between;
            margin-bottom: 1.5rem; background: var(--bg-secondary); border: 1px solid var(--border-color);
            padding: 1rem; border-radius: var(--radius-lg);
        }
        .search-input {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary);
            padding: 0.5rem 1rem; border-radius: var(--radius-md); font-size: 0.875rem; min-width: 280px;
        }
        .tab-group { display: flex; gap: 0.5rem; }
        .tab-btn {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-secondary);
            padding: 0.5rem 1rem; border-radius: var(--radius-md); cursor: pointer; font-size: 0.875rem; font-weight: 600;
        }
        .tab-btn.active { background: var(--accent-cyan); color: #000; border-color: var(--accent-cyan); }
        .table-wrap { overflow-x: auto; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-lg); }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }
        th, td { padding: 0.875rem 1rem; border-bottom: 1px solid var(--border-color); }
        th {
            background: var(--bg-tertiary); color: var(--text-secondary); font-weight: 600;
            text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em;
        }
        tr:last-child td { border-bottom: none; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: var(--radius-md); font-size: 0.75rem; font-weight: 700; }
        .badge-active { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }
        .badge-trusted { background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }
        .badge-rogue { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }
        .badge-stale { background: rgba(100, 116, 139, 0.2); color: var(--text-muted); }
        .code-pill { background: var(--bg-tertiary); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; color: var(--accent-cyan); }
        .ports-pill { background: var(--bg-tertiary); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.8rem; }
        .action-btn {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary);
            padding: 0.35rem 0.75rem; border-radius: var(--radius-md); cursor: pointer; font-size: 0.75rem; font-weight: 600;
        }
        .action-btn:hover { background: var(--border-color); }
        .summary-box {
            margin-bottom: 2rem; background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-cyan); border-radius: var(--radius-lg); padding: 1.25rem;
        }
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .scorecard-grid { grid-template-columns: 1fr 1fr; }
            .filter-bar { flex-direction: column; align-items: stretch; }
            .search-input { min-width: 100%; }
        }
"#;

pub const DASHBOARD_SCRIPT: &str = r#"
        document.addEventListener('DOMContentLoaded', function() {
            var searchInput = document.getElementById('tableSearch');
            var rows = document.querySelectorAll('.host-row');
            var tabBtns = document.querySelectorAll('.tab-btn');
            var activeFilter = 'ALL';

            function filterRows() {
                var query = searchInput.value.toLowerCase();
                rows.forEach(function(row) {
                    var text = row.getAttribute('data-search').toLowerCase();
                    var status = row.getAttribute('data-status');
                    var matchesSearch = text.indexOf(query) !== -1;
                    var matchesStatus = (activeFilter === 'ALL' || status === activeFilter);
                    row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
                });
            }

            if (searchInput) {
                searchInput.addEventListener('input', filterRows);
            }

            tabBtns.forEach(function(btn) {
                btn.addEventListener('click', function() {
                    tabBtns.forEach(function(b) { b.classList.remove('active'); });
                    btn.classList.add('active');
                    activeFilter = btn.getAttribute('data-filter');
                    filterRows();
                });
            });

            document.querySelectorAll('[data-action="copy-curl"]').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var ip = btn.getAttribute('data-ip');
                    var cmd = 'curl -v http://' + ip + ':80';
                    navigator.clipboard.writeText(cmd).then(function() {
                        var orig = btn.innerText;
                        btn.innerText = 'Copied!';
                        setTimeout(function() { btn.innerText = orig; }, 1500);
                    });
                });
            });
        });
"#;
