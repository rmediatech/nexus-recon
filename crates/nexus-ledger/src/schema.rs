pub const CREATE_TABLES_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    open_ports TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_snapshots (
    id TEXT PRIMARY KEY,
    subnet_cidr TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    total_hosts_scanned INTEGER NOT NULL,
    active_hosts_count INTEGER NOT NULL,
    rogue_hosts_count INTEGER NOT NULL,
    hosts_json TEXT NOT NULL,
    signature TEXT NOT NULL
);
"#;
