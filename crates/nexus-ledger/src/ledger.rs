use chrono::{DateTime, Utc};
use nexus_core::{HostRecord, HostStatus, NexusError, Result, SubnetAuditSnapshot};
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use crate::schema::CREATE_TABLES_SQL;

#[derive(Clone)]
pub struct NexusLedger {
    conn: Arc<Mutex<Connection>>,
}

impl NexusLedger {
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| NexusError::Database(e.to_string()))?;
        conn.execute_batch(CREATE_TABLES_SQL)
            .map_err(|e| NexusError::Database(e.to_string()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| NexusError::Database(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| NexusError::Database(e.to_string()))?;

        conn.execute_batch(CREATE_TABLES_SQL)
            .map_err(|e| NexusError::Database(e.to_string()))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn upsert_host(&self, host: &HostRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let open_ports_str = serde_json::to_string(&host.open_ports)?;
        let status_str = format!("{:?}", host.status);

        conn.execute(
            r#"
            INSERT INTO hosts (ip, mac, vendor, hostname, open_ports, first_seen, last_seen, status, latency_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                vendor = excluded.vendor,
                hostname = excluded.hostname,
                open_ports = excluded.open_ports,
                last_seen = excluded.last_seen,
                status = excluded.status,
                latency_ms = excluded.latency_ms;
            "#,
            params![
                host.ip.to_string(),
                host.mac,
                host.vendor,
                host.hostname,
                open_ports_str,
                host.first_seen.to_rfc3339(),
                host.last_seen.to_rfc3339(),
                status_str,
                host.latency_ms,
            ],
        )
        .map_err(|e| NexusError::Database(e.to_string()))?;

        Ok(())
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT ip, mac, vendor, hostname, open_ports, first_seen, last_seen, status, latency_ms FROM hosts ORDER BY ip ASC")
            .map_err(|e| NexusError::Database(e.to_string()))?;

        let host_iter = stmt
            .query_map([], |row| {
                let ip_str: String = row.get(0)?;
                let mac: Option<String> = row.get(1)?;
                let vendor: Option<String> = row.get(2)?;
                let hostname: Option<String> = row.get(3)?;
                let open_ports_str: String = row.get(4)?;
                let first_seen_str: String = row.get(5)?;
                let last_seen_str: String = row.get(6)?;
                let status_str: String = row.get(7)?;
                let latency_ms: f64 = row.get(8)?;

                let ip = IpAddr::from_str(&ip_str).unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));
                let open_ports: Vec<u16> = serde_json::from_str(&open_ports_str).unwrap_or_default();
                let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let status = match status_str.as_str() {
                    "Trusted" => HostStatus::Trusted,
                    "Active" => HostStatus::Active,
                    "Rogue" => HostStatus::Rogue,
                    _ => HostStatus::Stale,
                };

                Ok(HostRecord {
                    ip,
                    mac,
                    vendor,
                    hostname,
                    open_ports,
                    first_seen,
                    last_seen,
                    status,
                    latency_ms,
                })
            })
            .map_err(|e| NexusError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for h in host_iter {
            results.push(h.map_err(|e| NexusError::Database(e.to_string()))?);
        }

        Ok(results)
    }

    pub fn record_snapshot(&self, snapshot: &SubnetAuditSnapshot) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let hosts_json = serde_json::to_string(&snapshot.hosts)?;

        conn.execute(
            r#"
            INSERT INTO audit_snapshots (id, subnet_cidr, timestamp, total_hosts_scanned, active_hosts_count, rogue_hosts_count, hosts_json, signature)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                snapshot.id,
                snapshot.subnet_cidr,
                snapshot.timestamp.to_rfc3339(),
                snapshot.total_hosts_scanned as i64,
                snapshot.active_hosts_count as i64,
                snapshot.rogue_hosts_count as i64,
                hosts_json,
                snapshot.signature,
            ],
        )
        .map_err(|e| NexusError::Database(e.to_string()))?;

        Ok(())
    }

    pub fn list_snapshots(&self, limit: usize) -> Result<Vec<SubnetAuditSnapshot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, subnet_cidr, timestamp, total_hosts_scanned, active_hosts_count, rogue_hosts_count, hosts_json, signature FROM audit_snapshots ORDER BY timestamp DESC LIMIT ?1")
            .map_err(|e| NexusError::Database(e.to_string()))?;

        let snapshot_iter = stmt
            .query_map([limit as i64], |row| {
                let id: String = row.get(0)?;
                let subnet_cidr: String = row.get(1)?;
                let timestamp_str: String = row.get(2)?;
                let total_hosts_scanned: i64 = row.get(3)?;
                let active_hosts_count: i64 = row.get(4)?;
                let rogue_hosts_count: i64 = row.get(5)?;
                let hosts_json: String = row.get(6)?;
                let signature: String = row.get(7)?;

                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let hosts: Vec<HostRecord> = serde_json::from_str(&hosts_json).unwrap_or_default();

                Ok(SubnetAuditSnapshot {
                    id,
                    subnet_cidr,
                    timestamp,
                    total_hosts_scanned: total_hosts_scanned as usize,
                    active_hosts_count: active_hosts_count as usize,
                    rogue_hosts_count: rogue_hosts_count as usize,
                    hosts,
                    signature,
                })
            })
            .map_err(|e| NexusError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for s in snapshot_iter {
            results.push(s.map_err(|e| NexusError::Database(e.to_string()))?);
        }

        Ok(results)
    }
}
