use crate::error::LedgerError;
use crate::models::LedgerSummaryStats;
use crate::schema::init_schema;
use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus, SubnetAuditSnapshot};
use nexus_telemetry::chain::Block;
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

pub struct NexusLedger {
    conn: Mutex<Connection>,
}

impl NexusLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn record_host(&self, host: &HostRecord) -> Result<(), LedgerError> {
        let conn = self.conn.lock().unwrap();
        let ports_json = serde_json::to_string(&host.open_ports)?;
        let status_str = format!("{:?}", host.status);

        conn.execute(
            "INSERT INTO discovered_hosts (ip, mac, vendor, hostname, open_ports_json, first_seen, last_seen, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                vendor = excluded.vendor,
                hostname = excluded.hostname,
                open_ports_json = excluded.open_ports_json,
                last_seen = excluded.last_seen,
                status = excluded.status,
                latency_ms = excluded.latency_ms;",
            params![
                host.ip.to_string(),
                host.mac,
                host.vendor,
                host.hostname,
                ports_json,
                host.first_seen.to_rfc3339(),
                host.last_seen.to_rfc3339(),
                status_str,
                host.latency_ms,
            ],
        )?;
        Ok(())
    }

    pub fn list_hosts(&self, limit: usize) -> Result<Vec<HostRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, mac, vendor, hostname, open_ports_json, first_seen, last_seen, status, latency_ms 
             FROM discovered_hosts ORDER BY last_seen DESC LIMIT ?1;"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let ip_str: String = row.get(0)?;
            let mac: Option<String> = row.get(1)?;
            let vendor: Option<String> = row.get(2)?;
            let hostname: Option<String> = row.get(3)?;
            let ports_json: String = row.get(4)?;
            let first_seen_str: String = row.get(5)?;
            let last_seen_str: String = row.get(6)?;
            let status_str: String = row.get(7)?;
            let latency_ms: f64 = row.get(8)?;

            let ip: IpAddr = ip_str.parse().unwrap_or("0.0.0.0".parse().unwrap());
            let open_ports: Vec<u16> = serde_json::from_str(&ports_json).unwrap_or_default();
            let first_seen = chrono::DateTime::parse_from_rfc3339(&first_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_seen = chrono::DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let status = match status_str.as_str() {
                "Trusted" => HostStatus::Trusted,
                "Rogue" => HostStatus::Rogue,
                "Stale" => HostStatus::Stale,
                _ => HostStatus::Active,
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
        })?;

        let mut hosts = Vec::new();
        for r in rows {
            hosts.push(r?);
        }
        Ok(hosts)
    }

    pub fn upsert_host(&self, host: &HostRecord) -> Result<(), LedgerError> {
        self.record_host(host)
    }

    pub fn record_snapshot(&self, snap: &SubnetAuditSnapshot) -> Result<(), LedgerError> {
        let conn = self.conn.lock().unwrap();
        let hosts_json = serde_json::to_string(&snap.hosts)?;

        conn.execute(
            "INSERT INTO subnet_snapshots (id, subnet_cidr, timestamp, total_hosts_scanned, active_hosts_count, rogue_hosts_count, hosts_json, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
            params![
                snap.id,
                snap.subnet_cidr,
                snap.timestamp.to_rfc3339(),
                snap.total_hosts_scanned as i64,
                snap.active_hosts_count as i64,
                snap.rogue_hosts_count as i64,
                hosts_json,
                snap.signature,
            ],
        )?;
        Ok(())
    }

    pub fn list_snapshots(&self, limit: usize) -> Result<Vec<SubnetAuditSnapshot>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subnet_cidr, timestamp, total_hosts_scanned, active_hosts_count, rogue_hosts_count, hosts_json, signature 
             FROM subnet_snapshots ORDER BY timestamp DESC LIMIT ?1;"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: String = row.get(0)?;
            let subnet_cidr: String = row.get(1)?;
            let timestamp_str: String = row.get(2)?;
            let total_hosts_scanned: i64 = row.get(3)?;
            let active_hosts_count: i64 = row.get(4)?;
            let rogue_hosts_count: i64 = row.get(5)?;
            let hosts_json: String = row.get(6)?;
            let signature: String = row.get(7)?;

            let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
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
        })?;

        let mut snapshots = Vec::new();
        for r in rows {
            snapshots.push(r?);
        }
        Ok(snapshots)
    }

    pub fn record_telemetry_block(&self, block: &Block) -> Result<(), LedgerError> {
        let conn = self.conn.lock().unwrap();
        let raw_json = serde_json::to_string(block)?;

        conn.execute(
            "INSERT INTO telemetry_blocks (block_index, block_hash, prev_hash, payload_digest, who, source_addr, dest_addr, action, transport, safety_tier, hosts_discovered, open_ports_found, duration_ps, timestamp_utc, raw_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15);",
            params![
                block.index as i64,
                block.block_hash,
                block.prev_hash,
                block.payload_digest,
                block.entry.who,
                block.entry.from,
                block.entry.to,
                block.entry.what,
                block.entry.how,
                block.entry.minutiae.safety_tier,
                block.entry.minutiae.hosts_discovered as i64,
                block.entry.minutiae.open_ports_found as i64,
                block.entry.minutiae.duration_ps as i64,
                block.timestamp_utc,
                raw_json,
            ],
        )?;
        Ok(())
    }

    pub fn verify_stored_chain_integrity(&self, seed: &str) -> Result<usize, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT block_index, block_hash, prev_hash, payload_digest, action, timestamp_utc, raw_json 
             FROM telemetry_blocks ORDER BY block_index ASC;"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;

        use sha2::Digest;
        let mut hasher = sha2::Sha256::default();
        hasher.update(b"NEXUS_RECON_GENESIS_V1:");
        hasher.update(seed.as_bytes());
        let mut expected_prev = hex::encode(hasher.finalize());
        let mut count = 0;

        for (expected_idx, row_res) in rows.enumerate() {
            let (idx, block_hash, prev_hash, payload_digest, action, timestamp_utc, raw_json) = row_res?;
            if idx != expected_idx as u64 {
                return Err(LedgerError::SequenceMismatch { expected: expected_idx as u64, actual: idx });
            }
            if prev_hash != expected_prev {
                return Err(LedgerError::BlockchainTamper { index: idx, calculated: prev_hash, expected: expected_prev });
            }
            let block: Block = serde_json::from_str(&raw_json)?;
            if block.entry.what != action {
                return Err(LedgerError::BlockchainTamper { index: idx, calculated: action, expected: block.entry.what });
            }
            let calc_hash = Block::calculate_hash(idx, &timestamp_utc, &prev_hash, &payload_digest);
            if calc_hash != block_hash {
                return Err(LedgerError::BlockchainTamper { index: idx, calculated: calc_hash, expected: block_hash });
            }
            expected_prev = block_hash;
            count += 1;
        }
        Ok(count)
    }

    pub fn get_summary_stats(&self) -> Result<LedgerSummaryStats, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let query_count = |sql: &str| conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0);
        Ok(LedgerSummaryStats {
            total_hosts: query_count("SELECT COUNT(*) FROM discovered_hosts;"),
            active_hosts: query_count("SELECT COUNT(*) FROM discovered_hosts WHERE status = 'Active';"),
            rogue_hosts: query_count("SELECT COUNT(*) FROM discovered_hosts WHERE status = 'Rogue';"),
            stale_hosts: query_count("SELECT COUNT(*) FROM discovered_hosts WHERE status = 'Stale';"),
            total_open_ports: 0,
            total_snapshots: query_count("SELECT COUNT(*) FROM subnet_snapshots;"),
            total_blocks: query_count("SELECT COUNT(*) FROM telemetry_blocks;"),
        })
    }
}
