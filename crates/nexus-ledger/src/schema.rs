use crate::error::LedgerError;
use rusqlite::Connection;

pub fn init_schema(conn: &Connection) -> Result<(), LedgerError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;",
    )?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS discovered_hosts (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            open_ports_json TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL,
            latency_ms REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subnet_snapshots (
            id TEXT PRIMARY KEY,
            subnet_cidr TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            total_hosts_scanned INTEGER NOT NULL,
            active_hosts_count INTEGER NOT NULL,
            rogue_hosts_count INTEGER NOT NULL,
            hosts_json TEXT NOT NULL,
            signature TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS telemetry_blocks (
            block_index INTEGER PRIMARY KEY,
            block_hash TEXT NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            who TEXT NOT NULL,
            source_addr TEXT NOT NULL,
            dest_addr TEXT NOT NULL,
            action TEXT NOT NULL,
            transport TEXT NOT NULL,
            safety_tier TEXT NOT NULL,
            hosts_discovered INTEGER NOT NULL,
            open_ports_found INTEGER NOT NULL,
            duration_ps INTEGER NOT NULL,
            timestamp_utc TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_hosts_status ON discovered_hosts(status);
        CREATE INDEX IF NOT EXISTS idx_snapshots_time ON subnet_snapshots(timestamp);
        CREATE INDEX IF NOT EXISTS idx_blocks_time ON telemetry_blocks(timestamp_utc);",
    )?;

    Ok(())
}
