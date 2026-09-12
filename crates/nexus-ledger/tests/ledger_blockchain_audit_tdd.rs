use nexus_ledger::repository::NexusLedger;
use nexus_telemetry::chain::HashChain;
use nexus_telemetry::provenance::{IncidentMinutiae, IncidentProvenance};
use rusqlite::Connection;
use tempfile::NamedTempFile;

#[test]
fn test_rw_blockchain_blocks_stored_and_integrity_verified() {
    let ledger = NexusLedger::open_in_memory().unwrap();

    let mut chain = HashChain::new("NEXUS_AUDIT_SEED");
    let b0 = chain.append(IncidentProvenance::new(
        "operator-1",
        "192.168.1.5",
        "192.168.1.0/24",
        "PassiveAudit",
        "RADIX",
        IncidentMinutiae::default(),
    ));

    let b1 = chain.append(IncidentProvenance::new(
        "operator-1",
        "192.168.1.5",
        "192.168.1.0/24",
        "ActiveSweep",
        "TCP-SYN",
        IncidentMinutiae::default(),
    ));

    ledger.record_telemetry_block(&b0).unwrap();
    ledger.record_telemetry_block(&b1).unwrap();

    let audit_res = ledger.verify_stored_chain_integrity("NEXUS_AUDIT_SEED");
    assert!(audit_res.is_ok());
    assert_eq!(audit_res.unwrap(), 2);
}

#[test]
fn test_attack_blockchain_tampered_in_sqlite_detected() {
    let temp_db = NamedTempFile::new().unwrap();
    let db_path = temp_db.path();

    {
        let ledger = NexusLedger::open(db_path).unwrap();
        let mut chain = HashChain::new("NEXUS_AUDIT_SEED");
        let b0 = chain.append(IncidentProvenance::new(
            "admin",
            "127.0.0.1",
            "10.0.0.0/24",
            "SweepSubnet",
            "TCP",
            IncidentMinutiae::default(),
        ));
        ledger.record_telemetry_block(&b0).unwrap();
    }

    // Direct malicious SQLite UPDATE tampering with action
    {
        let conn = Connection::open(db_path).unwrap();
        conn.execute(
            "UPDATE telemetry_blocks SET action = 'MaliciousActionTamper' WHERE block_index = 0",
            [],
        )
        .unwrap();
    }

    {
        let ledger = NexusLedger::open(db_path).unwrap();
        let audit_res = ledger.verify_stored_chain_integrity("NEXUS_AUDIT_SEED");
        assert!(audit_res.is_err());
    }
}
