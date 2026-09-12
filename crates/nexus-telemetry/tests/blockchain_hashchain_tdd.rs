use nexus_telemetry::chain::{Block, HashChain};
use nexus_telemetry::provenance::{IncidentMinutiae, IncidentProvenance};

fn sample_entry(action: &str) -> IncidentProvenance {
    IncidentProvenance::new(
        "commander-1",
        "10.0.0.5",
        "10.0.0.0/24",
        action,
        "TCP",
        IncidentMinutiae::default(),
    )
}

#[test]
fn test_rw_hashchain_sequential_block_generation() {
    let mut chain = HashChain::new("NEXUS_RECON_GENESIS_2026");
    assert_eq!(chain.len(), 0);

    let b0 = chain.append(sample_entry("Sweep-Subnet"));
    assert_eq!(b0.index, 0);
    assert_eq!(b0.prev_hash, chain.genesis_hash());

    let b1 = chain.append(sample_entry("PortProbe-Host10"));
    assert_eq!(b1.index, 1);
    assert_eq!(b1.prev_hash, b0.block_hash);

    assert!(chain.verify_integrity().is_ok());
}

#[test]
fn test_attack_hashchain_payload_tamper_detected() {
    let mut chain = HashChain::new("NEXUS_SEED");
    chain.append(sample_entry("InitialSweep"));
    let mut b1 = chain.append(sample_entry("PortScan"));

    // Modify payload
    b1.entry.what = "AlteredActionMalicious".to_string();
    assert!(b1.verify().is_err());
}

#[test]
fn test_attack_hashchain_prev_hash_tamper_detected() {
    let mut chain = HashChain::new("NEXUS_SEED");
    chain.append(sample_entry("Action1"));
    let mut b1 = chain.append(sample_entry("Action2"));

    b1.prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(b1.verify().is_err());
}
