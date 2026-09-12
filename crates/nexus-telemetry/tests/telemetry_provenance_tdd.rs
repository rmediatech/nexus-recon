use nexus_telemetry::provenance::{IncidentMinutiae, IncidentProvenance};
use nexus_telemetry::timer::HighPrecisionTimer;

#[test]
fn test_rw_provenance_5w1h_serialization_roundtrip() {
    let minutiae = IncidentMinutiae {
        duration_ps: 1_450_000_000_000,
        hosts_discovered: 12,
        open_ports_found: 28,
        safety_tier: "Tier2".to_string(),
        status_code: 200,
        ..Default::default()
    };

    let event = IncidentProvenance::new(
        "operator-prime",
        "192.168.1.50",
        "192.168.1.0/24",
        "SubnetSweep",
        "TCP-SYN",
        minutiae,
    );

    let digest = event.compute_payload_digest();
    assert_eq!(digest.len(), 64);

    let serialized = serde_json::to_string(&event).expect("Failed to serialize");
    let deserialized: IncidentProvenance = serde_json::from_str(&serialized).expect("Failed to deserialize");
    assert_eq!(event, deserialized);
}

#[test]
fn test_rw_high_precision_timer_sub_nanos() {
    let timer = HighPrecisionTimer::start();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let elapsed_ps = timer.elapsed_picoseconds();
    let elapsed_ms = timer.elapsed_millis();

    assert!(elapsed_ps >= 5_000_000_000); // >= 5 million ps
    assert!(elapsed_ms >= 4.5);
}

#[test]
fn test_ec_empty_minutiae_and_extra_fields() {
    let mut minutiae = IncidentMinutiae::default();
    minutiae.extra.insert("rogue_mac".to_string(), "00:de:ad:be:ef:00".to_string());

    let event = IncidentProvenance::new(
        "auto-scout",
        "127.0.0.1",
        "10.0.0.0/16",
        "PassiveAudit",
        "RADIX-TRIE",
        minutiae,
    );

    assert_eq!(event.minutiae.extra.get("rogue_mac").unwrap(), "00:de:ad:be:ef:00");
}
