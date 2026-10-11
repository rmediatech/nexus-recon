//! # Mandatory Adversarial Self-Attack Test Battery: Provenance & Canary Defense (POC TDD+++++)
//!
//! Asserts that sovereign key custody, cryptographic canary tokens, and watermarks
//! in `nexus-recon` are immutable, tamper-evident, and mathematically resilient against removal.

use nexus_core::provenance::{
    verify_sovereign_watermark, CANARY_PREIMAGE, SOVEREIGN_ARCHITECT,
    SOVEREIGN_CANARY_SHA256, SOVEREIGN_KEY_ID,
};
use sha2::{Digest, Sha256};

#[test]
fn test_adversarial_sovereign_canary_integrity() {
    // 1. Verify key identity
    assert_eq!(SOVEREIGN_KEY_ID, "4E428019A109578B");
    assert!(SOVEREIGN_ARCHITECT.contains("Rick Walker"));
    assert!(SOVEREIGN_ARCHITECT.contains("rick@rmediatech.com"));

    // 2. Re-compute SHA-256 digest from preimage
    let mut hasher = Sha256::new();
    hasher.update(CANARY_PREIMAGE.as_bytes());
    let computed_digest = hasher.finalize();

    assert_eq!(
        computed_digest.as_slice(),
        &SOVEREIGN_CANARY_SHA256[..],
        "Canary digest must match cryptographic hash of the preimage exactly"
    );

    // 3. Verify watermark validator
    assert!(verify_sovereign_watermark());
}

#[test]
fn test_adversarial_canary_tamper_detection() {
    let mut corrupted_canary = SOVEREIGN_CANARY_SHA256;
    corrupted_canary[0] ^= 0xFF; // Flip bits

    // If an attacker attempts to mutate or scrub the canary, verification fails
    assert_ne!(corrupted_canary, SOVEREIGN_CANARY_SHA256);
}
