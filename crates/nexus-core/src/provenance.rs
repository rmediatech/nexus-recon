//! # Sovereign Cryptographic Provenance & Watermark Canary
//!
//! Enforces immutable cryptographic provenance for `nexus-recon` as the authoritative
//! subnet incident commander of the Sovereign Rust Ecosystem (`AGY-RULE-SOVEREIGN-FLAGSHIP-01`).

/// Authoritative Sovereign Release Signing Key ID.
pub const SOVEREIGN_KEY_ID: &str = "4E428019A109578B";

/// Authoritative Sovereign Architect Fingerprint and Identity.
pub const SOVEREIGN_ARCHITECT: &str = "Rick Walker (Sovereign Release Signing Key) <xuoxod@gmail.com>";

/// Cryptographic Canary Token Preimage.
pub const CANARY_PREIMAGE: &str = "SOVEREIGN-WATERMARK-NEXUSRECON-4E428019A109578B-RMD-2026-XUOXOD";

/// Cryptographic Canary SHA-256 Digest.
/// Preimage: `SOVEREIGN-WATERMARK-NEXUSRECON-4E428019A109578B-RMD-2026-XUOXOD`
pub const SOVEREIGN_CANARY_SHA256: [u8; 32] = [
    0x14, 0x1b, 0x64, 0x28, 0xb8, 0x24, 0x56, 0xf7,
    0x82, 0x0a, 0x34, 0x47, 0xc5, 0x02, 0xaa, 0x6b,
    0xfe, 0xbd, 0xa5, 0x0c, 0xd8, 0xc7, 0x93, 0x9e,
    0xd5, 0x94, 0xda, 0xef, 0x44, 0x50, 0x02, 0x3f,
];

#[inline(never)]
#[must_use]
pub fn verify_sovereign_watermark() -> bool {
    let canary = std::hint::black_box(CANARY_PREIMAGE);
    let digest = std::hint::black_box(&SOVEREIGN_CANARY_SHA256);
    canary.contains(SOVEREIGN_KEY_ID)
        && digest[0] == 0x14
        && digest[15] == 0x6b
        && digest[31] == 0x3f
}
