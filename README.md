# 📡 Nexus-Recon (`nexus-recon-rs`)
### *Air-Gapped Subnet Incident Commander & Network Operations Cockpit*

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust: 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Security: Zero-CDN](https://img.shields.io/badge/security-Zero--CDN%20Air--Gapped-brightgreen.svg)]()
[![Ledger: SQLite WAL](https://img.shields.io/badge/database-SQLite%20WAL-informational.svg)]()

---

## 🧭 Overview

**Nexus-Recon** is an autonomous, inside-out network reconnaissance engine and incident response cockpit. It enables homelab operators, SREs, and security engineers to discover active devices, detect rogue hardware attachments, track port deltas, and export cryptographic compliance dossiers without requiring inbound open firewall ports or heavy enterprise monitoring agents.

Powered by the sovereign **Conduit** engine, Nexus-Recon operates seamlessly across air-gapped subnets and multi-site homelabs.

```
┌──────────────────────────────┐                ┌──────────────────────────────┐
│  Inside-Out Subnet Sweeper   │ ══════════════ │  Radix Trie LPM Host Index   │
│  (ARP / ICMP / TCP Probing)  │                │  (Fast IP Prefix Categorizer)│
└──────────────┬───────────────┘                └──────────────┬───────────────┘
               │                                               │
               ▼                                               ▼
┌──────────────────────────────┐                ┌──────────────────────────────┐
│  SQLite WAL Forensics Ledger │ ══════════════ │  Zero-CDN HTML/SVG Dossier   │
│  (Delta History & Anomaly)   │                │  (Embedded Donut & Sparkline)│
└──────────────────────────────┘                └──────────────────────────────┘
```

---

## ✨ Key Features

1. **Inside-Out Subnet Reconnaissance**: Probes subnets from within local segments, bypassing external perimeter firewalls.
2. **Radix Trie LPM Indexing**: Ultra-fast Longest Prefix Match (LPM) indexing of IPv4 host records.
3. **Embedded OUI Database**: Instant MAC vendor identification (Raspberry Pi, Apple, Google, Ubiquiti, Espressif, Intel, etc.).
4. **SQLite WAL Time-Series Persistence**: Audit ledger tracking first-seen, last-seen, latency jitter, and rogue status.
5. **Zero-CDN HTML Compliance Dossiers**: Self-contained dark-mode HTML reports with embedded SVG donut breakdown charts and latency sparklines.
6. **Air-Gapped Forensic JSON Serialization**: Export and ingest tamper-evident snapshots verified with HMAC-SHA256 signatures.

---

## 🚀 Quickstart

### 1. Build & Run Tests
```bash
cargo test --workspace
```

### 2. Generate Default TOML Configuration
```bash
nexus-recon --generate-config > nexus-recon.toml
```

### 3. Sweep Local Subnet & Export HTML Dossier
```bash
nexus-recon scan 192.168.1.0/24 --ports 22,80,443,8084 --export-html /tmp/network_dossier.html
```

### 4. Continuous Subnet Watch & Radar Sweep
```bash
nexus-recon watch --interval 30
```

### 5. Ingest Air-Gapped Forensic Snapshot
```bash
nexus-recon ingest /tmp/forensic_dump.json
```

---

## 🛡️ License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
