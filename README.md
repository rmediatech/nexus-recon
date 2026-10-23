# 📡 Nexus-Recon (`nexus-recon-rs`)
### *Air-Gapped Subnet Incident Commander & Network Operations Cockpit*

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Security: Zero-CDN](https://img.shields.io/badge/security-Zero--CDN%20Air--Gapped-brightgreen.svg)]()
[![Ledger: SQLite WAL](https://img.shields.io/badge/database-SQLite%20WAL-informational.svg)]()
[![Audit: SHA--256 Blockchain](https://img.shields.io/badge/audit-SHA--256%20Blockchain-purple.svg)]()
[![Tests: 51/51 Passing](https://img.shields.io/badge/tests-51%2F51%20passing-success.svg)]()

---

## 🏛️ Sovereign Conduit Trilogy Context

**NexusRecon** is **Showcase 3** of the **Sovereign Conduit Showcase Trilogy**:

1. **Showcase 1 (`sentry-edge-rs`)**: Edge-First WAF & Layer-7 Reverse Proxy with eBPF Rate Limiting & Zero-CDN HTML Dashboards.
2. **Showcase 2 (`forgetunnel-rs`)**: Sovereign Local-AI & Webhook Edge Gateway with Real-Time SSE/NDJSON TTFT/TPS Metering and SHA-256 Blockchain Non-Repudiation.
3. **Showcase 3 (`nexus-recon-rs`)**: Air-Gapped Subnet Incident Commander & Network Radar with Radix IP Trie Routing, Differential Rogue Asset Detection, and Decoupled 6-Format SST Reports.

---

## 🧭 Overview

NexusRecon is an autonomous, inside-out network reconnaissance engine and incident response cockpit. It enables homelab operators, SREs, and SOC engineers to map subnets, detect rogue hardware attachments, track port surface deltas, and export cryptographic compliance dossiers without requiring inbound open firewall ports, external SaaS dependencies, or heavy monitoring daemons.

```text
┌──────────────────────────────┐                ┌──────────────────────────────┐
│  Inside-Out Subnet Sweeper   │ ══════════════ │  Radix Trie LPM Host Index   │
│  (Async TCP Port Probing)    │                │  (O(k) Fast Subnet Routing)  │
└──────────────┬───────────────┘                └──────────────┬───────────────┘
               │                                               │
               ▼                                               ▼
┌──────────────────────────────┐                ┌──────────────────────────────┐
│  SQLite WAL Forensics Ledger │ ══════════════ │  Decoupled 6-Format Reports  │
│  (Delta History & Anomaly)   │                │  (HTML5, ASCII, MD, CSV, ...)│
└──────────────┬───────────────┘                └──────────────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│  SHA-256 Blockchain Audit    │
│  (Tamper-Evident Hash-Chain) │
└──────────────────────────────┘
```

---

## ✨ Key Features

1. **Inside-Out Subnet Reconnaissance**: High-concurrency async TCP connect sweep with configurable worker pool semaphores.
2. **Bitwise Radix IP Trie ($O(k)$ Routing)**: Longest Prefix Match (LPM) IPv4 host record lookup.
3. **Embedded IEEE MAC OUI Database**: Instant MAC vendor identification (Raspberry Pi, Apple, VMware, Intel, Espressif, Dell, etc.).
4. **Differential Snapshot Engine**: Computes $\Delta = \text{Snapshot}_{t_1} - \text{Snapshot}_{t_0}$ to isolate rogue devices and newly opened ports.
5. **Rolling SHA-256 Blockchain Audit**: Cryptographic tamper-evident hash-chain guaranteeing forensic non-repudiation.
6. **4-Tier Action Gatekeeper**: Granular safety matrix preventing unauthorized destructive operations.
7. **Decoupled 6-Format SST Reports**: Single Source of Truth generation of HTML5 Dossier (Zero-Inline, Strict CSP), ANSI ASCII, GitHub Markdown, RFC 4180 CSV (Formula Injection Sanitized), JSON, and JSONL.
8. **Static Standalone Musl PIE**: Portable, zero-dependency release binary for air-gapped forensic field kits.

---

## 📚 Field Manuals & Documentation

- [📖 Operator Guide (`NEXUS-DOC-OP-01`)](docs/OPERATOR_GUIDE.md)
- [📦 Installation & Uninstallation Guide (`NEXUS-DOC-INST-01`)](docs/INSTALLATION_AND_UNINSTALLATION.md)
- [🛡️ Architecture & Security Manual (`NEXUS-DOC-ARCH-01`)](docs/ARCHITECTURE_AND_SECURITY.md)

---

## 🚀 Quickstart

### 1. Build from Source
```bash
cargo build --release --workspace
```

### 2. Run Comprehensive TDD Battery (51 Tests)
```bash
cargo test --workspace
```

### 3. Generate Default Configuration Template
```bash
./target/release/nexus-recon --generate-config > nexus-recon.toml
```

### 4. Sweep Local Subnet
```bash
./target/release/nexus-recon sweep 192.0.2.0/24 --ports 22,53,80,443,3000,8080,11434 --concurrency 64
```

### 5. Run Differential Anomaly Detection
```bash
./target/release/nexus-recon diff
```

### 6. Verify Blockchain Ledger Integrity
```bash
./target/release/nexus-recon audit
```

### 7. Export Decoupled 6-Format Reports
```bash
./target/release/nexus-recon report --format html --output nexus_report.html
./target/release/nexus-recon report --format ascii --output nexus_report.txt
./target/release/nexus-recon report --format md --output nexus_report.md
./target/release/nexus-recon report --format csv --output nexus_report.csv
./target/release/nexus-recon report --format json --output nexus_report.json
./target/release/nexus-recon report --format jsonl --output nexus_report.jsonl
```

---

## 🏗️ Crates Architecture (OJP)

| Crate | Responsibility |
| :--- | :--- |
| **`nexus-core`** | Radix IP Trie, OUI Database, Safety Matrix, Snapshot Diff, Config |
| **`nexus-telemetry`** | Picosecond Timer, 5W1H Micro-Provenance, SHA-256 Blockchain Engine |
| **`nexus-scanner`** | Async TCP Connect Scanner, Semaphore Concurrency Limiter, Subnet Sweeper |
| **`nexus-ledger`** | SQLite WAL Storage, Snapshot History, Blockchain Non-Repudiation Verifier |
| **`nexus-reports`** | Decoupled 6-Format Report Formatters, CSV Formula Defense, Strict CSP |
| **`nexus-cli`** | Operator CLI, ANSI Terminal Views, Live HUD Monitor |

---

## 🛡️ License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
