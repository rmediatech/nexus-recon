# 📖 NexusRecon Enterprise Operator Guide (`NEXUS-DOC-OP-01`)

> **Air-Gapped Subnet Incident Commander & Network Radar**  
> *The Decoupled Open-Source Solution for Subnet Asset Discovery, Differential Anomaly Tracking, and SHA-256 Blockchain Audit Verification.*

---

## 📑 Table of Contents
1. [Overview & Architectural Philosophy](#1-overview--architectural-philosophy)
2. [CLI Command Reference](#2-cli-command-reference)
3. [High-Concurrency Subnet Sweeps](#3-high-concurrency-subnet-sweeps)
4. [Differential Anomaly Detection & Rogue Asset Tracking](#4-differential-anomaly-detection--rogue-asset-tracking)
5. [4-Tier Safety Matrix & Action Gatekeeper](#5-4-tier-safety-matrix--action-gatekeeper)
6. [Air-Gapped Forensics: Export & Cryptographic Ingestion](#6-air-gapped-forensics-export--cryptographic-ingestion)
7. [Decoupled 6-Format Enterprise Report Generation](#7-decoupled-6-format-enterprise-report-generation)
8. [SHA-256 Blockchain Non-Repudiation Auditing](#8-sha-256-blockchain-non-repudiation-auditing)
9. [Universal Orchestration & Automated Validation](#9-universal-orchestration--automated-validation)

---

## 1. Overview & Architectural Philosophy

NexusRecon is engineered around the **One-Job-Philosophy (OJP)**. It decouples high-speed async network scanning, IP Trie routing, SQLite WAL asset ledgering, blockchain audit trails, and multi-format report generation into strictly separated crates:

- **`nexus-core`**: Bitwise Radix IP Trie ($O(k)$ subnet routing), IEEE MAC OUI database, 4-tier safety matrix gatekeeper, differential snapshot analysis engine, and banner fingerprint matcher.
- **`nexus-telemetry`**: 5W1H micro-provenance schema, sub-nanosecond/picosecond precision execution timer (`HighPrecisionTimer`), and rolling SHA-256 blockchain hash-chain engine.
- **`nexus-scanner`**: High-performance async TCP connect port scanner with concurrency semaphore throttling and CIDR subnet sweeper.
- **`nexus-ledger`**: High-performance SQLite WAL persistent sink for discovered hosts, timestamped subnet snapshots, and cryptographic blockchain blocks.
- **`nexus-reports`**: Decoupled Single Source of Truth (SST) report engine generating 6 synchronized formats (Interactive Responsive HTML5 Dossier, ANSI ASCII Table, GitHub-Flavored Markdown, RFC 4180 CSV with Formula Injection Defense, Pretty JSON, Streaming JSONL).
- **`nexus-cli`**: High-performance operator CLI with ANSI terminal formatting and live monitoring HUD.

---

## 2. CLI Command Reference

The NexusRecon CLI binary (`nexus-recon`) provides comprehensive management commands:

| Command | Description | Safety Tier | Default / Flags |
| :--- | :--- | :--- | :--- |
| `nexus-recon sweep` | Perform high-concurrency async TCP sweep across a CIDR subnet | Tier 2 | `[CIDR] --ports 22,80,443 --concurrency 50 --timeout 250` |
| `nexus-recon scan` | Quick scan a subnet with optional Zero-CDN HTML or signed JSON export | Tier 2 | `[CIDR] --export-html report.html --export-json audit.json` |
| `nexus-recon hosts` | List known network hosts from SQLite WAL ledger | Tier 1 | `--limit 50 --db path/to/ledger.db` |
| `nexus-recon diff` | Compute differential analysis between last two snapshots (detects rogues) | Tier 1 | `--db path/to/ledger.db` |
| `nexus-recon report` | Generate decoupled 6-format enterprise reports from SQLite ledger | Tier 1 | `--format html,ascii,md,csv,json,jsonl --output out.ext --db db.sqlite` |
| `nexus-recon audit` | Verify SHA-256 cryptographic blockchain ledger against SQL injection or tampering | Tier 1 | `--db path/to/ledger.db` |
| `nexus-recon monitor` | Launch live incident response monitoring HUD | Tier 1 | `--db path/to/ledger.db` |
| `nexus-recon ingest` | Ingest and verify signed air-gapped forensic JSON audit dump | Tier 2 | `<FILE.json>` |
| `nexus-recon --generate-config` | Emit fully documented TOML configuration template | Tier 1 | `--generate-config` |

---

## 3. High-Concurrency Subnet Sweeps

NexusRecon discovers active assets across CIDR subnets asynchronously with configurable worker pools and per-port timeout bounds.

### Executing a Local Subnet Sweep
```bash
nexus-recon sweep 192.168.1.0/24 --ports 22,53,80,443,3000,8080,11434 --concurrency 64 --timeout 200
```

### Sample Output
```text
====================================================================
📡 NEXUS-RECON : AIR-GAPPED SUBNET INCIDENT COMMANDER (v0.1.0)
   Node: hyperion-prime | Config: in-memory-default
====================================================================
🔍 Executing High-Concurrency Async Sweep: 192.168.1.0/24 (Ports: [22, 53, 80, 443, 3000, 8080, 11434])

IP ADDRESS       MAC ADDRESS        HOSTNAME                 PORTS        STATUS
--------------------------------------------------------------------------------
192.168.1.1      b8:27:eb:aa:11:01  gateway.core.local       22,53,80,443 TRUSTED
192.168.1.10     00:0c:29:bb:22:02  hyperion-srv-01.local    22,443,3000  TRUSTED
192.168.1.199    ac:bc:32:ff:66:06  unauthorized-probe-99    22,4444      ROGUE ⚠️

✅ Sweep Complete: 3 active assets discovered in 42.15ms.
```

---

## 4. Differential Anomaly Detection & Rogue Asset Tracking

Every scan produces an immutable, HMAC-SHA256 signed `SubnetAuditSnapshot`. The `SnapshotDiffEngine` computes differential deltas between snapshots:

```bash
nexus-recon diff --db /path/to/nexus_recon.db
```

### Analysis Output
```text
🌪️  DIFFERENTIAL SNAPSHOT ANALYSIS:
  • New Rogue / Active Hosts: 1
    + [Rogue] 192.168.1.250 (Ports: [80, 8080, 9999])
  • Missing / Offline Hosts: 0
  • Newly Opened Ports: 1
    * Host 192.168.1.10: Port 8084 opened
```

---

## 5. 4-Tier Safety Matrix & Action Gatekeeper

Every operational action in NexusRecon is governed by a 4-tier authorization gatekeeper:

- **Tier 1 (Read-Only)**: Status queries, host listings, report generation, blockchain audits. Requires zero special authorization.
- **Tier 2 (Active Non-Destructive)**: Subnet sweeping, TCP banner grabbing, air-gapped forensic JSON ingestion.
- **Tier 3 (Elevated Impact)**: Bulk ledger purge, network interface reconfiguration, automated isolation. Requires `--force-approval` flag.
- **Tier 4 (Critical / Destructive)**: Hardware factory reset, ledger shredding. Requires strict confirmation code `CONFIRM-DESTRUCTIVE-PURGE-99`.

---

## 6. Air-Gapped Forensics: Export & Cryptographic Ingestion

For air-gapped security operations centers (SOC) without internet connectivity:

### Exporting Signed JSON Dossier
```bash
nexus-recon scan 10.0.0.0/24 --export-json /media/usb/forensic_dump.json
```

### Ingesting in Central Command Post
```bash
nexus-recon ingest /media/usb/forensic_dump.json
```
The ingestion engine verifies the HMAC-SHA256 signature using the shared sovereign secret before writing to the central SQLite WAL ledger.

---

## 7. Decoupled 6-Format Enterprise Report Generation

Generate synchronized enterprise reports across 6 decoupled formats:

```bash
# HTML5 Dossier (Strict Zero-Inline, Strict CSP, Responsive Native Look)
nexus-recon report --format html --output report.html

# ASCII Table
nexus-recon report --format ascii --output report.txt

# GitHub-Flavored Markdown
nexus-recon report --format md --output report.md

# RFC 4180 CSV (Sanitized against Formula Injection `=,+,-,@`)
nexus-recon report --format csv --output report.csv

# Structured JSON
nexus-recon report --format json --output report.json

# Streaming JSONL
nexus-recon report --format jsonl --output report.jsonl
```

---

## 8. SHA-256 Blockchain Non-Repudiation Auditing

Every network operation appends a cryptographic block containing:
- 8-byte big-endian block index
- ISO-8601 UTC timestamp
- Previous block hash
- SHA-256 payload digest of the 5W1H micro-provenance event

To audit the ledger for tampering:
```bash
nexus-recon audit --db /path/to/nexus_recon.db
```

Output:
```text
🔍 Auditing cryptographic SHA-256 blockchain ledger at: /path/to/nexus_recon.db
✅ Blockchain Integrity 100% VERIFIED across 20 blocks (Zero Tampering Detected)
```

---

## 9. Universal Orchestration & Automated Validation

Execute the universal global orchestrator to perform full-spectrum automated verification:
```bash
bash $HOME/universals/scripts/nexus-orchestrator.sh all
```

Or run the automated TDD battery:
```bash
bash $HOME/universals/scripts/tests/nexus_orchestrator_tdd.sh
```
