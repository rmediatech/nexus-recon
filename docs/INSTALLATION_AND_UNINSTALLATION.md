# 📦 NexusRecon Installation & Uninstallation Field Manual (`NEXUS-DOC-INST-01`)

> **Air-Gapped Subnet Incident Commander & Network Radar**  
> *Complete lifecycle guide for deploying, configuring, verifying, and cleanly purging NexusRecon on Linux/POSIX bare-metal, containers, and air-gapped field appliances.*

---

## 📑 Table of Contents
1. [Prerequisites & System Requirements](#1-prerequisites--system-requirements)
2. [Building from Source (Standard & Static Musl PIE)](#2-building-from-source-standard--static-musl-pie)
3. [Binary Deployment & File Paths](#3-binary-deployment--file-paths)
4. [Service Configuration (Systemd Integration)](#4-service-configuration-systemd-integration)
5. [Verification & Post-Install Smoke Test](#5-verification--post-install-smoke-test)
6. [Clean Uninstallation & Data Purging](#6-clean-uninstallation--data-purging)

---

## 1. Prerequisites & System Requirements

### Hardware Requirements
- **Architecture**: `x86_64` or `aarch64`
- **Memory**: 64 MB minimum (256 MB recommended for large CIDR sweeps like `/16`)
- **Storage**: 15 MB for static binary + SQLite WAL storage for host snapshots

### Software Dependencies
- **Linux Kernel**: 4.19+ (compatible with standard POSIX sockets and eBPF/raw sockets)
- **Rust Toolchain (Build-time only)**: 1.75.0+ with `cargo`
- **Static Linking (Optional)**: `musl-tools` and `x86_64-unknown-linux-musl` target

---

## 2. Building from Source (Standard & Static Musl PIE)

### Standard Release Build
```bash
git clone git@github.com:xuoxod/nexus-recon.git
cd nexus-recon
cargo build --release --workspace
```
The optimized binary is located at `target/release/nexus-recon`.

### Static Standalone Musl PIE Release Build
For true air-gapped portable deployment with zero runtime libc dependencies:
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --bin nexus-recon
```
The static binary is located at `target/x86_64-unknown-linux-musl/release/nexus-recon`.

Verify static linkage:
```bash
file target/x86_64-unknown-linux-musl/release/nexus-recon
# Output: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked
```

---

## 3. Binary Deployment & File Paths

Install the binary into the system path:
```bash
sudo install -m 755 target/release/nexus-recon /usr/local/bin/nexus-recon
```

### Directory Structure
- **Binary**: `/usr/local/bin/nexus-recon`
- **Configuration**: `/etc/nexus-recon/nexus-recon.toml` or `~/.config/nexus-recon/nexus-recon.toml`
- **SQLite WAL Ledger**: `/var/lib/nexus-recon/nexus_ledger.db`

Generate configuration directory and default config:
```bash
sudo mkdir -p /etc/nexus-recon /var/lib/nexus-recon
sudo chmod 700 /var/lib/nexus-recon
nexus-recon --generate-config | sudo tee /etc/nexus-recon/nexus-recon.toml
```

---

## 4. Service Configuration (Systemd Integration)

Create a systemd unit `/etc/systemd/system/nexus-recon.service` for continuous periodic subnet monitoring:

```ini
[Unit]
Description=NexusRecon Air-Gapped Subnet Incident Commander
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/nexus-recon monitor
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nexus-recon
```

---

## 5. Verification & Post-Install Smoke Test

Execute a quick subnet verification scan:
```bash
nexus-recon sweep 127.0.0.1/32 --ports 22,80,443 --timeout 100
```

Verify blockchain ledger audit integrity:
```bash
nexus-recon audit --db /var/lib/nexus-recon/nexus_ledger.db
```

---

## 6. Clean Uninstallation & Data Purging

To cleanly remove NexusRecon and purge all stored data:

### Stop and Disable Systemd Service
```bash
sudo systemctl stop nexus-recon || true
sudo systemctl disable nexus-recon || true
sudo rm -f /etc/systemd/system/nexus-recon.service
sudo systemctl daemon-reload
```

### Remove Binary and Configuration
```bash
sudo rm -f /usr/local/bin/nexus-recon
sudo rm -rf /etc/nexus-recon
```

### Purge SQLite WAL Ledger (Destructive)
```bash
sudo rm -rf /var/lib/nexus-recon
```
