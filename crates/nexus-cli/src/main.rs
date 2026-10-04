use clap::{Parser, Subcommand};
use colored::Colorize;
use nexus_core::diff::SnapshotDiffEngine;
use nexus_core::models::{HostStatus, SubnetAuditSnapshot};
use nexus_core::NexusConfig;
use nexus_ledger::NexusLedger;
use nexus_reports::document::NexusReportDocument;
use nexus_reports::formatters::{AsciiFormatter, CsvFormatter, HtmlFormatter, JsonFormatter, JsonlFormatter, MarkdownFormatter};
use nexus_reports::{export_air_gapped_json, generate_html_dossier, import_air_gapped_json};
use nexus_scanner::sweep::{SubnetSweeper, SweepConfig};
use nexus_telemetry::chain::HashChain;
use nexus_telemetry::provenance::{IncidentMinutiae, IncidentProvenance};
use nexus_telemetry::timer::HighPrecisionTimer;
use std::fs;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "nexus-recon",
    author = "rick walker <xuoxod@gmail.com>",
    version = "0.1.0",
    about = "📡 Sovereign Air-Gapped Subnet Incident Commander & Network Radar",
    long_about = "NexusRecon performs inside-out subnet reconnaissance, ARP/ICMP/TCP host trie mapping, SQLite WAL anomaly tracking, and zero-CDN compliance report generation.",
    after_help = "SOVEREIGN PROVENANCE:\n  - Authenticated via Sovereign Master Key 4E428019A109578B.\n  - Release Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01"
)]
struct Cli {
    #[arg(short, long, value_name = "FILE", help = "Path to TOML configuration file")]
    config: Option<PathBuf>,

    #[arg(long, help = "Generate default nexus-recon.toml configuration template")]
    generate_config: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Perform high-concurrency async TCP sweep across a CIDR subnet")]
    Sweep {
        #[arg(default_value = "192.168.1.0/24", help = "Target Subnet CIDR")]
        cidr: String,

        #[arg(short, long, value_delimiter = ',', help = "Target TCP ports to scan (e.g. 22,80,443,11434)")]
        ports: Option<Vec<u16>>,

        #[arg(long, default_value = "50", help = "Concurrent worker tasks")]
        concurrency: usize,

        #[arg(long, default_value = "250", help = "Socket timeout in milliseconds")]
        timeout: u64,
    },

    #[command(about = "Quick scan a subnet CIDR for active hosts and open ports")]
    Scan {
        #[arg(default_value = "192.168.1.0/24", help = "Target Subnet CIDR")]
        cidr: String,

        #[arg(short, long, value_delimiter = ',', help = "Target TCP ports to scan (e.g. 22,80,443,11434)")]
        ports: Option<Vec<u16>>,

        #[arg(long, help = "Export report to HTML file path")]
        export_html: Option<PathBuf>,

        #[arg(long, help = "Export report to air-gapped JSON file path")]
        export_json: Option<PathBuf>,
    },

    #[command(about = "List known network hosts from SQLite WAL ledger")]
    Hosts {
        #[arg(short, long, default_value = "50", help = "Maximum hosts to list")]
        limit: usize,

        #[arg(short, long, help = "Path to SQLite database")]
        db: Option<PathBuf>,
    },

    #[command(about = "Compute differential analysis between last two snapshots")]
    Diff {
        #[arg(short, long, help = "Path to SQLite database")]
        db: Option<PathBuf>,
    },

    #[command(about = "Generate decoupled 6-format enterprise reports from SQLite ledger")]
    Report {
        #[arg(short, long, default_value = "html", help = "Format: html, ascii, markdown, csv, json, jsonl")]
        format: String,

        #[arg(short, long, help = "Optional file path to write report output")]
        output: Option<PathBuf>,

        #[arg(short, long, help = "Path to SQLite database")]
        db: Option<PathBuf>,
    },

    #[command(about = "Verify cryptographic SHA-256 blockchain ledger integrity")]
    Audit {
        #[arg(short, long, help = "Path to SQLite database")]
        db: Option<PathBuf>,
    },

    #[command(about = "Launch live incident response monitoring HUD")]
    Monitor {
        #[arg(short, long, help = "Path to SQLite database")]
        db: Option<PathBuf>,
    },

    #[command(about = "Ingest air-gapped forensic JSON audit dump")]
    Ingest {
        #[arg(help = "Path to forensic JSON file")]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Verify Sovereign Cryptographic Watermark & Key Provenance
    assert!(
        nexus_core::provenance::verify_sovereign_watermark(),
        "Sovereign Cryptographic Provenance Tamper Detected!"
    );

    if cli.generate_config {
        println!("{}", NexusConfig::generate_default_template());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let (config, config_source) = NexusConfig::discover_or_default(cli.config.as_deref())?;
    let ledger = NexusLedger::open(Path::new(&config.db_path))?;

    println!(
        "{}",
        "====================================================================".bright_blue()
    );
    println!(
        "{}",
        "📡 NEXUS-RECON : AIR-GAPPED SUBNET INCIDENT COMMANDER (v0.1.0)"
            .bright_cyan()
            .bold()
    );
    println!(
        "   Node: {} | Config: {}",
        config.node_label.bright_yellow(),
        config_source.display().to_string().bright_green()
    );
    println!(
        "{}",
        "====================================================================".bright_blue()
    );

    match cli.command {
        Some(Commands::Sweep { cidr, ports, concurrency, timeout }) => {
            let scan_ports = ports.unwrap_or(config.scan_ports.clone());
            println!("🔍 Executing High-Concurrency Async Sweep: {} (Ports: {:?})", cidr.bright_cyan().bold(), scan_ports);

            let timer = HighPrecisionTimer::start();
            let sweep_cfg = SweepConfig {
                cidr: cidr.clone(),
                ports: scan_ports.clone(),
                concurrency,
                timeout_ms: timeout,
            };
            let sweeper = SubnetSweeper::new(sweep_cfg);
            let hosts = sweeper.execute_sweep().await?;
            let duration_ps = timer.elapsed_picoseconds();

            for h in &hosts {
                ledger.record_host(h)?;
            }

            let snapshot = SubnetAuditSnapshot::new(&cidr, 254, hosts.clone(), &config.secret_key);
            ledger.record_snapshot(&snapshot)?;

            // Record cryptographic blockchain block
            let mut chain = HashChain::new(&config.secret_key);
            let minutiae = IncidentMinutiae {
                duration_ps,
                hosts_discovered: hosts.len(),
                open_ports_found: hosts.iter().map(|h| h.open_ports.len()).sum(),
                safety_tier: "Tier2".to_string(),
                status_code: 200,
                ..Default::default()
            };
            let entry = IncidentProvenance::new(
                &config.node_label,
                "127.0.0.1",
                &cidr,
                "SubnetSweep",
                "TCP-ASYNC",
                minutiae,
            );
            let block = chain.append(entry);
            ledger.record_telemetry_block(&block)?;

            println!("\n{:<16} {:<18} {:<24} {:<12} {}", "IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "PORTS", "STATUS");
            println!("{}", "--------------------------------------------------------------------------------".bright_black());
            for h in &hosts {
                let status_colored = match h.status {
                    HostStatus::Trusted => "TRUSTED".bright_green(),
                    HostStatus::Active => "ACTIVE".bright_blue(),
                    HostStatus::Rogue => "ROGUE ⚠️".bright_red().bold(),
                    HostStatus::Stale => "STALE".bright_black(),
                };
                let ports_str = h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                println!(
                    "{:<16} {:<18} {:<24} {:<12} {}",
                    h.ip.to_string().bright_cyan(),
                    h.mac.as_deref().unwrap_or("N/A"),
                    h.hostname.as_deref().unwrap_or("N/A").bright_white(),
                    ports_str,
                    status_colored
                );
            }
            println!("\n✅ Sweep Complete: {} active assets discovered in {:.2}ms.", hosts.len(), timer.elapsed_millis());
        }

        Some(Commands::Scan { cidr, ports, export_html, export_json }) => {
            let scan_ports = ports.unwrap_or(config.scan_ports.clone());
            println!("🔍 Scanning CIDR {} for ports {:?}", cidr.bright_cyan().bold(), scan_ports);

            let sweeper = SubnetSweeper::new(SweepConfig {
                cidr: cidr.clone(),
                ports: scan_ports.clone(),
                concurrency: 20,
                timeout_ms: 200,
            });
            let hosts = sweeper.execute_sweep().await.unwrap_or_default();

            for h in &hosts {
                ledger.record_host(h)?;
            }

            let snapshot = SubnetAuditSnapshot::new(&cidr, 254, hosts.clone(), &config.secret_key);
            ledger.record_snapshot(&snapshot)?;

            if let Some(html_path) = export_html {
                let html = generate_html_dossier(&snapshot, &config.node_label);
                fs::write(&html_path, html)?;
                println!("\n📑 Exported standalone Zero-CDN HTML dossier: {}", html_path.display().to_string().bright_green());
            }

            if let Some(json_path) = export_json {
                let json_data = export_air_gapped_json(&snapshot);
                fs::write(&json_path, json_data)?;
                println!("📦 Exported signed air-gapped forensic JSON: {}", json_path.display().to_string().bright_yellow());
            }
        }

        Some(Commands::Hosts { limit, db }) => {
            let db_path = db.unwrap_or_else(|| PathBuf::from(&config.db_path));
            let target_ledger = NexusLedger::open(&db_path)?;
            let hosts = target_ledger.list_hosts(limit)?;
            println!("📋 Known Hosts in SQLite WAL Ledger ({} total):", hosts.len());
            println!("\n{:<16} {:<18} {:<24} {:<10}", "IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "STATUS");
            println!("{}", "-----------------------------------------------------------------".bright_black());
            for h in hosts {
                println!(
                    "{:<16} {:<18} {:<24} {:?}",
                    h.ip.to_string().bright_cyan(),
                    h.mac.as_deref().unwrap_or("N/A"),
                    h.hostname.as_deref().unwrap_or("N/A"),
                    h.status
                );
            }
        }

        Some(Commands::Diff { db }) => {
            let db_path = db.unwrap_or_else(|| PathBuf::from(&config.db_path));
            let target_ledger = NexusLedger::open(&db_path)?;
            let snapshots = target_ledger.list_snapshots(2)?;
            if snapshots.len() < 2 {
                println!("⚠️ Need at least 2 recorded subnet snapshots to compute differential changes.");
                return Ok(());
            }

            let diff = SnapshotDiffEngine::compute_diff(&snapshots[1], &snapshots[0]);
            println!("🌪️  DIFFERENTIAL SNAPSHOT ANALYSIS:");
            println!("  • New Rogue / Active Hosts: {}", diff.new_hosts.len());
            for h in &diff.new_hosts {
                println!("    + [{:?}] {} (Ports: {:?})", h.status, h.ip, h.open_ports);
            }
            println!("  • Missing / Offline Hosts: {}", diff.missing_hosts.len());
            for h in &diff.missing_hosts {
                println!("    - {}", h.ip);
            }
            println!("  • Newly Opened Ports: {}", diff.opened_ports.len());
            for p in &diff.opened_ports {
                println!("    * Host {}: Port {} opened", p.ip, p.port);
            }
        }

        Some(Commands::Report { format, output, db }) => {
            let db_path = db.unwrap_or_else(|| PathBuf::from(&config.db_path));
            let target_ledger = NexusLedger::open(&db_path)?;
            let hosts = target_ledger.list_hosts(250)?;
            let mut doc = NexusReportDocument::new(&config.node_label, &config.subnet_cidr);
            for h in hosts {
                doc.add_host(h);
            }

            let rendered = match format.to_lowercase().as_str() {
                "ascii" => AsciiFormatter::render(&doc),
                "markdown" | "md" => MarkdownFormatter::render(&doc),
                "csv" => CsvFormatter::render(&doc),
                "json" => JsonFormatter::render(&doc),
                "jsonl" => JsonlFormatter::render(&doc),
                _ => HtmlFormatter::render(&doc),
            };

            if let Some(out_path) = output {
                fs::write(&out_path, &rendered)?;
                println!("✅ Generated {} report at: {}", format.to_uppercase(), out_path.display().to_string().bright_green());
            } else {
                println!("{}", rendered);
            }
        }

        Some(Commands::Audit { db }) => {
            let db_path = db.unwrap_or_else(|| PathBuf::from(&config.db_path));
            println!("🔍 Auditing cryptographic SHA-256 blockchain ledger at: {}", db_path.display());
            let target_ledger = NexusLedger::open(&db_path)?;
            match target_ledger.verify_stored_chain_integrity(&config.secret_key) {
                Ok(blocks) => {
                    println!("✅ Blockchain Integrity 100% VERIFIED across {} blocks (Zero Tampering Detected)", blocks);
                }
                Err(e) => {
                    eprintln!("❌ BLOCKCHAIN AUDIT FAILURE: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::Monitor { db }) => {
            let db_path = db.unwrap_or_else(|| PathBuf::from(&config.db_path));
            let target_ledger = NexusLedger::open(&db_path)?;
            println!("📡 Launching Live Nexus Incident Monitor HUD...");
            println!("Subnet: {} | Mode: Passive + Active Sweep | Status: ARMED", config.subnet_cidr);
            let stats = target_ledger.get_summary_stats()?;
            println!("Active Devices: {} | Rogue Alerts: {} | Total Snapshots: {}", stats.active_hosts, stats.rogue_hosts, stats.total_snapshots);
        }

        Some(Commands::Ingest { file }) => {
            let json_str = fs::read_to_string(&file)?;
            let snapshot = import_air_gapped_json(&json_str, &config.secret_key)?;
            ledger.record_snapshot(&snapshot)?;
            println!("📥 Ingested forensic snapshot '{}' ({} hosts, signature verified ✅)", snapshot.id.bright_cyan(), snapshot.hosts.len());
        }

        None => {
            println!("Use 'nexus-recon --help' to view available commands.");
        }
    }

    Ok(())
}
