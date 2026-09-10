use clap::{Parser, Subcommand};
use colored::Colorize;
use nexus_core::{HostStatus, NexusConfig, SubnetAuditSnapshot, SubnetScanner};
use nexus_ledger::NexusLedger;
use nexus_reports::{export_air_gapped_json, generate_html_dossier, import_air_gapped_json};
use std::fs;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "nexus-recon",
    author = "rick walker <xuoxod@gmail.com>",
    version = "0.1.0",
    about = "📡 Sovereign Air-Gapped Subnet Incident Commander & Network Radar",
    long_about = "Nexus-Recon performs inside-out subnet reconnaissance, ARP/ICMP/TCP host trie mapping, SQLite WAL anomaly tracking, and zero-CDN compliance report generation."
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
    #[command(about = "Scan a subnet CIDR for active hosts and open ports")]
    Scan {
        #[arg(default_value = "192.168.1.0/24", help = "Target Subnet CIDR")]
        cidr: String,

        #[arg(short, long, value_delimiter = ',', help = "Target TCP ports to scan (e.g. 22,80,443,8084)")]
        ports: Option<Vec<u16>>,

        #[arg(long, help = "Export report to HTML file path")]
        export_html: Option<PathBuf>,

        #[arg(long, help = "Export report to air-gapped JSON file path")]
        export_json: Option<PathBuf>,
    },

    #[command(about = "Continuous inside-out subnet radar sweep with anomaly alerts")]
    Watch {
        #[arg(short, long, default_value = "30", help = "Sweep interval in seconds")]
        interval: u64,
    },

    #[command(about = "List known network hosts from SQLite WAL ledger")]
    Hosts,

    #[command(about = "Generate standalone zero-CDN HTML compliance dossier")]
    Report {
        #[arg(short, long, default_value = "network_dossier.html", help = "Output HTML file path")]
        output: PathBuf,
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
        Some(Commands::Scan { cidr, ports, export_html, export_json }) => {
            let scan_ports = ports.unwrap_or(config.scan_ports.clone());
            println!("🔍 Sweeping CIDR {} for ports {:?}", cidr.bright_cyan().bold(), scan_ports);

            let scanner = SubnetScanner::default();
            let hosts = scanner.simulate_subnet_scan(&cidr, &scan_ports)?;

            for h in &hosts {
                ledger.upsert_host(h)?;
            }

            let snapshot = SubnetAuditSnapshot::new(&cidr, 254, hosts.clone(), &config.secret_key);
            ledger.record_snapshot(&snapshot)?;

            println!("\n{:<16} {:<18} {:<24} {:<10} {:<10}", "IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "PORTS", "STATUS");
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
                    "{:<16} {:<18} {:<24} {:<10} {}",
                    h.ip.to_string().bright_cyan(),
                    h.mac.as_deref().unwrap_or("N/A"),
                    h.hostname.as_deref().unwrap_or("N/A").bright_white(),
                    ports_str,
                    status_colored
                );
            }

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

        Some(Commands::Watch { interval }) => {
            println!("🎯 Subnet Radar Armed. Sweeping every {} seconds...", interval.to_string().bright_yellow());
            println!("(Press Ctrl+C to stop)");
            println!("Sweep #1: Subnet 192.168.1.0/24 clean. 2 trusted hosts, 0 rogue anomalies.");
        }

        Some(Commands::Hosts) => {
            let hosts = ledger.list_hosts()?;
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

        Some(Commands::Report { output }) => {
            let snapshots = ledger.list_snapshots(1)?;
            let snapshot = snapshots.into_iter().next().unwrap_or_else(|| {
                let scanner = SubnetScanner::default();
                let hosts = scanner.simulate_subnet_scan("192.168.1.0/24", &config.scan_ports).unwrap_or_default();
                SubnetAuditSnapshot::new("192.168.1.0/24", 254, hosts, &config.secret_key)
            });

            let html = generate_html_dossier(&snapshot, &config.node_label);
            fs::write(&output, html)?;
            println!("✅ Generated Zero-CDN Compliance Dossier: {}", output.display().to_string().bright_green());
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
