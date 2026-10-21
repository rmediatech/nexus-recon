use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "nexus-recon",
    author = "Rick Walker <rick@rmediatech.com>",
    version = "0.1.0",
    about = "📡 Sovereign Air-Gapped Subnet Incident Commander & Network Radar",
    long_about = "NexusRecon performs inside-out subnet reconnaissance, ARP/ICMP/TCP host trie mapping, SQLite WAL anomaly tracking, and zero-CDN compliance report generation.",
    after_help = "SOVEREIGN PROVENANCE:\n  - Authenticated via Sovereign Master Key 4E428019A109578B.\n  - Release Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01"
)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", help = "Path to TOML configuration file")]
    pub config: Option<PathBuf>,

    #[arg(long, help = "Generate default nexus-recon.toml configuration template")]
    pub generate_config: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Perform high-concurrency async TCP sweep across a CIDR subnet")]
    Sweep {
        #[arg(default_value = "192.0.2.0/24", help = "Target Subnet CIDR")]
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
        #[arg(default_value = "192.0.2.0/24", help = "Target Subnet CIDR")]
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
