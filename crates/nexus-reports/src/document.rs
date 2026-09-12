use chrono::Utc;
use nexus_core::models::{HostRecord, HostStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetSummaryMetrics {
    pub total_hosts: usize,
    pub active_hosts: usize,
    pub rogue_hosts: usize,
    pub stale_hosts: usize,
    pub trusted_hosts: usize,
    pub total_open_ports: usize,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusReportDocument {
    pub report_id: String,
    pub generated_at: String,
    pub node_label: String,
    pub subnet_cidr: String,
    pub metrics: SubnetSummaryMetrics,
    pub hosts: Vec<HostRecord>,
    pub executive_summary: String,
}

impl NexusReportDocument {
    pub fn new(node_label: impl Into<String>, subnet_cidr: impl Into<String>) -> Self {
        let generated_at = Utc::now().to_rfc3339();
        let report_id = format!("nexus-rep-{}", Utc::now().timestamp());

        Self {
            report_id,
            generated_at,
            node_label: node_label.into(),
            subnet_cidr: subnet_cidr.into(),
            metrics: SubnetSummaryMetrics {
                total_hosts: 0,
                active_hosts: 0,
                rogue_hosts: 0,
                stale_hosts: 0,
                trusted_hosts: 0,
                total_open_ports: 0,
                avg_latency_ms: 0.0,
            },
            hosts: Vec::new(),
            executive_summary: "Air-gapped subnet incident recon report initialized.".to_string(),
        }
    }

    pub fn add_host(&mut self, host: HostRecord) {
        self.hosts.push(host);
        self.recalculate_metrics();
    }

    pub fn recalculate_metrics(&mut self) {
        let total = self.hosts.len();
        let mut active = 0;
        let mut rogue = 0;
        let mut stale = 0;
        let mut trusted = 0;
        let mut total_ports = 0;
        let mut lat_sum = 0.0;

        for h in &self.hosts {
            match h.status {
                HostStatus::Active => active += 1,
                HostStatus::Rogue => rogue += 1,
                HostStatus::Stale => stale += 1,
                HostStatus::Trusted => trusted += 1,
            }
            total_ports += h.open_ports.len();
            lat_sum += h.latency_ms;
        }

        self.metrics = SubnetSummaryMetrics {
            total_hosts: total,
            active_hosts: active,
            rogue_hosts: rogue,
            stale_hosts: stale,
            trusted_hosts: trusted,
            total_open_ports: total_ports,
            avg_latency_ms: if total > 0 { lat_sum / total as f64 } else { 0.0 },
        };

        self.executive_summary = NarrativeStoryteller::generate_story(
            &self.node_label,
            &self.subnet_cidr,
            &self.metrics,
        );
    }
}

pub struct NarrativeStoryteller;

impl NarrativeStoryteller {
    pub fn generate_story(
        node_label: &str,
        subnet_cidr: &str,
        metrics: &SubnetSummaryMetrics,
    ) -> String {
        format!(
            "Node '{}' completed forensic recon on subnet '{}'. Detected {} total assets ({} active, {} trusted, {} rogue alert). Total open services cataloged: {} with an average network latency of {:.2}ms.",
            node_label,
            subnet_cidr,
            metrics.total_hosts,
            metrics.active_hosts,
            metrics.trusted_hosts,
            metrics.rogue_hosts,
            metrics.total_open_ports,
            metrics.avg_latency_ms,
        )
    }
}
