use crate::models::{HostRecord, HostStatus, SubnetAuditSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortChange {
    pub ip: IpAddr,
    pub port: u16,
    pub state: String, // "Opened" or "Closed"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusChange {
    pub ip: IpAddr,
    pub old_status: HostStatus,
    pub new_status: HostStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkDiff {
    pub new_hosts: Vec<HostRecord>,
    pub missing_hosts: Vec<HostRecord>,
    pub opened_ports: Vec<PortChange>,
    pub closed_ports: Vec<PortChange>,
    pub status_changes: Vec<StatusChange>,
}

pub struct SnapshotDiffEngine;

impl SnapshotDiffEngine {
    pub fn compute_diff(before: &SubnetAuditSnapshot, after: &SubnetAuditSnapshot) -> NetworkDiff {
        let before_map: HashMap<IpAddr, &HostRecord> = before.hosts.iter().map(|h| (h.ip, h)).collect();
        let after_map: HashMap<IpAddr, &HostRecord> = after.hosts.iter().map(|h| (h.ip, h)).collect();

        let mut new_hosts = Vec::new();
        let mut missing_hosts = Vec::new();
        let mut opened_ports = Vec::new();
        let mut closed_ports = Vec::new();
        let mut status_changes = Vec::new();

        // Check for new hosts and changed hosts in 'after'
        for (ip, after_h) in &after_map {
            if let Some(before_h) = before_map.get(ip) {
                // Check status change
                if before_h.status != after_h.status {
                    status_changes.push(StatusChange {
                        ip: *ip,
                        old_status: before_h.status,
                        new_status: after_h.status,
                    });
                }

                // Check port changes
                let before_ports: HashSet<u16> = before_h.open_ports.iter().copied().collect();
                let after_ports: HashSet<u16> = after_h.open_ports.iter().copied().collect();

                for p in after_ports.difference(&before_ports) {
                    opened_ports.push(PortChange {
                        ip: *ip,
                        port: *p,
                        state: "Opened".to_string(),
                    });
                }

                for p in before_ports.difference(&after_ports) {
                    closed_ports.push(PortChange {
                        ip: *ip,
                        port: *p,
                        state: "Closed".to_string(),
                    });
                }
            } else {
                new_hosts.push((*after_h).clone());
            }
        }

        // Check for missing hosts from 'before'
        for (ip, before_h) in &before_map {
            if !after_map.contains_key(ip) {
                missing_hosts.push((*before_h).clone());
            }
        }

        NetworkDiff {
            new_hosts,
            missing_hosts,
            opened_ports,
            closed_ports,
            status_changes,
        }
    }
}
