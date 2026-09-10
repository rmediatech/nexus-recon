use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use crate::models::HostRecord;

#[derive(Default)]
pub struct RadixTrieNode {
    pub host: Option<HostRecord>,
    pub children: HashMap<bool, Box<RadixTrieNode>>,
}

pub struct SubnetRadixTrie {
    root: RadixTrieNode,
}

impl SubnetRadixTrie {
    pub fn new() -> Self {
        Self {
            root: RadixTrieNode::default(),
        }
    }

    fn ip_to_bits(ip: &Ipv4Addr) -> Vec<bool> {
        let octets = ip.octets();
        let mut bits = Vec::with_capacity(32);
        for octet in octets {
            for i in (0..8).rev() {
                bits.push(((octet >> i) & 1) == 1);
            }
        }
        bits
    }

    pub fn insert(&mut self, record: HostRecord) {
        if let IpAddr::V4(v4) = record.ip {
            let bits = Self::ip_to_bits(&v4);
            let mut curr = &mut self.root;

            for bit in bits {
                curr = curr.children.entry(bit).or_default();
            }

            curr.host = Some(record);
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&HostRecord> {
        if let IpAddr::V4(v4) = ip {
            let bits = Self::ip_to_bits(v4);
            let mut curr = &self.root;

            for bit in bits {
                if let Some(next) = curr.children.get(&bit) {
                    curr = next;
                } else {
                    return None;
                }
            }

            curr.host.as_ref()
        } else {
            None
        }
    }

    pub fn all_hosts(&self) -> Vec<HostRecord> {
        let mut results = Vec::new();
        Self::collect_hosts(&self.root, &mut results);
        results
    }

    fn collect_hosts(node: &RadixTrieNode, results: &mut Vec<HostRecord>) {
        if let Some(h) = &node.host {
            results.push(h.clone());
        }
        for child in node.children.values() {
            Self::collect_hosts(child, results);
        }
    }
}

impl Default for SubnetRadixTrie {
    fn default() -> Self {
        Self::new()
    }
}
