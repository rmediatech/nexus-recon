use std::collections::HashMap;

pub struct OuiDatabase {
    prefixes: HashMap<String, String>,
}

impl OuiDatabase {
    pub fn new() -> Self {
        let mut prefixes = HashMap::new();
        // Standard homelab / enterprise vendor MAC prefixes (first 6 hex chars)
        prefixes.insert("b827eb".to_string(), "Raspberry Pi Foundation".to_string());
        prefixes.insert("dca632".to_string(), "Raspberry Pi Trading Ltd".to_string());
        prefixes.insert("e45f01".to_string(), "Raspberry Pi Ltd".to_string());
        prefixes.insert("001a11".to_string(), "Google LLC".to_string());
        prefixes.insert("f4f5d8".to_string(), "Google LLC".to_string());
        prefixes.insert("acde48".to_string(), "Apple, Inc.".to_string());
        prefixes.insert("3c22fb".to_string(), "Apple, Inc.".to_string());
        prefixes.insert("00155d".to_string(), "Microsoft Corporation".to_string());
        prefixes.insert("005056".to_string(), "VMware, Inc.".to_string());
        prefixes.insert("000c29".to_string(), "VMware, Inc.".to_string());
        prefixes.insert("525400".to_string(), "QEMU / KVM Virtual NIC".to_string());
        prefixes.insert("24a160".to_string(), "Espressif Systems".to_string());
        prefixes.insert("30aea4".to_string(), "Espressif Systems".to_string());
        prefixes.insert("7483c2".to_string(), "Ubiquiti Networks".to_string());
        prefixes.insert("f09fc2".to_string(), "Ubiquiti Networks".to_string());
        prefixes.insert("001b21".to_string(), "Intel Corporation".to_string());
        prefixes.insert("7085c2".to_string(), "ASUSTek Computer".to_string());

        Self { prefixes }
    }

    pub fn lookup(&self, mac: &str) -> String {
        let clean_mac: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_lowercase();

        if clean_mac.len() >= 6 {
            let prefix = &clean_mac[..6];
            if let Some(vendor) = self.prefixes.get(prefix) {
                return vendor.clone();
            }
        }

        "Unknown Vendor / Generic NIC".to_string()
    }
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::new()
    }
}
