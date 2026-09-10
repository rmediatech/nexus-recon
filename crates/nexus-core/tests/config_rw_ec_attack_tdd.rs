use nexus_core::NexusConfig;
use std::fs;

#[test]
fn test_rw_config_template_roundtrip() {
    let template = NexusConfig::generate_default_template();
    let config: NexusConfig = toml::from_str(&template).expect("Default template should parse cleanly");
    assert_eq!(config.node_label, "hyperion-prime");
    assert_eq!(config.subnet_cidr, "192.168.1.0/24");
    assert!(config.scan_ports.contains(&22));
    assert!(config.validate().is_ok());
}

#[test]
fn test_rw_config_disk_persistence() {
    let temp_dir = std::env::temp_dir().join(format!("nexus_test_conf_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("nexus-recon.toml");

    let mut config = NexusConfig::default();
    config.node_label = "valkyrie-edge-02".to_string();
    config.subnet_cidr = "10.0.0.0/16".to_string();
    config.scan_ports = vec![80, 443, 8084];

    let toml_str = toml::to_string_pretty(&config).unwrap();
    fs::write(&file_path, toml_str).unwrap();

    let loaded = NexusConfig::load_from_file(&file_path).expect("Should load back cleanly");
    assert_eq!(loaded.node_label, "valkyrie-edge-02");
    assert_eq!(loaded.subnet_cidr, "10.0.0.0/16");
    assert_eq!(loaded.scan_ports, vec![80, 443, 8084]);

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_ec_config_boundary_ports() {
    let mut config = NexusConfig::default();
    config.scan_ports = vec![1, 65535];
    assert!(config.validate().is_ok());

    config.scan_interval_secs = 1;
    assert!(config.validate().is_ok());

    config.scan_interval_secs = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_attack_config_path_traversal() {
    let mut config = NexusConfig::default();
    config.db_path = "../../etc/shadow".to_string();
    assert!(config.validate().is_err(), "Path traversal in db_path must be rejected");
}

#[test]
fn test_attack_config_malformed_syntax() {
    let malformed = "node_label = [unclosed syntax";
    let res: std::result::Result<NexusConfig, _> = toml::from_str(malformed);
    assert!(res.is_err());
}

#[test]
fn test_attack_config_empty_ports() {
    let mut config = NexusConfig::default();
    config.scan_ports = vec![];
    assert!(config.validate().is_err(), "Empty scan_ports must be rejected");
}
