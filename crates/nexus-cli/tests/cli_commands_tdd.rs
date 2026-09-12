use std::process::Command;

#[test]
fn test_cli_help_and_version() {
    let bin_path = env!("CARGO_BIN_EXE_nexus-recon");
    let mut cmd = Command::new(bin_path);

    let output = cmd.arg("--help").output().expect("Failed to run CLI --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nexus-recon") || stdout.contains("Air-Gapped"));
}

#[test]
fn test_cli_generate_config_template() {
    let bin_path = env!("CARGO_BIN_EXE_nexus-recon");
    let mut cmd = Command::new(bin_path);

    let output = cmd.arg("--generate-config").output().expect("Failed to run CLI --generate-config");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("node_label"));
    assert!(stdout.contains("subnet_cidr"));
}
