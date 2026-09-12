use nexus_core::fingerprint::ServiceFingerprintMatcher;

#[test]
fn test_rw_fingerprint_standard_ports() {
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(22), "SSH");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(80), "HTTP");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(443), "HTTPS/TLS");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(554), "RTSP-Stream");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(7880), "LiveKit-SFU");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(11434), "Ollama-LLM");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(6379), "Redis");
    assert_eq!(ServiceFingerprintMatcher::lookup_by_port(5432), "PostgreSQL");
}

#[test]
fn test_rw_fingerprint_banner_detection() {
    let ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
    assert_eq!(
        ServiceFingerprintMatcher::identify_from_banner(ssh_banner, 2222),
        "OpenSSH (Ubuntu)"
    );

    let http_banner = b"HTTP/1.1 200 OK\r\nServer: Caddy\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        ServiceFingerprintMatcher::identify_from_banner(http_banner, 8080),
        "Caddy Web Server"
    );

    let ollama_banner = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOllama is running";
    assert_eq!(
        ServiceFingerprintMatcher::identify_from_banner(ollama_banner, 11434),
        "Ollama LLM Engine"
    );
}

#[test]
fn test_ec_fingerprint_unknown_port_and_empty_banner() {
    assert_eq!(
        ServiceFingerprintMatcher::lookup_by_port(64999),
        "Unknown-Service"
    );
    assert_eq!(
        ServiceFingerprintMatcher::identify_from_banner(b"", 64999),
        "Unknown-Service"
    );
}
