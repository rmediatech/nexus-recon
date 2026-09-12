pub struct ServiceFingerprintMatcher;

impl ServiceFingerprintMatcher {
    pub fn lookup_by_port(port: u16) -> &'static str {
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            443 => "HTTPS/TLS",
            554 => "RTSP-Stream",
            1883 => "MQTT",
            3000 => "Node/Webhook-Receiver",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            6379 => "Redis",
            7880 | 7881 => "LiveKit-SFU",
            8080 | 8000 | 8888 => "HTTP-Alt",
            8443 => "HTTPS-Alt",
            9090 => "Prometheus",
            11434 => "Ollama-LLM",
            27017 => "MongoDB",
            _ => "Unknown-Service",
        }
    }

    pub fn identify_from_banner(banner: &[u8], port: u16) -> String {
        let text = String::from_utf8_lossy(banner);

        if text.contains("SSH-2.0-OpenSSH") {
            if text.contains("Ubuntu") {
                return "OpenSSH (Ubuntu)".to_string();
            } else if text.contains("Debian") {
                return "OpenSSH (Debian)".to_string();
            }
            return "OpenSSH".to_string();
        }

        if text.contains("Server: Caddy") || text.contains("caddy") {
            return "Caddy Web Server".to_string();
        }

        if text.contains("Server: nginx") {
            return "Nginx Web Server".to_string();
        }

        if text.contains("Server: Apache") {
            return "Apache HTTPD".to_string();
        }

        if text.contains("Ollama is running") || text.contains("ollama") {
            return "Ollama LLM Engine".to_string();
        }

        if text.contains("LiveKit") {
            return "LiveKit WebRTC Media Server".to_string();
        }

        if text.contains("Redis") {
            return "Redis Database".to_string();
        }

        // Fallback to port lookup
        Self::lookup_by_port(port).to_string()
    }
}
