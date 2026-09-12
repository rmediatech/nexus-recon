use crate::document::NexusReportDocument;

pub struct JsonlFormatter;

impl JsonlFormatter {
    pub fn render(doc: &NexusReportDocument) -> String {
        let mut out = String::new();
        for h in &doc.hosts {
            if let Ok(line) = serde_json::to_string(h) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}
