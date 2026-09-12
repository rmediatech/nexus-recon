use crate::document::NexusReportDocument;

pub struct JsonFormatter;

impl JsonFormatter {
    pub fn render(doc: &NexusReportDocument) -> String {
        serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".to_string())
    }
}
