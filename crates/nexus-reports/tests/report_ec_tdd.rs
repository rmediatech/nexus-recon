use nexus_reports::document::NexusReportDocument;
use nexus_reports::formatters::{AsciiFormatter, CsvFormatter, HtmlFormatter, JsonFormatter, JsonlFormatter, MarkdownFormatter};

#[test]
fn test_ec_empty_ledger_report_rendering() {
    let doc = NexusReportDocument::new("empty-node", "0.0.0.0/0");

    assert!(!HtmlFormatter::render(&doc).is_empty());
    assert!(!AsciiFormatter::render(&doc).is_empty());
    assert!(!MarkdownFormatter::render(&doc).is_empty());
    assert!(!CsvFormatter::render(&doc).is_empty());
    assert!(!JsonFormatter::render(&doc).is_empty());
    assert!(JsonlFormatter::render(&doc).is_empty());
}
