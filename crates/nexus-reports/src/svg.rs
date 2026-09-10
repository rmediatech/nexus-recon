pub fn render_status_donut_chart(trusted: usize, active: usize, rogue: usize, stale: usize) -> String {
    let total = (trusted + active + rogue + stale).max(1) as f64;
    let circumference = 2.0 * std::f64::consts::PI * 40.0; // r = 40

    let p_trusted = (trusted as f64 / total) * circumference;
    let p_active = (active as f64 / total) * circumference;
    let p_rogue = (rogue as f64 / total) * circumference;
    let p_stale = (stale as f64 / total) * circumference;

    let o_trusted = 0.0;
    let o_active = o_trusted + p_trusted;
    let o_rogue = o_active + p_active;
    let o_stale = o_rogue + p_rogue;

    format!(
        r##"<svg viewBox="0 0 120 120" width="120" height="120" xmlns="http://www.w3.org/2000/svg">
  <circle cx="60" cy="60" r="40" fill="transparent" stroke="#1e293b" stroke-width="16" />
  <circle cx="60" cy="60" r="40" fill="transparent" stroke="#10b981" stroke-width="16" stroke-dasharray="{:.1} {:.1}" stroke-dashoffset="-{:.1}" />
  <circle cx="60" cy="60" r="40" fill="transparent" stroke="#3b82f6" stroke-width="16" stroke-dasharray="{:.1} {:.1}" stroke-dashoffset="-{:.1}" />
  <circle cx="60" cy="60" r="40" fill="transparent" stroke="#ef4444" stroke-width="16" stroke-dasharray="{:.1} {:.1}" stroke-dashoffset="-{:.1}" />
  <circle cx="60" cy="60" r="40" fill="transparent" stroke="#64748b" stroke-width="16" stroke-dasharray="{:.1} {:.1}" stroke-dashoffset="-{:.1}" />
  <text x="60" y="65" fill="#f8fafc" font-size="14" font-weight="bold" text-anchor="middle" font-family="sans-serif">{}</text>
</svg>"##,
        p_trusted, circumference - p_trusted, o_trusted,
        p_active, circumference - p_active, o_active,
        p_rogue, circumference - p_rogue, o_rogue,
        p_stale, circumference - p_stale, o_stale,
        trusted + active + rogue + stale
    )
}

pub fn render_latency_sparkline(latencies: &[f64]) -> String {
    if latencies.is_empty() {
        return r##"<svg width="100" height="30"><line x1="0" y1="15" x2="100" y2="15" stroke="#475569" stroke-width="2"/></svg>"##.to_string();
    }

    let max = latencies.iter().cloned().fold(1.0, f64::max);
    let min = latencies.iter().cloned().fold(0.0, f64::min);
    let range = (max - min).max(0.1);

    let width = 120.0;
    let height = 30.0;
    let step = if latencies.len() > 1 {
        width / (latencies.len() - 1) as f64
    } else {
        width
    };

    let points: Vec<String> = latencies
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            let x = i as f64 * step;
            let norm = (val - min) / range;
            let y = height - (norm * (height - 6.0)) - 3.0;
            format!("{:.1},{:.1}", x, y)
        })
        .collect();

    format!(
        r##"<svg viewBox="0 0 120 30" width="120" height="30" xmlns="http://www.w3.org/2000/svg">
  <polyline fill="none" stroke="#06b6d4" stroke-width="2" points="{}" />
</svg>"##,
        points.join(" ")
    )
}
