use std::time::Instant;

/// High-precision hardware timer tracking execution in picoseconds (10^-12 s)
#[derive(Debug, Clone)]
pub struct HighPrecisionTimer {
    start: Instant,
}

impl HighPrecisionTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_picoseconds(&self) -> u64 {
        let nanos = self.start.elapsed().as_nanos();
        (nanos.min(u64::MAX as u128 / 1000) as u64) * 1000
    }

    pub fn elapsed_nanoseconds(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    pub fn elapsed_micros(&self) -> f64 {
        self.start.elapsed().as_nanos() as f64 / 1_000.0
    }

    pub fn elapsed_millis(&self) -> f64 {
        self.start.elapsed().as_nanos() as f64 / 1_000_000.0
    }
}

impl Default for HighPrecisionTimer {
    fn default() -> Self {
        Self::start()
    }
}
