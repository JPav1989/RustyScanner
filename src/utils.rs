use sha2::{Sha256, Digest};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub const QUARANTINE_LOG: &str = "quarantine_log.csv";
pub const QUARANTINE_DIR: &str = "./quarantine";

pub fn hash_file(path: &str) -> Option<String> {
    let contents = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(contents);
    Some(format!("{:x}", hasher.finalize()))
}

pub fn log_quarantine_event(original: &Path, quarantined: &Path, threats: &[String]) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(QUARANTINE_LOG)
        .expect("Failed to open quarantine log");

    let line = format!(
        "\"{}\",\"{}\",\"{}\"\n",
        original.display(),
        quarantined.display(),
        threats.join("; ")
    );

    if let Err(e) = file.write_all(line.as_bytes()) {
        eprintln!("Failed to write to quarantine log: {}", e);
    }
}