use crate::signature;
use walkdir::WalkDir;
use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use std::fs::copy;
use crate::utils;
use std::fs::OpenOptions;
use std::io::Write;

pub fn scan_path(path: &str, sigs: &[signature::Signature]) {
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            if let Ok(contents) = fs::read_to_string(entry.path()) {
                let matches = signature::match_file(&contents, sigs);
                if !matches.is_empty() {
                    println!("Threats found in {:?}:", entry.path());
                    for m in &matches {
                        println!("   - {}", m);
                    }
                    quarantine_file(entry.path(), &matches);
                }
            }
        }
    }
}

fn log_quarantine_event(original_path: &Path, quarantine_path: &Path, threats: &[String]) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let log_entry = format!("{}: Quarantined {:?} to {:?}. Threats: {:?}\n",
        timestamp, original_path, quarantine_path, threats);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("quarantine.log")
    {
        if let Err(e) = file.write_all(log_entry.as_bytes()) {
            eprintln!("Failed to write to quarantine log: {}", e);
        }
    }
}

pub fn quarantine_file(original_path: &Path, threat_names: &[String]) {
    let filename = original_path.file_name().unwrap_or_default();
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let mut dest = PathBuf::from(crate::utils::QUARANTINE_DIR);
    dest.push(format!("{}_{}", timestamp, filename.to_string_lossy()));

    if let Err(e) = copy(&original_path, &dest) {
        eprintln!("Failed to quarantine {:?} -> {:?}", original_path, dest);
    } else {
        println!("Quarantined {:?} -> {:?}", original_path, dest);
        log_quarantine_event(original_path, &dest, threat_names);
    }
}