use serde::Deserialize;
use regex::Regex;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Signature {
    pub name: String,
    pub pattern: String
}

pub fn load_signatures(path: &str) -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    let sigs: Vec<Signature> = serde_json::from_str(&data)?;
    Ok(sigs)
}

pub fn match_file(contents: &str, sigs: &[Signature]) -> Vec<String> {
    let mut hits = Vec::new();
    for sig in sigs {
        if let Ok(re) = Regex::new(&sig.pattern) {
            if re.is_match(contents) {
                hits.push(sig.name.clone());
            }
        }
    }
    hits
}