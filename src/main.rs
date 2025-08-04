mod scanner;
mod signature;
mod utils;

use clap::Parser;

#[derive(Parser)]
#[command(name = "RustyScanner")]
#[command(about = "A basic virus scanner made in Rust")]

struct Cli {
    path: String,
    #[arg(short, long)]
    signatures: String
}


fn main() {
    let cli = Cli::parse();
    
    let sigs = signature::load_signatures(&cli.signatures).expect("Failed to load signatures");
    
    scanner::scan_path(&cli.path, &sigs);
}
