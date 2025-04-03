use clap::Parser;
use regex::Regex;
use sha3::{Digest, Keccak256};
use std::process;

// Blockchain address validator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // The blockchain address to validate
    #[arg(short, long)]
    address: String,

    // The blockchain type (eth, btc, sol)
    #[arg(short, long, default_value = "eth")]
    blockchain: String,

    // Optional: Enable verbose output
    #[arg(short, long, action)]
    verbose: bool,
}

#[derive(Debug)]
struct ValidationResult {
    valid: bool,
    details: Vec<(String, String)>,
}

impl ValidationResult {
    fn new() -> Self {
        Self {
            valid: true,
            details: Vec::new(),
        }
    }

    fn add_check(&mut self, check: &str, result: bool, message: String) {
        self.valid = self.valid && result;
        self.details.push((check.to_string(), message));
    }
}

fn main() {
    let args = parse_input();
    let validation_result = validate_address(&args);
    display_results(&validation_result, args.verbose);
}

fn parse_input() -> Args {
    Args::parse()
}

fn validate_address(args: &Args) -> ValidationResult {
    match args.blockchain.as_str() {
        "eth" => validate_eth_address(&args.address),
        "btc" => validate_btc_address(&args.address),
        "sol" => validate_sol_address(&args.address),
        _ => {
            eprintln!("Unsupported blockchain type: {}", args.blockchain);
            process::exit(1);
        }
    }
}

fn display_results(result: &ValidationResult, verbose: bool) {
    if result.valid {
        println!("✅ Address is valid!");
    } else {
        println!("❌ Invalid address!");
    }

    if verbose {
        println!("\nValidation details:");
        for (check, result) in &result.details {
            println!("- {}: {}", check, result);
        }
    }
}

fn validate_eth_address(address: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check if it starts with 0x
    let starts_with_0x = address.starts_with("0x");
    result.add_check(
        "Starts with 0x",
        starts_with_0x,
        format!("{}", starts_with_0x),
    );

    // Check length (0x + 40 hex chars)
    let correct_length = address.len() == 42;
    result.add_check(
        "Length (42 chars)",
        correct_length,
        format!("{} (actual: {})", correct_length, address.len()),
    );

    // Check if it's valid hex
    if let Some(hex_part) = address.strip_prefix("0x") {
        let is_valid_hex = hex::decode(hex_part).is_ok();
        result.add_check(
            "Valid hex characters",
            is_valid_hex,
            format!("{}", is_valid_hex),
        );

        // Check checksum for mixed-case addresses
        if hex_part.chars().any(|c| c.is_uppercase()) {
            let checksum_valid = validate_eth_checksum(address);
            result.add_check(
                "EIP-55 checksum",
                checksum_valid,
                format!("{}", checksum_valid),
            );
        } else {
            result.add_check(
                "EIP-55 checksum",
                true,
                "skipped (all lowercase)".to_string(),
            );
        }
    }

    result
}

fn validate_eth_checksum(address: &str) -> bool {
    let address = address.strip_prefix("0x").unwrap();
    let address_lower = address.to_lowercase();
    
    let mut hasher = Keccak256::new();
    hasher.update(address_lower.as_bytes());
    let hash = hasher.finalize();
    
    address.chars().zip(address_lower.chars()).enumerate().all(|(i, (actual, lower))| {
        if lower.is_digit(16) {
            true
        } else {
            let hash_val = hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 }) & 0xf;
            (hash_val >= 8) == actual.is_uppercase()
        }
    })
}

fn validate_btc_address(address: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    let first_char = address.chars().next();
    let is_legacy = first_char == Some('1');
    let is_p2sh = first_char == Some('3');
    let is_bech32 = address.starts_with("bc1");

    result.add_check(
        "Address type",
        is_legacy || is_p2sh || is_bech32,
        format!(
            "{}",
            if is_legacy {
                "Legacy (starts with 1)"
            } else if is_p2sh {
                "P2SH (starts with 3)"
            } else if is_bech32 {
                "Bech32 (starts with bc1)"
            } else {
                "Unknown"
            }
        ),
    );

    let length_ok = if is_legacy {
        address.len() == 34 || address.len() == 33
    } else if is_p2sh {
        address.len() == 34
    } else if is_bech32 {
        address.len() >= 42 && address.len() <= 62
    } else {
        false
    };

    result.add_check(
        "Length",
        length_ok,
        format!("{} (actual: {})", length_ok, address.len()),
    );

    if is_legacy || is_p2sh {
        let re = Regex::new(r"^[1-9A-HJ-NP-Za-km-z]+$").unwrap();
        let is_base58 = re.is_match(address);
        result.add_check(
            "Base58 characters",
            is_base58,
            format!("{}", is_base58),
        );
    }

    result
}

fn validate_sol_address(address: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Length check
    let length_ok = (32..=44).contains(&address.len());
    result.add_check(
        "Length (32-44 chars)",
        length_ok,
        format!("{} (actual: {})", length_ok, address.len()),
    );

    // Base58 pattern check
    let re = Regex::new(r"^[1-9A-HJ-NP-Za-km-z]+$").unwrap();
    let is_base58 = re.is_match(address);
    result.add_check(
        "Base58 characters",
        is_base58,
        format!("{}", is_base58),
    );

    // First character check
    let first_char_ok = address.starts_with(|c: char| ('1'..='5').contains(&c));
    result.add_check(
        "First character (1-5)",
        first_char_ok,
        format!(
            "{} (actual: {})",
            first_char_ok,
            address.chars().next().unwrap_or(' ')
        ),
    );

    // Base58 decoding check
    if result.valid {
        let decode_result = bs58::decode(address).into_vec();
        let is_valid_encoding = decode_result.is_ok();
        let is_correct_length = decode_result.as_ref().map_or(false, |v| v.len() == 32);
        
        result.add_check(
            "Base58 decoding",
            is_valid_encoding,
            format!("{}", is_valid_encoding),
        );
        
        if is_valid_encoding {
            result.add_check(
                "Decoded length (32 bytes)",
                is_correct_length,
                format!(
                    "{} (actual: {})",
                    is_correct_length,
                    decode_result.unwrap().len()
                ),
            );
        }
    }

    result
}

 /* Now, you can run the program with different blockchain addresses. Here are some examples: 
 ./target/release/blockchain-validator --address 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2 --blockchain eth
./target/release/blockchain-validator --address 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 --blockchain btc */