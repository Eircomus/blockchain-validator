use clap::Parser;
use sha3::{Digest, Keccak256};
use std::process;

/// Blockchain address validator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The blockchain address to validate
    #[arg(short, long)]
    address: String,

    /// The blockchain type (eth, btc)
    #[arg(short, long, default_value = "eth")]
    blockchain: String,
}

fn main() {
    let args = Args::parse();

    let is_valid = match args.blockchain.as_str() {
        "eth" => validate_eth_address(&args.address),
        "btc" => validate_btc_address(&args.address),
        _ => {
            eprintln!("Unsupported blockchain type: {}", args.blockchain);
            process::exit(1);
        }
    };

    if is_valid {
        println!("✅ Address is valid!");
    } else {
        println!("❌ Invalid address!");
    }
}

fn validate_eth_address(address: &str) -> bool {
    // Basic Ethereum address validation
    
    // Check if it starts with 0x
    if !address.starts_with("0x") {
        return false;
    }
    
    // Check length (0x + 40 hex chars)
    if address.len() != 42 {
        return false;
    }
    
    // Check if it's valid hex
    if let Some(hex_part) = address.strip_prefix("0x") {
        if hex::decode(hex_part).is_err() {
            return false;
        }
        
        // Check checksum for mixed-case addresses
        if hex_part.chars().any(|c| c.is_uppercase()) {
            return validate_eth_checksum(address);
        }
        
        return true;
    }
    
    false
}

fn validate_eth_checksum(address: &str) -> bool {
    // Implementation of EIP-55 checksum validation
    let address = address.strip_prefix("0x").unwrap();
    let address_lower = address.to_lowercase();
    
    // Hash the lowercase address
    let mut hasher = Keccak256::new();
    hasher.update(address_lower.as_bytes());
    let hash = hasher.finalize();
    
    // Check each character against the hash
    address.chars().zip(address_lower.chars()).enumerate().all(|(i, (actual, lower))| {
        if lower.is_digit(16) {
            // If it's a digit, no case to check
            true
        } else {
            // If it's a letter, check if the case matches the hash
            let hash_val = hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 }) & 0xf;
            (hash_val >= 8) == actual.is_uppercase()
        }
    })
} 

fn validate_btc_address(address: &str) -> bool {
    // Basic Bitcoin address validation
    // This is a simplified check - real validation would be more complex
    
    // Check length based on address type
    match address.chars().next() {
        // Legacy address starts with 1
        Some('1') => address.len() == 34 || address.len() == 33,
        // P2SH address starts with 3
        Some('3') => address.len() == 34,
        // Bech32 address starts with bc1
        _ if address.starts_with("bc1") => address.len() >= 42 && address.len() <= 62,
        _ => false,
    }
} 
 /*In this code, we define a  Args  struct using the  clap  crate to parse command-line arguments. The struct has two fields:  address  and  blockchain . The  address  field is the blockchain address to validate, and the  blockchain  field is the blockchain type ( eth  or  btc ). 
 The  main  function parses the command-line arguments using the  Args::parse()  method. It then calls the appropriate validation function based on the blockchain type. If the address is valid, it prints a success message; otherwise, it prints an error message. 
 The  validate_eth_address  function checks if the Ethereum address is valid. It first checks if the address starts with  0x  and has a length of 42 characters. Then, it checks if the address is a valid hexadecimal string. If the address contains uppercase characters, it calls the  validate_eth_checksum  function to validate the checksum. 
 The  validate_eth_checksum  function implements the EIP-55 checksum validation algorithm. It hashes the lowercase address and checks each character against the hash. If the character is a digit, it doesn’t need to check the case. If the character is a letter, it checks if the case matches the hash. 
 The  validate_btc_address  function checks if the Bitcoin address is valid. It checks the length of the address based on the address type (legacy, P2SH, or Bech32). 
 Now, let’s test the program with some sample addresses. 
 Testing the Blockchain Address Validator 
 To test the blockchain address validator, you can run the program with different blockchain addresses. 
 First, compile the program using the following command: 
 cargo build --release 
 This command compiles the program in release mode, which optimizes the binary for performance. 
 Now, you can run the program with different blockchain addresses. Here are some examples: 
 ./target/release/blockchain-validator --address 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2 --blockchain eth
./target/release/blockchain-validator --address 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 --blockchain btc */