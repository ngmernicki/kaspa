use bip39::{Language, Mnemonic};
use hex;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{ExtendedPrivateKey, ExtendedPublicKey, DerivationPath, SecretKey as KaspaSecretKey, PrivateKey, PublicKey as KaspaPublicKey};
// Important: Import the kaspa_bip32's version of secp256k1 for the PublicKey type
use kaspa_bip32::secp256k1::PublicKey as KaspaSecp256k1PublicKey;
use rand::Rng;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::io::{self};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::error::Error as StdError;
use bs58;
use byteorder::{BigEndian, ByteOrder};
use rpassword::read_password;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 0: Determine if we need to sign or verify a signature
    println!("Choose an option:");
    println!("1. Sign a message");
    println!("2. Verify a signature");
    println!("3. Check address against extended public key");
    let mut option = String::new();
    io::stdin().read_line(&mut option)?;
    let option = option.trim();

    match option {
        "1" => sign_message_flow(),
        "2" => verify_signature_flow(),
        "3" => check_address_against_xpub_flow(),
        &_ => {
            println!("Invalid option.");
            Ok(())
        }
    }?;
    println!("Press Enter to exit.");
    let mut exit_message = String::new();
    io::stdin().read_line(&mut exit_message)?;

    Ok(())
}

fn sign_message_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Get or generate mnemonic
    let mnemonic = get_or_generate_mnemonic()?;
    //println!("Using mnemonic: {}", mnemonic);

    // Step 2: Generate seed from mnemonic
    let seed = generate_seed_from_mnemonic(&mnemonic);

    // Step 3: Derive Kaspa private key and address
    let (private_key, address) = derive_kaspa_key_and_address(&seed)?;
    let address_str = address.to_string();
    
    // Step 4: Generate the extended public key (xpub) for address derivation
    let master_key = create_master_key(&seed)?;
    let xpub = create_extended_public_key(&master_key)?;
    println!("Derived Kaspa address: {}", address);
    println!("Derived Extended Public Key: {}", xpub);

    // Step 5: Get message to sign
    println!("Enter message to sign:");
    let mut message = String::new();
    io::stdin().read_line(&mut message)?;
    message = message.trim().to_string();

    // Step 6: Sign the message
    let signature = sign_message(&message, &private_key)?;
    println!("Message: {}", message);
    println!("Signature: {}", signature);

    let is_valid = verify_signature(&message, &signature, &address_str)?;
    println!(
        "Signature verification: {}",
        if is_valid { "Valid" } else { "Invalid" }
    );
    Ok(())
}

fn verify_signature_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Get address
    println!("Enter Kaspa address:");
    let mut address_input = String::new();
    io::stdin().read_line(&mut address_input)?;
    let address_input = address_input.trim();

    // Step 2: Get message to verify
    println!("Enter message to verify:");
    let mut message = String::new();
    io::stdin().read_line(&mut message)?;
    message = message.trim().to_string();

    // Step 3: Get signature to verify
    println!("Enter signature to verify:");
    let mut signature = String::new();
    io::stdin().read_line(&mut signature)?;
    signature = signature.trim().to_string();

    // Step 4: Verify the signature
    let is_valid = verify_signature(&message, &signature, &address_input)?;
    println!(
        "Signature verification: {}",
        if is_valid { "Valid" } else { "Invalid" }
    );
    Ok(())
}

fn check_address_against_xpub_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: get xpub
    println!("Enter extended public key:");
    let mut xpub_input = String::new();
    io::stdin().read_line(&mut xpub_input)?;
    let xpub_input = load_xpub_from_string(xpub_input.trim())?;
    //load_xpub_from_string

    // Step 2: get address to check
    println!("Enter wallet address:");
    let mut address_input = String::new();
    io::stdin().read_line(&mut address_input)?;
    let address_input = address_input.trim();

    // Step 3: determine optimal thread count
    let num_threads = num_cpus::get();
    println!("This will use {} threads.",num_threads);
    let num_derivations = 2_000_000_000;
    // Step 4: // Check if the address belongs to this xpub (searching first 1000000 addresses)
    let start_time = std::time::Instant::now();
    match check_address_belongs_to_xpub_parallel(&xpub_input,address_input,num_derivations,num_threads)? {
        Some(index) => println!("Address found! It's the {}th derived address from this xpub.", index),
        None => println!("Address does not belong to this xpub (within first {} addresses).",num_derivations)
    }
    let duration = start_time.elapsed();
    println!("Search completed in {:.2?}", duration);
    Ok(())
}

type KaspaXPub = ExtendedPublicKey<KaspaSecp256k1PublicKey>;

fn load_xpub_from_string(xpub_str: &str) -> Result<KaspaXPub, Box<dyn std::error::Error>> {
    // First, decode the Base58 encoded string (without checksum, as bs58 crate doesn't have built-in check)
    let decoded = bs58::decode(xpub_str).into_vec()?;
    
    // Check if we have 82 bytes (78 + 4 byte checksum)
    if decoded.len() == 82 {
        // Take only the first 78 bytes, discarding the checksum
        let data = &decoded[0..78];
        
        // Extract the components of the extended key
        let depth = data[4];
        
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&data[5..9]);
        
        let child_number = kaspa_bip32::ChildNumber(u32::from_be_bytes([data[9], data[10], data[11], data[12]]));
        
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);
        
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&data[45..78]);
        
        // Create the public key
        let public_key = KaspaSecp256k1PublicKey::from_slice(&pubkey_bytes)?;
        
        // Create extended key attributes
        let attrs = kaspa_bip32::ExtendedKeyAttrs {
            depth,
            parent_fingerprint: fingerprint,
            child_number,
            chain_code,
        };
        
        // Create the extended public key
        let xpub = ExtendedPublicKey::from_public_key(public_key, &attrs);
        
        return Ok(xpub);
    } else if decoded.len() == 78 {
        // Extract the components of the extended key
        // Format: [4-byte version] [1-byte depth] [4-byte fingerprint] [4-byte child number] [32-byte chain code] [33-byte public key]
    
        // Extract depth (1 byte)
        let depth = decoded[4];
        
        // Extract parent fingerprint (4 bytes)
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&decoded[5..9]);
        
        // Extract child number (4 bytes)
        let child_number = kaspa_bip32::ChildNumber(BigEndian::read_u32(&decoded[9..13]));
        
        // Extract chain code (32 bytes)
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&decoded[13..45]);
        
        // Extract public key (33 bytes)
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&decoded[45..78]);
        
        // Parse the secp256k1 public key using Kaspa's type
        let public_key = KaspaSecp256k1PublicKey::from_slice(&pubkey_bytes)?;
        
        // Use the ExtendedKeyAttrs struct directly instead of going through a namespace
        let attrs = kaspa_bip32::ExtendedKeyAttrs {
            depth,
            parent_fingerprint: fingerprint,
            child_number,
            chain_code,
        };

        // Create the extended public key using from_public_key
        let xpub = ExtendedPublicKey::from_public_key(public_key, &attrs);

        Ok(xpub)
    } else {
        return Err(format!("Invalid extended public key length: got {} bytes, expected 78 or 82", decoded.len()).into());
    }
    
    
}

fn diagnose_xpub_string(xpub_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Diagnosing xpub string: {}", xpub_str);
    println!("Length of string: {}", xpub_str.len());
    
    // Try to decode base58
    let decoded_result = bs58::decode(xpub_str).into_vec();
    match decoded_result {
        Ok(decoded) => {
            println!("Successfully decoded Base58. Decoded length: {} bytes", decoded.len());
            
            if decoded.len() != 78 {
                println!("WARNING: Decoded length should be 78 bytes for standard xpub!");
                
                if decoded.len() < 78 {
                    println!("  Too short: missing {} bytes", 78 - decoded.len());
                } else {
                    println!("  Too long: {} extra bytes", decoded.len() - 78);
                }
            }
            
            // Check version bytes
            if decoded.len() >= 4 {
                let version = &decoded[0..4];
                println!("Version bytes: {:02x} {:02x} {:02x} {:02x}", 
                         version[0], version[1], version[2], version[3]);
                
                // Standard xpub version is 0x0488B21E
                if version == [0x04, 0x88, 0xB2, 0x1E] {
                    println!("Recognized as standard BIP32 xpub version");
                } else {
                    println!("WARNING: Unrecognized version. Expected 0x0488B21E for standard xpub");
                }
            }
            
            // Print other parts if complete
            if decoded.len() >= 78 {
                println!("Depth: {}", decoded[4]);
                println!("Parent fingerprint: {:02x}{:02x}{:02x}{:02x}", 
                         decoded[5], decoded[6], decoded[7], decoded[8]);
                
                // Check if public key starts with 0x02 or 0x03 (compressed format)
                if decoded[45] == 0x02 || decoded[45] == 0x03 {
                    println!("Public key appears to be in correct compressed format");
                } else {
                    println!("WARNING: Public key doesn't start with 0x02 or 0x03: {:02x}", decoded[45]);
                }
            }
            
            println!("Full decoded data (hex):");
            for i in 0..decoded.len() {
                print!("{:02x}", decoded[i]);
                if (i + 1) % 16 == 0 { println!(); }
            }
            println!();
        },
        Err(e) => {
            println!("Failed to decode Base58: {}", e);
            println!("This might not be a valid Base58-encoded string");
        }
    }
    
    Ok(())
}

#[allow(dead_code)]
fn load_xpub_from_string_improved(xpub_str: &str) -> Result<ExtendedPublicKey<KaspaSecp256k1PublicKey>, Box<dyn std::error::Error>> {
    // Normalize the string (trim whitespace, etc.)
    let xpub_str = xpub_str.trim();
    
    // First, decode the Base58 encoded string
    let decoded = match bs58::decode(xpub_str).into_vec() {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to decode Base58 string: {}", e).into()),
    };
    
    if decoded.len() != 78 {
        // Run diagnostics automatically
        println!("Running diagnostics on problematic xpub...");
        let _ = diagnose_xpub_string(xpub_str);
        
        return Err(format!("Invalid extended public key length: got {} bytes, expected 78", decoded.len()).into());
    }
    
    // Extract the components of the extended key
    // Format: [4-byte version] [1-byte depth] [4-byte fingerprint] [4-byte child number] [32-byte chain code] [33-byte public key]
    
    // Extract depth (1 byte)
    let depth = decoded[4];
    
    // Extract parent fingerprint (4 bytes)
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&decoded[5..9]);
    
    // Extract child number (4 bytes)
    //kaspa_bip32::ChildNumber(BigEndian::read_u32(&decoded[9..13]));
    let child_number = kaspa_bip32::ChildNumber(u32::from_be_bytes([decoded[9], decoded[10], decoded[11], decoded[12]]));
    
    // Extract chain code (32 bytes)
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&decoded[13..45]);
    
    // Extract public key (33 bytes)
    let mut pubkey_bytes = [0u8; 33];
    pubkey_bytes.copy_from_slice(&decoded[45..78]);
    
    // Verify public key format
    if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 {
        return Err(format!("Invalid public key format: first byte is {:02x}, expected 0x02 or 0x03", pubkey_bytes[0]).into());
    }
    
    // Parse the secp256k1 public key using Kaspa's type
    let public_key = match KaspaSecp256k1PublicKey::from_slice(&pubkey_bytes) {
        Ok(key) => key,
        Err(e) => return Err(format!("Failed to parse public key: {}", e).into()),
    };
    
    // Create the extended key attributes
    let attrs = kaspa_bip32::ExtendedKeyAttrs {
        depth,
        parent_fingerprint: fingerprint,
        child_number,
        chain_code,
    };
    
    // Create the extended public key using from_public_key
    let xpub = ExtendedPublicKey::from_public_key(public_key, &attrs);
    
    Ok(xpub)
}

// Modified to use KaspaPublicKey instead of secp256k1::PublicKey
fn create_extended_public_key(master_key: &ExtendedPrivateKey<KaspaSecretKey>) -> Result<ExtendedPublicKey<KaspaSecp256k1PublicKey>, Box<dyn std::error::Error>> {
    // Create a context for Secp256k1 operations
    let secp = Secp256k1::new();
    
    // Derive the account path first (m/44'/111111'/0')
    let account_path = DerivationPath::from_str("m/44'/111111'/0'")?;
    let master_key_owned = master_key.clone();
    let account_key = master_key_owned.derive_path(&account_path)?;
    
    // Get the private key bytes
    let priv_key_bytes = account_key.private_key().to_bytes();
    
    // Create secp256k1's secret key from the private key bytes
    let secret_key = secp256k1::SecretKey::from_slice(&priv_key_bytes)?;
    
    // Create secp256k1's public key from the secret key
    let secp_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    
    // Convert secp256k1::PublicKey to KaspaSecp256k1PublicKey
    // They use the same serialization format, so we can serialize and deserialize
    let pubkey_bytes = secp_pubkey.serialize();
    let kaspa_pubkey = KaspaSecp256k1PublicKey::from_slice(&pubkey_bytes)?;
    
    // Create the extended public key from the account key attributes
    let attrs = account_key.attrs().clone();
    let xpub = ExtendedPublicKey::from_public_key(kaspa_pubkey, &attrs);
    
    Ok(xpub)
}



fn create_master_key(seed: &[u8]) -> Result<ExtendedPrivateKey<KaspaSecretKey>, Box<dyn std::error::Error>> {
    // Generate master key from seed
    let master_key = ExtendedPrivateKey::<KaspaSecretKey>::new(seed)?;
    Ok(master_key)
}

fn get_or_generate_mnemonic() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    println!("Enter your 12-word mnemonic phrase (or leave empty to generate a new one):");
    let input = read_password()?;
    //let mut input = String::new();
    //io::stdin().read_line(&mut input)?;

    let mnemonic = if input.trim().is_empty() {
        // Instead of trying to use RngCore directly, let's create entropy manually
        // Generate 16 bytes of entropy (128 bits) for a 12-word mnemonic
        let mut entropy = [0u8; 16];

        // Fill with random bytes using the rand crate
        let mut thread_rng = rand::thread_rng();
        for byte in entropy.iter_mut() {
            *byte = thread_rng.r#gen();
        }

        // Create mnemonic from entropy directly without using generate_in_with
        Mnemonic::from_entropy_in(Language::English, &entropy)?
    } else {
        // Parse existing mnemonic
        Mnemonic::parse_in(Language::English, input.trim())?
    };

    Ok(mnemonic)
}

fn generate_seed_from_mnemonic(mnemonic: &Mnemonic) -> Vec<u8> {
    // For BIP39, we typically use an empty passphrase
    let passphrase = "";
    let seed_array = mnemonic.to_seed(passphrase);
    seed_array.to_vec() // Convert [u8; 64] to Vec<u8>
}
// Wrapper for thread errors
#[derive(Debug)]
struct ThreadError(String);

impl std::fmt::Display for ThreadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Thread error: {}", self.0)
    }
}

impl StdError for ThreadError {}

impl From<kaspa_bip32::Error> for ThreadError {
    fn from(err: kaspa_bip32::Error) -> Self {
        ThreadError(err.to_string())
    }
}

impl From<&str> for ThreadError {
    fn from(s: &str) -> Self {
        ThreadError(s.to_string())
    }
}

// Updated to use the correct PublicKey type
fn check_address_belongs_to_xpub_parallel(
    xpub: &ExtendedPublicKey<KaspaSecp256k1PublicKey>,
    address_to_check: &str,
    search_limit: u32,
    num_threads: usize
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    // Parse the address to check
    let address_to_check = Address::constructor(address_to_check);
    let address_to_check_str = address_to_check.to_string();
    
    // Derive the change path first (external chain is 0)
    let change_path = DerivationPath::from_str("m/0")?;
    let change_xpub = xpub.clone().derive_path(&change_path)?;
    
    // Share the xpub and result across threads
    let change_xpub = Arc::new(change_xpub);
    let found_index = Arc::new(Mutex::new(None));
    let should_exit = Arc::new(Mutex::new(false));
    
    // Create thread handles
    let mut handles = vec![];
    
    // Calculate chunk size for each thread
    let chunk_size = (search_limit as usize + num_threads - 1) / num_threads;
    
    // Spawn threads
    for thread_id in 0..num_threads {
        // Calculate range for this thread
        let start = thread_id as u32 * chunk_size as u32;
        let end = std::cmp::min(start + chunk_size as u32, search_limit);
        
        // Skip if we're already past the search limit
        if start >= search_limit {
            continue;
        }
        
        // Clone Arc references for this thread
        let change_xpub = Arc::clone(&change_xpub);
        let found_index = Arc::clone(&found_index);
        let should_exit = Arc::clone(&should_exit);
        let address_to_check_str = address_to_check_str.clone();
        
        // Spawn the thread
        let handle = thread::spawn(move || -> Result<(), ThreadError> {
            // Check if we should exit early
            if *should_exit.lock().unwrap() {
                return Ok(());
            }
            
            // Process this thread's range
            for i in start..end {
                // Check if another thread found the address
                if *should_exit.lock().unwrap() {
                    break;
                }
                
                // Derive the i-th child
                let index_path = DerivationPath::from_str(&format!("m/{}", i))?;
                let child_xpub = <ExtendedPublicKey<kaspa_bip32::secp256k1::PublicKey> as Clone>::clone(&change_xpub).derive_path(&index_path)?;
                
                // Get the public key
                let public_key = child_xpub.public_key();
                
                // Extract the X coordinate from the compressed public key
                let pubkey_bytes = public_key.serialize();
                let x_only_pubkey = match pubkey_bytes[0] {
                    0x02 | 0x03 => &pubkey_bytes[1..33], // Take 32 bytes after the prefix byte
                    _ => return Err("Unexpected public key format".into()),
                };
                
                // Create the Kaspa address
                let derived_address = Address::new(Prefix::Mainnet, Version::PubKey, x_only_pubkey);
                 
                //println!("Derived Address: {}, Index Path: {}",derived_address,index_path);
                
                // Check if this address matches the one we're looking for
                if derived_address.to_string() == address_to_check_str {
                    // Address found, update the shared result
                    let mut found = found_index.lock().unwrap();
                    *found = Some(i);
                    
                    // Signal other threads to exit
                    let mut exit = should_exit.lock().unwrap();
                    *exit = true;
                    
                    break;
                }
            }
            
            Ok(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        match handle.join() {
            Ok(result) => {
                if let Err(e) = result {
                    return Err(Box::new(ThreadError(format!("Thread error: {}", e))));
                }
            }
            Err(_) => {
                return Err("Thread panicked".into());
            }
        }
    }
    
    // Return the result
    Ok(*found_index.lock().unwrap())
}

fn derive_kaspa_key_and_address(
    seed: &[u8],
) -> Result<(SecretKey, Address), Box<dyn std::error::Error>> {
    // Create a context for Secp256k1 operations
    let secp = Secp256k1::new();

    // Use BIP44 derivation path for Kaspa:
    // m/44'/111111'/0'/0/0 (Kaspa uses 111111 as its coin type)
    let path_str = "m/44'/111111'/0'/0/0";
    let path = DerivationPath::from_str(path_str)?;

    // Generate master key from seed using KaspaSecretKey
    let master_key = ExtendedPrivateKey::<KaspaSecretKey>::new(seed)?;

    // Derive child key at the specified path
    let child_key = master_key.derive_path(&path)?;

    // Get the kaspa private key bytes - use to_bytes()
    let kaspa_priv_key = child_key.private_key();
    let kaspa_priv_key_bytes = kaspa_priv_key.to_bytes();

    // Convert to secp256k1 SecretKey for signing
    let private_key = SecretKey::from_slice(&kaspa_priv_key_bytes)?;

    // Generate public key from the private key
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    // Generate Kaspa address (mainnet)
    // By default serialize() gives 33-byte compressed format, but we need 32-byte X coordinate only
    // Extract just the X coordinate (last 32 bytes of the 33-byte compressed key)
    let pubkey_bytes = public_key.serialize();
    let x_only_pubkey = match pubkey_bytes[0] {
        0x02 | 0x03 => &pubkey_bytes[1..33], // Take 32 bytes after the prefix byte
        _ => panic!("Unexpected public key format"),
    };

    let address = Address::new(Prefix::Mainnet, Version::PubKey, x_only_pubkey);

    Ok((private_key, address))
}

fn sign_message(
    message: &str,
    private_key: &SecretKey,
) -> Result<String, Box<dyn std::error::Error>> {
    // Create a context for Secp256k1 operations
    let secp = Secp256k1::new();

    // Hash the message (Kaspa typically uses double SHA256)
    let message_hash = double_sha256(message);

    // Create a secp256k1 message object from the hash
    let secp_message = Message::from_slice(&message_hash)?;

    // Sign the message
    let signature = secp.sign_ecdsa(&secp_message, private_key);

    // Return the signature as a hex string
    Ok(hex::encode(signature.serialize_compact()))
}

fn verify_signature(
    message: &str,
    signature_hex: &str,
    address: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Step 1: Parse the Kaspa address
    let kaspa_address = Address::constructor(address);

    // Step 2: Extract the public key data from the address
    // Kaspa address contains the X coordinate of the public key
    let pubkey_data = &kaspa_address.payload;

    // Step 3: Create a context for Secp256k1 operations
    let secp = Secp256k1::new();

    // Hash the message
    let message_hash = double_sha256(message);

    // Create a secp256k1 message object from the hash
    let secp_message = Message::from_slice(&message_hash)?;

    // Parse the signature from hex
    let signature_bytes = hex::decode(signature_hex)?;
    let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)?;

    // We need to reconstruct the full public key from just the X coordinate
    // This requires trying both possible Y coordinates (even and odd)

    // Try with even Y coordinate (02 prefix)
    let mut even_pubkey_bytes = vec![0x02];
    even_pubkey_bytes.extend_from_slice(pubkey_data);

    // Try with odd Y coordinate (03 prefix)
    let mut odd_pubkey_bytes = vec![0x03];
    odd_pubkey_bytes.extend_from_slice(pubkey_data);

    // Try to parse both possible public keys
    let even_pubkey_result = secp256k1::PublicKey::from_slice(&even_pubkey_bytes);
    let odd_pubkey_result = secp256k1::PublicKey::from_slice(&odd_pubkey_bytes);

    // Try verification with both possible public keys
    match (even_pubkey_result, odd_pubkey_result) {
        (Ok(even_pubkey), _) => {
            if secp
                .verify_ecdsa(&secp_message, &signature, &even_pubkey)
                .is_ok()
            {
                return Ok(true);
            }
        }
        (_, Ok(odd_pubkey)) => {
            if secp
                .verify_ecdsa(&secp_message, &signature, &odd_pubkey)
                .is_ok()
            {
                return Ok(true);
            }
        }
        _ => {}
    }

    // If we reach here, neither key verified the signature
    Ok(false)
}

fn double_sha256(data: &str) -> [u8; 32] {
    let mut hasher1 = Sha256::new();
    hasher1.update(data.as_bytes());
    let first_hash = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(first_hash);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hasher2.finalize());
    output
}
