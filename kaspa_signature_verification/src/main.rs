use bip39::{Language, Mnemonic};
use hex;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, PrivateKey, SecretKey as KaspaSecretKey};
use rand::Rng;
use rand::rngs::ThreadRng;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::io::{self};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 0: Determine if we need to sign or verify a signature
    println!("Choose an option:");
    println!("1. Sign a message");
    println!("2. Verify a signature");
    let mut option = String::new();
    io::stdin().read_line(&mut option)?;
    let option = option.trim();

    match option {
        "1" => sign_message_flow(),
        "2" => verify_signature_flow(),
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

fn sign_message_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Get or generate mnemonic
    let mnemonic = get_or_generate_mnemonic()?;
    println!("Using mnemonic: {}", mnemonic);

    // Step 2: Generate seed from mnemonic
    let seed = generate_seed_from_mnemonic(&mnemonic);

    // Step 3: Derive Kaspa private key and address
    let (private_key, address) = derive_kaspa_key_and_address(&seed)?;
    let address_str = address.to_string();
    println!("Derived Kaspa address: {}", address);

    // Step 4: Get message to sign
    println!("Enter message to sign:");
    let mut message = String::new();
    io::stdin().read_line(&mut message)?;
    message = message.trim().to_string();

    // Step 5: Sign the message
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

fn get_or_generate_mnemonic() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    println!("Enter your 12-word mnemonic phrase (or leave empty to generate a new one):");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

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
