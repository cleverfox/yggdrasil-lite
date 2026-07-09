//! Generate deterministic test keys for e2e tests.
//!
//! Creates Ed25519 keypairs such that lite_node's public key is LOWER than
//! both yggstack public keys (byte comparison). This ensures deterministic
//! tree root selection, avoiding bloom filter convergence delay.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example gen_test_keys -p yggdrasil-lite
//! ```
//!
//! # Output files
//!
//! - `tests/keys/lite_node.seed`  — 32-byte Ed25519 seed (64 hex chars)
//! - `tests/keys/yggstack.key`    — 64-byte Ed25519 keypair (128 hex chars)
//! - `tests/keys/yggstack2.key`   — second keypair for e2e_multi.sh

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::Path;
use yggdrasil_lite::address::addr_for_key;

fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let keys_dir = crate_dir.join("tests/keys");
    let lite_seed_path = keys_dir.join("lite_node.seed");
    let yggstack_key_path = keys_dir.join("yggstack.key");
    let yggstack2_key_path = keys_dir.join("yggstack2.key");

    fs::create_dir_all(&keys_dir).expect("create keys dir");

    // Generate the lite_node/yggstack pair if either is missing.
    if !lite_seed_path.exists() || !yggstack_key_path.exists() {
        eprintln!("Generating test keys (lite_node pub < yggstack pub)...");

        let key_a = random_signing_key();
        let key_b = random_signing_key();

        // Assign: lite_node gets LOWER pub key, yggstack gets HIGHER
        // (yggstack as root avoids bloom filter convergence delay)
        let (lite_key, ygg_key) =
            if key_a.verifying_key().to_bytes() < key_b.verifying_key().to_bytes() {
                (key_a, key_b)
            } else {
                (key_b, key_a)
            };

        // Save lite_node seed (32 bytes → 64 hex chars)
        let lite_seed_hex = hex::encode(lite_key.to_bytes());
        fs::write(&lite_seed_path, &lite_seed_hex).expect("write lite_node.seed");

        // Save yggstack keypair (64 bytes → 128 hex chars)
        let ygg_key_hex = hex::encode(ygg_key.to_keypair_bytes());
        fs::write(&yggstack_key_path, &ygg_key_hex).expect("write yggstack.key");
    }

    let lite_pub = load_lite_pub(&lite_seed_path);

    // Generate the second yggstack key (for e2e_multi.sh) if missing,
    // also with a pub key higher than lite_node's.
    if !yggstack2_key_path.exists() {
        eprintln!("Generating yggstack2 key (pub > lite_node pub)...");
        let ygg2_key = loop {
            let k = random_signing_key();
            if k.verifying_key().to_bytes() > lite_pub {
                break k;
            }
        };
        let ygg2_key_hex = hex::encode(ygg2_key.to_keypair_bytes());
        fs::write(&yggstack2_key_path, &ygg2_key_hex).expect("write yggstack2.key");
    }

    eprintln!("Keys in {}:", keys_dir.display());
    print_key("lite_node", &lite_pub);
    print_key("yggstack ", &load_ygg_pub(&yggstack_key_path));
    print_key("yggstack2", &load_ygg_pub(&yggstack2_key_path));
}

fn load_lite_pub(path: &Path) -> [u8; 32] {
    let hex_str = fs::read_to_string(path).unwrap().trim().to_string();
    let seed: [u8; 32] = hex::decode(&hex_str).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn load_ygg_pub(path: &Path) -> [u8; 32] {
    let hex_str = fs::read_to_string(path).unwrap().trim().to_string();
    let keypair: [u8; 64] = hex::decode(&hex_str).unwrap().try_into().unwrap();
    SigningKey::from_keypair_bytes(&keypair)
        .unwrap()
        .verifying_key()
        .to_bytes()
}

fn print_key(name: &str, pub_key: &[u8; 32]) {
    let addr = addr_for_key(pub_key);
    eprintln!(
        "  {} pub: {}...  IPv6: {}",
        name,
        &hex::encode(pub_key)[..16],
        std::net::Ipv6Addr::from(addr.0)
    );
}
