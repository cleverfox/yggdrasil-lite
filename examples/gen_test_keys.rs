//! Generate deterministic test keys for e2e tests.
//!
//! Creates two Ed25519 keypairs such that lite_node's public key is
//! LOWER than yggstack's public key (byte comparison). This ensures
//! yggstack is the tree root, avoiding bloom filter convergence delay.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example gen_test_keys -p yggdrasil-lite
//! ```
//!
//! # Output files
//!
//! - `tests/keys/lite_node.seed` — 32-byte Ed25519 seed (64 hex chars)
//! - `tests/keys/yggstack.key`  — 64-byte Ed25519 keypair (128 hex chars)

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::Path;
use yggdrasil_lite::address::addr_for_key;

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let keys_dir = crate_dir.join("tests/keys");
    let lite_seed_path = keys_dir.join("lite_node.seed");
    let yggstack_key_path = keys_dir.join("yggstack.key");

    // If keys already exist, just print info and exit
    if lite_seed_path.exists() && yggstack_key_path.exists() {
        eprintln!("Keys already exist at {}", keys_dir.display());
        print_key_info(&lite_seed_path, &yggstack_key_path);
        return;
    }

    fs::create_dir_all(&keys_dir).expect("create keys dir");

    eprintln!("Generating test keys (lite_node pub < yggstack pub)...");

    // Generate two random seeds and create keypairs
    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];
    OsRng.fill_bytes(&mut seed_a);
    OsRng.fill_bytes(&mut seed_b);

    let key_a = SigningKey::from_bytes(&seed_a);
    let key_b = SigningKey::from_bytes(&seed_b);

    let pub_a = key_a.verifying_key().to_bytes();
    let pub_b = key_b.verifying_key().to_bytes();

    // Assign: lite_node gets LOWER pub key, yggstack gets HIGHER
    // (yggstack as root avoids bloom filter convergence delay)
    let (lite_key, ygg_key) = if pub_a < pub_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    let lite_pub: [u8; 32] = lite_key.verifying_key().to_bytes();
    let ygg_pub: [u8; 32] = ygg_key.verifying_key().to_bytes();

    // Save lite_node seed (32 bytes → 64 hex chars)
    let lite_seed_hex = hex::encode(lite_key.to_bytes());
    fs::write(&lite_seed_path, &lite_seed_hex).expect("write lite_node.seed");

    // Save yggstack keypair (64 bytes → 128 hex chars)
    let ygg_key_hex = hex::encode(ygg_key.to_keypair_bytes());
    fs::write(&yggstack_key_path, &ygg_key_hex).expect("write yggstack.key");

    let lite_addr = addr_for_key(&lite_pub);
    let ygg_addr = addr_for_key(&ygg_pub);

    eprintln!("Generated keys:");
    eprintln!("  lite_node pub: {}...", &hex::encode(lite_pub)[..16]);
    eprintln!("  lite_node IPv6: {}", format_ipv6(&lite_addr.0));
    eprintln!("  yggstack  pub: {}...", &hex::encode(ygg_pub)[..16]);
    eprintln!("  yggstack  IPv6: {}", format_ipv6(&ygg_addr.0));
    eprintln!("  lite > ygg:    {}", lite_pub > ygg_pub);
    eprintln!("  Saved to {}", keys_dir.display());
}

fn print_key_info(lite_seed_path: &Path, yggstack_key_path: &Path) {
    let lite_seed_hex = fs::read_to_string(lite_seed_path)
        .unwrap()
        .trim()
        .to_string();
    let yggstack_key_hex = fs::read_to_string(yggstack_key_path)
        .unwrap()
        .trim()
        .to_string();

    let lite_seed_bytes = hex::decode(&lite_seed_hex).unwrap();
    let lite_seed: [u8; 32] = lite_seed_bytes.try_into().unwrap();
    let lite_signing = SigningKey::from_bytes(&lite_seed);
    let lite_pub = lite_signing.verifying_key().to_bytes();

    let ygg_key_bytes = hex::decode(&yggstack_key_hex).unwrap();
    let ygg_key: [u8; 64] = ygg_key_bytes.try_into().unwrap();
    let ygg_signing = SigningKey::from_keypair_bytes(&ygg_key).unwrap();
    let ygg_pub = ygg_signing.verifying_key().to_bytes();

    let lite_addr = addr_for_key(&lite_pub);
    let ygg_addr = addr_for_key(&ygg_pub);

    eprintln!("  lite_node pub: {}...", &hex::encode(lite_pub)[..16]);
    eprintln!("  lite_node IPv6: {}", format_ipv6(&lite_addr.0));
    eprintln!("  yggstack  pub: {}...", &hex::encode(ygg_pub)[..16]);
    eprintln!("  yggstack  IPv6: {}", format_ipv6(&ygg_addr.0));
    eprintln!("  lite > ygg:    {}", lite_pub > ygg_pub);
}

fn format_ipv6(addr: &[u8; 16]) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from(*addr)
}
