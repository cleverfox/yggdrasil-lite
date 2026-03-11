//! Cryptographic primitives for yggdrasil-lite.
//!
//! - Ed25519 signing and verification
//! - Ed25519 <-> Curve25519 key conversion
//! - XSalsa20-Poly1305 authenticated encryption (NaCl box)
//! - Nonce construction from u64 counters
//!
//! Adapted from ironwood/src/crypto.rs and ironwood/src/encrypted/crypto.rs for no_std.

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use crypto_box::aead::{Aead, generic_array::GenericArray};
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, SalsaBox};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

/// Fixed-size public key.
pub type PublicKey = [u8; PUBLIC_KEY_SIZE];

/// Fixed-size signature.
pub type Sig = [u8; SIGNATURE_SIZE];

/// XSalsa20-Poly1305 overhead (Poly1305 authentication tag).
pub const BOX_OVERHEAD: usize = 16;

/// XSalsa20-Poly1305 nonce size (24 bytes).
pub const BOX_NONCE_SIZE: usize = 24;

/// Curve25519 public key (32 bytes).
pub type CurvePublicKey = [u8; 32];

/// Curve25519 private key (32 bytes).
pub type CurvePrivateKey = [u8; 32];

// ---------------------------------------------------------------------------
// Ed25519 operations
// ---------------------------------------------------------------------------

/// Cryptographic identity: holds signing key and derived public key.
pub struct Crypto {
    pub signing_key: SigningKey,
    pub public_key: PublicKey,
}

impl Crypto {
    pub fn new(signing_key: SigningKey) -> Self {
        let public_key: PublicKey = signing_key.verifying_key().to_bytes();
        Self { signing_key, public_key }
    }

    /// Sign a message with our private key.
    pub fn sign(&self, message: &[u8]) -> Sig {
        let sig = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// Verify a signature from the given public key.
    pub fn verify(key: &PublicKey, message: &[u8], sig: &Sig) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        verifying_key.verify(message, &signature).is_ok()
    }

    /// Sign a message with an arbitrary signing key.
    pub fn sign_with_key(key: &SigningKey, message: &[u8]) -> Sig {
        let sig = key.sign(message);
        sig.to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Ed25519 <-> Curve25519 conversion
// ---------------------------------------------------------------------------

/// Convert an Ed25519 private key (seed) to a Curve25519 private key.
///
/// Matches Go's `e2c.Ed25519PrivateKeyToCurve25519`.
pub fn ed25519_private_to_curve25519(signing_key: &SigningKey) -> CurvePrivateKey {
    let seed = signing_key.to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}

/// Convert an Ed25519 public key to a Curve25519 (Montgomery) public key.
///
/// Uses the bilinear map: u = (1 + y) / (1 - y) mod p.
/// Matches Go's `e2c.Ed25519PublicKeyToCurve25519`.
pub fn ed25519_public_to_curve25519(ed_pub: &PublicKey) -> Result<CurvePublicKey, ()> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards_point = compressed.decompress().ok_or(())?;
    let montgomery = edwards_point.to_montgomery();
    Ok(montgomery.0)
}

// ---------------------------------------------------------------------------
// XSalsa20-Poly1305 encryption (crypto_box crate)
// ---------------------------------------------------------------------------

/// Generate a new random Curve25519 keypair.
pub fn new_box_keys(rng: &mut impl rand_core::CryptoRngCore) -> (CurvePublicKey, CurvePrivateKey) {
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let secret = BoxSecretKey::from(key_bytes);
    let public = secret.public_key();
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_bytes());
    let priv_bytes = secret.to_bytes();
    (pub_bytes, priv_bytes)
}

/// Encrypt a message using XSalsa20-Poly1305.
pub fn box_seal(
    msg: &[u8],
    nonce: u64,
    their_pub: &CurvePublicKey,
    our_priv: &CurvePrivateKey,
) -> Result<Vec<u8>, ()> {
    let salsa_box = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.encrypt(nonce_ga, msg).map_err(|_| ())
}

/// Decrypt a message using XSalsa20-Poly1305.
pub fn box_open(
    ciphertext: &[u8],
    nonce: u64,
    their_pub: &CurvePublicKey,
    our_priv: &CurvePrivateKey,
) -> Result<Vec<u8>, ()> {
    let salsa_box = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.decrypt(nonce_ga, ciphertext).map_err(|_| ())
}

/// Encrypt with a precomputed shared secret.
pub fn box_seal_precomputed(
    msg: &[u8],
    nonce: u64,
    salsa_box: &SalsaBox,
) -> Result<Vec<u8>, ()> {
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.encrypt(nonce_ga, msg).map_err(|_| ())
}

/// Decrypt with a precomputed shared secret.
pub fn box_open_precomputed(
    ciphertext: &[u8],
    nonce: u64,
    salsa_box: &SalsaBox,
) -> Result<Vec<u8>, ()> {
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.decrypt(nonce_ga, ciphertext).map_err(|_| ())
}

/// Create a SalsaBox (precomputed shared secret) from keys.
pub fn make_salsa_box(their_pub: &CurvePublicKey, our_priv: &CurvePrivateKey) -> SalsaBox {
    let pk = BoxPublicKey::from(*their_pub);
    let sk = BoxSecretKey::from(*our_priv);
    SalsaBox::new(&pk, &sk)
}

/// Convert a u64 counter to a 24-byte XSalsa20 nonce.
///
/// Format: 16 zero bytes followed by 8 bytes big-endian u64.
/// Matches Go's `nonceForUint64`.
pub fn nonce_for_u64(value: u64) -> [u8; BOX_NONCE_SIZE] {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    nonce[16..24].copy_from_slice(&value.to_be_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn gen_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn sign_and_verify() {
        let crypto = Crypto::new(gen_signing_key());
        let message = b"hello yggdrasil-lite";
        let sig = crypto.sign(message);
        assert!(Crypto::verify(&crypto.public_key, message, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let crypto = Crypto::new(gen_signing_key());
        let sig = crypto.sign(b"correct");
        assert!(!Crypto::verify(&crypto.public_key, b"wrong", &sig));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let crypto1 = Crypto::new(gen_signing_key());
        let crypto2 = Crypto::new(gen_signing_key());
        let sig = crypto1.sign(b"test");
        assert!(!Crypto::verify(&crypto2.public_key, b"test", &sig));
    }

    #[test]
    fn nonce_for_u64_format() {
        let n = nonce_for_u64(0);
        assert_eq!(n, [0u8; 24]);

        let n = nonce_for_u64(1);
        let mut expected = [0u8; 24];
        expected[23] = 1;
        assert_eq!(n, expected);
    }

    #[test]
    fn box_seal_and_open() {
        let (pub_a, priv_a) = new_box_keys(&mut OsRng);
        let (pub_b, priv_b) = new_box_keys(&mut OsRng);

        let msg = b"hello world";
        let ciphertext = box_seal(msg, 42, &pub_b, &priv_a).unwrap();
        assert_ne!(&ciphertext[..], msg);
        assert_eq!(ciphertext.len(), msg.len() + BOX_OVERHEAD);

        let plaintext = box_open(&ciphertext, 42, &pub_a, &priv_b).unwrap();
        assert_eq!(&plaintext[..], msg);
    }

    #[test]
    fn box_wrong_nonce_fails() {
        let (pub_a, priv_a) = new_box_keys(&mut OsRng);
        let (pub_b, priv_b) = new_box_keys(&mut OsRng);

        let ciphertext = box_seal(b"secret", 1, &pub_b, &priv_a).unwrap();
        let result = box_open(&ciphertext, 2, &pub_a, &priv_b);
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_to_curve25519_roundtrip() {
        let key_a = gen_signing_key();
        let key_b = gen_signing_key();

        let curve_priv_a = ed25519_private_to_curve25519(&key_a);
        let curve_priv_b = ed25519_private_to_curve25519(&key_b);

        let pub_a_ed: PublicKey = key_a.verifying_key().to_bytes();
        let pub_b_ed: PublicKey = key_b.verifying_key().to_bytes();

        let curve_pub_a = ed25519_public_to_curve25519(&pub_a_ed).unwrap();
        let curve_pub_b = ed25519_public_to_curve25519(&pub_b_ed).unwrap();

        let msg = b"test message";
        let ct = box_seal(msg, 0, &curve_pub_b, &curve_priv_a).unwrap();
        let pt = box_open(&ct, 0, &curve_pub_a, &curve_priv_b).unwrap();
        assert_eq!(&pt[..], msg);
    }

    #[test]
    fn precomputed_matches_direct() {
        let (pub_a, priv_a) = new_box_keys(&mut OsRng);
        let (pub_b, priv_b) = new_box_keys(&mut OsRng);

        let msg = b"precomputed test";
        let ct1 = box_seal(msg, 5, &pub_b, &priv_a).unwrap();
        let salsa = make_salsa_box(&pub_b, &priv_a);
        let ct2 = box_seal_precomputed(msg, 5, &salsa).unwrap();
        assert_eq!(ct1, ct2);

        let pt = box_open(&ct1, 5, &pub_a, &priv_b).unwrap();
        assert_eq!(&pt[..], msg);
    }
}
