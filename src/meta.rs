//! Metadata handshake: TLV-encoded version, public key, and priority.
//!
//! Wire format:
//!   "meta" (4 bytes) + length (u16 BE) + TLV fields + ed25519 signature (64 bytes)
//!
//! The signature is over BLAKE2b-512(public_key, key=password).
//!
//! Adapted from yggdrasil/src/version.rs for no_std.

use alloc::vec::Vec;
use blake2::digest::Mac;
use blake2::Blake2bMac512;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

const PREAMBLE: &[u8; 4] = b"meta";
const SIGNATURE_SIZE: usize = 64;

/// Metadata handshake errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaError {
    InvalidPreamble,
    TooShort,
    BadSignature,
    IncompatibleVersion,
    InvalidKey,
    BufferTooSmall,
}

#[cfg(feature = "std")]
impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPreamble => write!(f, "invalid preamble"),
            Self::TooShort => write!(f, "metadata too short"),
            Self::BadSignature => write!(f, "incorrect password or invalid signature"),
            Self::IncompatibleVersion => write!(f, "incompatible version"),
            Self::InvalidKey => write!(f, "invalid public key"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MetaError {}

/// Handshake metadata exchanged between peers.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub public_key: [u8; 32],
    pub priority: u8,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key: [0u8; 32],
            priority: 0,
        }
    }
}

impl Metadata {
    /// Create metadata for the local node.
    pub fn new(public_key: [u8; 32], priority: u8) -> Self {
        Self {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key,
            priority,
        }
    }

    /// Check if the version is compatible.
    pub fn check(&self) -> bool {
        self.major_ver == PROTOCOL_VERSION_MAJOR
            && self.minor_ver >= PROTOCOL_VERSION_MINOR
    }

    /// Encode metadata to wire format, signed with the given key.
    ///
    /// Returns the complete metadata message including preamble, length, TLV fields, and signature.
    pub fn encode(&self, signing_key: &SigningKey, password: &[u8]) -> Vec<u8> {
        let mut bs = Vec::with_capacity(128);
        bs.extend_from_slice(PREAMBLE);
        bs.extend_from_slice(&[0, 0]); // length placeholder

        // Major version TLV
        bs.extend_from_slice(&META_VERSION_MAJOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.major_ver.to_be_bytes());

        // Minor version TLV
        bs.extend_from_slice(&META_VERSION_MINOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.minor_ver.to_be_bytes());

        // Public key TLV
        bs.extend_from_slice(&META_PUBLIC_KEY.to_be_bytes());
        bs.extend_from_slice(&32u16.to_be_bytes());
        bs.extend_from_slice(&self.public_key);

        // Priority TLV
        bs.extend_from_slice(&META_PRIORITY.to_be_bytes());
        bs.extend_from_slice(&1u16.to_be_bytes());
        bs.push(self.priority);

        // BLAKE2b-512 hash of public key, signed with ed25519
        let hash = blake2b_hash(&self.public_key, password);
        let sig = signing_key.sign(&hash);
        bs.extend_from_slice(&sig.to_bytes());

        // Fill in length (excludes the 6-byte header)
        let length = (bs.len() - 6) as u16;
        bs[4..6].copy_from_slice(&length.to_be_bytes());

        bs
    }

    /// Decode metadata from a byte buffer. Verifies the signature.
    ///
    /// Returns (metadata, bytes_consumed) on success.
    pub fn decode(data: &[u8], password: &[u8]) -> Result<(Self, usize), MetaError> {
        if data.len() < 6 {
            return Err(MetaError::TooShort);
        }

        if &data[..4] != PREAMBLE {
            return Err(MetaError::InvalidPreamble);
        }

        let length = u16::from_be_bytes([data[4], data[5]]) as usize;
        if length < SIGNATURE_SIZE {
            return Err(MetaError::TooShort);
        }

        let total = 6 + length;
        if data.len() < total {
            return Err(MetaError::BufferTooSmall);
        }

        let body = &data[6..total];
        let sig_bytes = &body[length - SIGNATURE_SIZE..];
        let fields = &body[..length - SIGNATURE_SIZE];

        // Parse TLV fields
        let mut meta = Metadata::default();
        let mut pos = 0;
        while pos + 4 <= fields.len() {
            let field_id = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
            let field_len = u16::from_be_bytes([fields[pos + 2], fields[pos + 3]]) as usize;
            pos += 4;
            if pos + field_len > fields.len() {
                break;
            }
            match field_id {
                META_VERSION_MAJOR if field_len >= 2 => {
                    meta.major_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_VERSION_MINOR if field_len >= 2 => {
                    meta.minor_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_PUBLIC_KEY if field_len == 32 => {
                    meta.public_key.copy_from_slice(&fields[pos..pos + 32]);
                }
                META_PRIORITY if field_len >= 1 => {
                    meta.priority = fields[pos];
                }
                _ => {} // skip unknown fields
            }
            pos += field_len;
        }

        // Verify signature
        let hash = blake2b_hash(&meta.public_key, password);
        let signature = Signature::from_bytes(
            sig_bytes.try_into().map_err(|_| MetaError::BadSignature)?
        );
        let verifying_key = VerifyingKey::from_bytes(&meta.public_key)
            .map_err(|_| MetaError::InvalidKey)?;
        verifying_key
            .verify(&hash, &signature)
            .map_err(|_| MetaError::BadSignature)?;

        Ok((meta, total))
    }
}

/// Compute BLAKE2b-512 hash of data, optionally keyed with password.
fn blake2b_hash(data: &[u8], password: &[u8]) -> [u8; 64] {
    if password.is_empty() {
        use blake2::Digest;
        use blake2::Blake2b512;
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        hasher.finalize().into()
    } else {
        let mut mac = Blake2bMac512::new_from_slice(password)
            .expect("BLAKE2b key length should be valid");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
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
    fn encode_decode_no_password() {
        let signing_key = gen_signing_key();
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 0);
        let encoded = meta.encode(&signing_key, b"");

        assert_eq!(&encoded[..4], b"meta");

        let (decoded, consumed) = Metadata::decode(&encoded, b"").unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.major_ver, PROTOCOL_VERSION_MAJOR);
        assert_eq!(decoded.minor_ver, PROTOCOL_VERSION_MINOR);
        assert_eq!(decoded.public_key, public_key);
        assert_eq!(decoded.priority, 0);
        assert!(decoded.check());
    }

    #[test]
    fn encode_decode_with_password() {
        let signing_key = gen_signing_key();
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 5);
        let password = b"test-password";
        let encoded = meta.encode(&signing_key, password);

        let (decoded, _) = Metadata::decode(&encoded, password).unwrap();
        assert_eq!(decoded.priority, 5);
        assert_eq!(decoded.public_key, public_key);
    }

    #[test]
    fn decode_wrong_password_fails() {
        let signing_key = gen_signing_key();
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 0);
        let encoded = meta.encode(&signing_key, b"correct");

        let result = Metadata::decode(&encoded, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn check_valid() {
        let meta = Metadata::new([1u8; 32], 0);
        assert!(meta.check());
    }

    #[test]
    fn check_invalid_version() {
        let mut meta = Metadata::new([1u8; 32], 0);
        meta.major_ver = 1;
        assert!(!meta.check());
    }

    #[test]
    fn interop_with_original_format() {
        // Verify that our encoding produces the same structure as yggdrasil/version.rs
        let signing_key = gen_signing_key();
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();
        let meta = Metadata::new(public_key, 3);
        let encoded = meta.encode(&signing_key, b"");

        // Check structure:
        // [4: "meta"][2: length][TLV fields][64: signature]
        assert_eq!(&encoded[..4], b"meta");
        let length = u16::from_be_bytes([encoded[4], encoded[5]]) as usize;
        assert_eq!(encoded.len(), 6 + length);

        // First TLV should be major version (id=0, len=2)
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 0); // field id
        assert_eq!(u16::from_be_bytes([encoded[8], encoded[9]]), 2); // field len
        assert_eq!(u16::from_be_bytes([encoded[10], encoded[11]]), 0); // major=0
    }
}
