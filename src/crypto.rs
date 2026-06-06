//! Cryptographic primitives for the Fengni protocol.
//!
//! This module provides:
//! - X25519 key pairs for identity and ephemeral keys
//! - ChaCha20-Poly1305 authenticated encryption
//! - HKDF-SHA256 key derivation
//!
//! # Security
//!
//! Ephemeral keys are generated per-handshake and never reused.
//! Static keys identify peers and must be kept secret.
//! Each derived key is bound to a specific HKDF info string to prevent
//! key reuse across protocol phases.

use crate::error::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// --- Constants ---

/// Size of a ChaCha20-Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;
/// Size of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Size of a ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Size of a derived symmetric key in bytes.
pub const SYMMETRIC_KEY_LEN: usize = 32;

// --- Key Pair ---

/// An X25519 key pair used for identity or ephemeral keys.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create a key pair from an existing 32-byte private key.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Returns the public key as 32 bytes.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.public.as_bytes()
    }

    /// Returns a reference to the X25519 static secret.
    pub(crate) fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Returns a reference to the X25519 public key.
    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &format_args!("{:02x?}", self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

// --- Key Derivation ---

/// Derive a 32-byte symmetric key from Diffie-Hellman shared secret material.
///
/// `shared_secret` — the raw bytes from X25519 ECDH output.
/// `info` — a context-specific label to bind this key to a particular
///          protocol phase (e.g., `b"fengni-v1-handshake"`).
pub fn derive_key(shared_secret: &[u8], info: &[u8]) -> Result<[u8; SYMMETRIC_KEY_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; SYMMETRIC_KEY_LEN];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(okm)
}

// --- AEAD Encryption ---

/// Encrypt `plaintext` using ChaCha20-Poly1305.
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(key: &[u8; SYMMETRIC_KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Encrypt)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypt `ciphertext` using ChaCha20-Poly1305.
///
/// The ciphertext must include the 16-byte authentication tag.
pub fn decrypt(key: &[u8; SYMMETRIC_KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// Derive a shared secret via X25519 ECDH.
pub fn diffie_hellman(secret: &StaticSecret, public: &PublicKey) -> [u8; PUBLIC_KEY_LEN] {
    *secret.diffie_hellman(public).as_bytes()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generate_is_valid() {
        let kp = KeyPair::generate();
        let _pub_bytes = kp.public_key_bytes();
        assert_eq!(_pub_bytes.len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn keypair_from_bytes_roundtrip() {
        let kp = KeyPair::generate();
        // Clone via secret bytes — verify public key matches
        let kp2 = KeyPair::from_bytes(kp.secret.to_bytes());
        assert_eq!(kp.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let nonce = [0x00u8; NONCE_LEN];
        let plaintext = b"hello fengni";

        let ct = encrypt(&key, &nonce, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);

        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0xAAu8; SYMMETRIC_KEY_LEN];
        let key2 = [0xBBu8; SYMMETRIC_KEY_LEN];
        let nonce = [0x00u8; NONCE_LEN];
        let plaintext = b"hello fengni";

        let ct = encrypt(&key1, &nonce, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let nonce = [0x00u8; NONCE_LEN];
        let plaintext = b"hello fengni";

        let mut ct = encrypt(&key, &nonce, plaintext).unwrap();
        ct[0] ^= 0x01; // flip a bit
        let result = decrypt(&key, &nonce, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn diffie_hellman_same_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let ss_a = diffie_hellman(alice.secret(), bob.public());
        let ss_b = diffie_hellman(bob.secret(), alice.public());
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn derive_key_deterministic() {
        let ikm = b"test shared secret material";
        let info = b"fengni-v1-test";
        let k1 = derive_key(ikm, info).unwrap();
        let k2 = derive_key(ikm, info).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_info() {
        let ikm = b"test shared secret material";
        let k1 = derive_key(ikm, b"info-a").unwrap();
        let k2 = derive_key(ikm, b"info-b").unwrap();
        assert_ne!(k1, k2);
    }
}
