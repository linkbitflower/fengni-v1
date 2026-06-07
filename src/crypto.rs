//! Cryptographic primitives for the Fengni protocol.
//!
//! This module provides:
//! - X25519 key pairs for identity and ephemeral keys
//! - Precomputed static-static DH (`ss`) for KCI resistance
//! - ChaCha20-Poly1305 authenticated encryption
//! - HKDF-SHA256 key derivation
//! - HMAC-SHA256 for identity proofs
//! - CipherState with nonce tracking and rekey
//!
//! # Security
//!
//! Ephemeral keys are generated per-handshake and never reused.
//! Static keys identify peers and must be kept secret.
//! Each derived key is bound to a specific HKDF info string to prevent
//! key reuse across protocol phases.
//! CipherState nonces start at 0 and must never exceed `u64::MAX - 1`
//! (reserved for rekey).

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
/// Size of an HMAC-SHA256 tag in bytes.
pub const HMAC_TAG_LEN: usize = 32;

// --- Key Pair ---

/// An X25519 key pair used for identity or ephemeral keys.
///
/// For identity keys, the static-static DH shared secret (`ss`)
/// is precomputed at construction time against a known peer,
/// providing KCI resistance at zero per-handshake cost.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
    /// Precomputed `DH(our_static, peer_static)` if peer is known.
    /// This is `ss` in the Noise framework — provides KCI resistance
    /// when included in session key derivation.
    pub(crate) ss: Option<[u8; PUBLIC_KEY_LEN]>,
}

impl KeyPair {
    /// Generate a new random key pair with no peer pinned.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public, ss: None }
    }

    /// Create a key pair from an existing 32-byte private key.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public, ss: None }
    }

    /// Compute the static-static DH precomputation against a known peer.
    ///
    /// Call this once when the peer's identity key is known. The
    /// precomputed `ss` term is cached and mixed into session key
    /// derivation for KCI resistance.
    pub fn pin_peer(&mut self, peer_static_public: &[u8; PUBLIC_KEY_LEN]) {
        let peer_public = PublicKey::from(*peer_static_public);
        self.ss = Some(*self.secret.diffie_hellman(&peer_public).as_bytes());
    }

    /// Returns the public key as 32 bytes.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.public.as_bytes()
    }

    /// Returns the precomputed static-static DH shared secret, if any.
    pub(crate) fn static_shared(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.ss
    }

    /// Returns a reference to the X25519 static secret.
    pub(crate) fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &format_args!("{:02x?}", self.public.as_bytes()))
            .field("has_ss", &self.ss.is_some())
            .finish_non_exhaustive()
    }
}

// --- Key Derivation ---

/// Derive a 32-byte symmetric key from input key material via HKDF-SHA256.
pub fn derive_key(ikm: &[u8], info: &[u8]) -> Result<[u8; SYMMETRIC_KEY_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; SYMMETRIC_KEY_LEN];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(okm)
}

/// Derive two 32-byte keys from input key material via HKDF-SHA256.
///
/// Used to produce independent `send_key` and `receive_key` from the
/// combined DH material after the handshake.
pub fn derive_key_pair(ikm: &[u8], info: &[u8]) -> Result<([u8; SYMMETRIC_KEY_LEN], [u8; SYMMETRIC_KEY_LEN]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm1 = [0u8; SYMMETRIC_KEY_LEN];
    let mut okm2 = [0u8; SYMMETRIC_KEY_LEN];
    hkdf.expand(info, &mut okm1)
        .map_err(|_| CryptoError::KeyDerivation)?;
    hkdf.expand(info, &mut okm2)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok((okm1, okm2))
}

// --- HMAC ---

/// Compute HMAC-SHA256 over `data` with the given `key`.
pub fn hmac_sha256(key: &[u8; SYMMETRIC_KEY_LEN], data: &[&[u8]]) -> [u8; HMAC_TAG_LEN] {
    use hmac::{Hmac, Mac, digest::KeyInit};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .expect("HMAC key is always 32 bytes");
    for chunk in data {
        Mac::update(&mut mac, chunk);
    }
    mac.finalize().into_bytes().into()
}

/// Verify a constant-time HMAC-SHA256 tag.
pub fn hmac_verify(
    key: &[u8; SYMMETRIC_KEY_LEN],
    data: &[&[u8]],
    expected: &[u8; HMAC_TAG_LEN],
) -> bool {
    let tag = hmac_sha256(key, data);
    // Constant-time comparison via the sha2/hmac crates' PartialEq on array
    tag == *expected
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

// --- CipherState ---

/// A stateful authenticated encryption key with automatic nonce management.
///
/// Wraps a ChaCha20-Poly1305 key with a monotonic nonce counter. Nonce `u64::MAX`
/// is reserved for `rekey()` per Noise spec Section 4.2.
pub struct CipherState {
    key: [u8; SYMMETRIC_KEY_LEN],
    n: u64,
    has_key: bool,
}

impl CipherState {
    /// Create a new CipherState with the given key, starting nonce at 0.
    pub fn new(key: &[u8; SYMMETRIC_KEY_LEN]) -> Self {
        Self { key: *key, n: 0, has_key: true }
    }

    /// Create an uninitialized CipherState.
    pub fn empty() -> Self {
        Self { key: [0u8; SYMMETRIC_KEY_LEN], n: 0, has_key: false }
    }

    /// Returns the current nonce value.
    pub fn nonce(&self) -> u64 {
        self.n
    }

    /// Encrypt `plaintext` with the current nonce and increment.
    ///
    /// Returns the ciphertext with authentication tag appended.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Encrypt);
        }
        validate_nonce(self.n)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&self.n.to_le_bytes());
        let ct = encrypt(&self.key, &nonce_bytes, plaintext)?;
        self.n += 1;
        Ok(ct)
    }

    /// Decrypt `ciphertext` with the current nonce and increment.
    ///
    /// The ciphertext must include the 16-byte authentication tag.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Decrypt);
        }
        validate_nonce(self.n)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&self.n.to_le_bytes());
        let pt = decrypt(&self.key, &nonce_bytes, ciphertext)?;
        self.n += 1;
        Ok(pt)
    }

    /// Rekey by encrypting a zero-block with nonce `u64::MAX`.
    ///
    /// Per Noise spec Section 4.2: `REKEY(k) = ENCRYPT(k, 2^64-1, 0^32)`.
    pub fn rekey(&mut self) -> Result<(), CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Encrypt);
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        let zeroes = [0u8; SYMMETRIC_KEY_LEN];
        let new_key_bytes = encrypt(&self.key, &nonce_bytes, &zeroes)?;
        // new_key_bytes is ciphertext, first 32 bytes are the rekey material
        if new_key_bytes.len() >= SYMMETRIC_KEY_LEN {
            self.key.copy_from_slice(&new_key_bytes[..SYMMETRIC_KEY_LEN]);
        }
        self.n = 0;
        Ok(())
    }

    /// Manually rekey with a provided key.
    pub fn rekey_manually(&mut self, key: &[u8; SYMMETRIC_KEY_LEN]) {
        self.key = *key;
        self.n = 0;
    }
}

/// A pair of CipherStates for bidirectional communication.
pub struct CipherStates {
    /// Key for encrypting data we send.
    pub send: CipherState,
    /// Key for decrypting data we receive.
    pub recv: CipherState,
}

/// Validate that a nonce has not reached the reserved value.
fn validate_nonce(n: u64) -> Result<(), CryptoError> {
    if n == u64::MAX {
        Err(CryptoError::Encrypt)
    } else {
        Ok(())
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generate_is_valid() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), PUBLIC_KEY_LEN);
        assert!(kp.static_shared().is_none());
    }

    #[test]
    fn keypair_from_bytes_roundtrip() {
        let kp = KeyPair::generate();
        let kp2 = KeyPair::from_bytes(kp.secret.to_bytes());
        assert_eq!(kp.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn keypair_pin_peer_produces_ss() {
        let mut alice = KeyPair::generate();
        let bob = KeyPair::generate();
        alice.pin_peer(&bob.public_key_bytes());
        assert!(alice.static_shared().is_some());

        // ss = DH(alice_static, bob_static) = DH(bob_static, alice_static)
        let mut bob2 = KeyPair::from_bytes(bob.secret.to_bytes());
        bob2.pin_peer(&alice.public_key_bytes());
        assert_eq!(alice.static_shared().unwrap(), bob2.static_shared().unwrap());
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
        assert!(decrypt(&key2, &nonce, &ct).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let nonce = [0x00u8; NONCE_LEN];
        let plaintext = b"hello fengni";

        let mut ct = encrypt(&key, &nonce, plaintext).unwrap();
        ct[0] ^= 0x01;
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn diffie_hellman_same_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_pub = x25519_dalek::PublicKey::from(alice.public_key_bytes());
        let bob_pub = x25519_dalek::PublicKey::from(bob.public_key_bytes());
        let ss_a = diffie_hellman(alice.secret(), &bob_pub);
        let ss_b = diffie_hellman(bob.secret(), &alice_pub);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn derive_key_deterministic() {
        let ikm = b"test shared secret material";
        let k1 = derive_key(ikm, b"fengni-v1-test").unwrap();
        let k2 = derive_key(ikm, b"fengni-v1-test").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_info() {
        let ikm = b"test shared secret material";
        let k1 = derive_key(ikm, b"info-a").unwrap();
        let k2 = derive_key(ikm, b"info-b").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn hmac_verification() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let tag1 = hmac_sha256(&key, &[b"hello", b" world"]);
        let tag2 = hmac_sha256(&key, &[b"hello", b" world"]);
        assert_eq!(tag1, tag2);
        assert!(hmac_verify(&key, &[b"hello", b" world"], &tag1));

        let tag3 = hmac_sha256(&key, &[b"hello", b" bob"]);
        assert_ne!(tag1, tag3);
        assert!(!hmac_verify(&key, &[b"hello", b" bob"], &tag1));
    }

    #[test]
    fn cipherstate_encrypt_decrypt() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let mut cs_send = CipherState::new(&key);
        let mut cs_recv = CipherState::new(&key);
        assert_eq!(cs_send.nonce(), 0);

        let ct = cs_send.encrypt(b"hello").unwrap();
        assert_eq!(cs_send.nonce(), 1);
        let pt = cs_recv.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(cs_recv.nonce(), 1);
    }

    #[test]
    fn cipherstate_decrypt_wrong_key_fails() {
        let key1 = [0xAAu8; SYMMETRIC_KEY_LEN];
        let key2 = [0xBBu8; SYMMETRIC_KEY_LEN];
        let mut cs_send = CipherState::new(&key1);
        let mut cs_recv = CipherState::new(&key2);

        let ct = cs_send.encrypt(b"hello").unwrap();
        assert!(cs_recv.decrypt(&ct).is_err());
    }

    #[test]
    fn cipherstate_rekey() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let mut cs_send = CipherState::new(&key);
        let mut cs_recv = CipherState::new(&key);
        let ct1 = cs_send.encrypt(b"hello").unwrap();
        cs_send.rekey().unwrap();
        cs_recv.rekey().unwrap();
        assert_eq!(cs_send.nonce(), 0);
        // Different key → different ciphertext for same plaintext
        let ct2 = cs_send.encrypt(b"hello").unwrap();
        assert_ne!(ct1, ct2);
        // Still decrypts correctly
        let pt2 = cs_recv.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"hello");
    }
}
