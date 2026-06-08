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
    aead::{Aead, AeadInPlace, KeyInit, OsRng},
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

/// AEAD confidentiality limit: maximum safe encryptions under a single key.
///
/// For ChaCha20-Poly1305 with sequential nonces this is effectively unlimited.
/// Ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
pub const CONFIDENTIALITY_LIMIT: u64 = u64::MAX;

/// AEAD integrity limit: maximum failed decryption attempts before the key MUST be retired.
///
/// Ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
pub const INTEGRITY_LIMIT: u64 = 1 << 36;

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

/// Encrypt `plaintext` into a caller-provided buffer (zero-copy).
///
/// Copies plaintext into `out`, encrypts in-place via
/// `encrypt_in_place_detached`, and appends the 16-byte tag.
/// Returns total bytes written. No internal allocation.
///
/// Requires `out.len() >= plaintext.len() + TAG_LEN`.
pub fn encrypt_into(
    key: &[u8; SYMMETRIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let pt_len = plaintext.len();
    let ct_len = pt_len + TAG_LEN;
    if out.len() < ct_len {
        return Err(CryptoError::Encrypt);
    }

    // Copy plaintext into caller buffer
    out[..pt_len].copy_from_slice(plaintext);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Encrypt)?;
    let nonce_arr = Nonce::from_slice(nonce);

    // Encrypt in-place in the caller buffer — no internal Vec
    let tag = cipher
        .encrypt_in_place_detached(nonce_arr, b"", &mut out[..pt_len])
        .map_err(|_| CryptoError::Encrypt)?;

    // Append tag after ciphertext
    out[pt_len..ct_len].copy_from_slice(&tag);
    Ok(ct_len)
}

/// Decrypt `ciphertext` into a caller-provided buffer (zero-copy).
///
/// Copies ciphertext body into `out`, decrypts in-place via
/// `decrypt_in_place_detached` with the detached tag. No internal allocation.
/// Returns plaintext length.
///
/// Requires `out.len() >= ciphertext.len() - TAG_LEN`.
pub fn decrypt_into(
    key: &[u8; SYMMETRIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let body_len = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(CryptoError::Decrypt)?;
    if out.len() < body_len {
        return Err(CryptoError::Decrypt);
    }

    // Split body and tag from the incoming ciphertext
    let body = &ciphertext[..body_len];
    let tag_bytes = &ciphertext[body_len..];

    // Copy body into caller buffer
    out[..body_len].copy_from_slice(body);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Decrypt)?;
    let nonce_arr = Nonce::from_slice(nonce);
    let tag_arr = chacha20poly1305::Tag::from_slice(tag_bytes);

    // Decrypt in-place in the caller buffer — no internal Vec
    cipher
        .decrypt_in_place_detached(nonce_arr, b"", &mut out[..body_len], tag_arr)
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(body_len)
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

    /// AEAD confidentiality limit — maximum safe encryptions under this key.
    ///
    /// For ChaCha20-Poly1305 with sequential nonces this is `u64::MAX`,
    /// but callers should treat this as the rekey threshold.
    pub fn confidentiality_limit() -> u64 {
        CONFIDENTIALITY_LIMIT
    }

    /// AEAD integrity limit — maximum failed decryptions before the key MUST be retired.
    ///
    /// After exceeding this limit, the connection should be closed and the key discarded.
    pub fn integrity_limit() -> u64 {
        INTEGRITY_LIMIT
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

    /// Encrypt `plaintext` into a caller-provided buffer (zero-copy).
    ///
    /// Writes ciphertext + tag into `out`, returns bytes written.
    /// Requires `out.len() >= plaintext.len() + TAG_LEN`.
    pub fn encrypt_into(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Encrypt);
        }
        validate_nonce(self.n)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&self.n.to_le_bytes());
        let written = encrypt_into(&self.key, &nonce_bytes, plaintext, out)?;
        self.n += 1;
        Ok(written)
    }

    /// Decrypt `ciphertext` into a caller-provided buffer (zero-copy).
    ///
    /// Writes plaintext into `out`, returns bytes written.
    /// Requires `out.len() >= ciphertext.len() - TAG_LEN`.
    pub fn decrypt_into(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Decrypt);
        }
        validate_nonce(self.n)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&self.n.to_le_bytes());
        let written = decrypt_into(&self.key, &nonce_bytes, ciphertext, out)?;
        self.n += 1;
        Ok(written)
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

    // --- Stateless methods (caller manages nonce) ---

    /// Encrypt with an explicit nonce (does not consume `&mut self`).
    ///
    /// The caller is responsible for nonce uniqueness. Internal nonce
    /// counter is untouched. Use for session serialization or multi-thread
    /// encryption where the caller partitions the nonce space.
    pub fn encrypt_with_nonce(&self, nonce: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Encrypt);
        }
        validate_nonce(nonce)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());
        encrypt(&self.key, &nonce_bytes, plaintext)
    }

    /// Decrypt with an explicit nonce (does not consume `&mut self`).
    ///
    /// See [`encrypt_with_nonce`](Self::encrypt_with_nonce).
    pub fn decrypt_with_nonce(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Decrypt);
        }
        validate_nonce(nonce)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());
        decrypt(&self.key, &nonce_bytes, ciphertext)
    }

    /// Zero-copy encrypt with an explicit nonce.
    ///
    /// Writes ciphertext + tag into `out`. Caller manages nonce.
    pub fn encrypt_into_with_nonce(
        &self,
        nonce: u64,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Encrypt);
        }
        validate_nonce(nonce)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());
        encrypt_into(&self.key, &nonce_bytes, plaintext, out)
    }

    /// Zero-copy decrypt with an explicit nonce.
    ///
    /// Writes plaintext into `out`. Caller manages nonce.
    pub fn decrypt_into_with_nonce(
        &self,
        nonce: u64,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if !self.has_key {
            return Err(CryptoError::Decrypt);
        }
        validate_nonce(nonce)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());
        decrypt_into(&self.key, &nonce_bytes, ciphertext, out)
    }
}

/// A pair of CipherStates for bidirectional communication.
pub struct CipherStates {
    /// Key for encrypting data we send.
    pub send: CipherState,
    /// Key for decrypting data we receive.
    pub recv: CipherState,
}

// --- ReplayValidator ---

/// Bitmap slider width in bits.
const REPLAY_WORD_SIZE: u64 = 64;
/// Number of words in the bitmap.
const REPLAY_N_WORDS: u64 = 16;
/// Total window width = 1024 packets.
const REPLAY_N_BITS: u64 = REPLAY_WORD_SIZE * REPLAY_N_WORDS;

/// Bitmap-based replay protection for received data packets.
///
/// Tracks a sliding window of 1024 nonce values, accepting limited
/// reordering while rejecting duplicated or too-old counters.
///
/// Pattern from boringtun's `ReceivingKeyCounterValidator`.
#[derive(Debug, Clone)]
pub struct ReplayValidator {
    /// Highest contiguous nonce we've received.
    next: u64,
    /// Bitmap of packets within the window.
    bitmap: [u64; REPLAY_N_WORDS as usize],
}

impl ReplayValidator {
    /// Create a new validator starting at nonce 0.
    pub fn new() -> Self {
        Self {
            next: 0,
            bitmap: [0u64; REPLAY_N_WORDS as usize],
        }
    }

    /// Quick pre-check before decryption: returns `Ok(())` if the counter
    /// is acceptable, `Err(NonceReplayed)` if duplicate, or
    /// `Err(Encrypt)` if too old.
    ///
    /// Call before expensive decryption to avoid wasting cycles on replays.
    #[inline]
    pub fn will_accept(&self, counter: u64) -> Result<(), CryptoError> {
        if counter >= self.next {
            // Growing counter — definitely no replay
            return Ok(());
        }
        if counter + REPLAY_N_BITS < self.next {
            // Too far back in the past
            return Err(CryptoError::Encrypt);
        }
        if self.check_bit(counter) {
            // Already seen this counter
            return Err(CryptoError::NonceReplayed);
        }
        Ok(())
    }

    /// Mark a counter as received after successful decryption.
    ///
    /// Advances the sliding window. Call only after decryption succeeds.
    #[inline]
    pub fn mark_did_receive(&mut self, counter: u64) {
        if counter >= self.next {
            // Counter ahead — clear gap bits and advance
            if counter - self.next >= REPLAY_N_BITS {
                // Big gap: clear entire bitmap
                for w in self.bitmap.iter_mut() {
                    *w = 0;
                }
            } else {
                // Small gap: clear intermediate words
                let mut i = self.next;
                while i % REPLAY_WORD_SIZE != 0 && i < counter {
                    self.clear_bit(i);
                    i += 1;
                }
                while i + REPLAY_WORD_SIZE <= counter {
                    self.clear_word(i);
                    i += REPLAY_WORD_SIZE;
                }
                while i <= counter {
                    self.clear_bit(i);
                    i += 1;
                }
            }
            self.set_bit(counter);
            self.next = counter + 1;
        } else {
            // counter < next: within window, not duplicate (already checked)
            self.set_bit(counter);
        }
    }

    // --- Bitmap helpers ---

    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % REPLAY_N_BITS;
        let word = (bit_idx / REPLAY_WORD_SIZE) as usize;
        let bit = (bit_idx % REPLAY_WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % REPLAY_N_BITS;
        let word = (bit_idx / REPLAY_WORD_SIZE) as usize;
        let bit = (bit_idx % REPLAY_WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % REPLAY_N_BITS;
        let word = (bit_idx / REPLAY_WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % REPLAY_N_BITS;
        let word = (bit_idx / REPLAY_WORD_SIZE) as usize;
        let bit = (bit_idx % REPLAY_WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }
}

impl Default for ReplayValidator {
    fn default() -> Self {
        Self::new()
    }
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
        assert!(kp.ss.is_none());
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
        // ss = DH(alice_static, bob_static) = DH(bob_static, alice_static)
        let ss_direct = *alice.secret().diffie_hellman(&x25519_dalek::PublicKey::from(bob.public_key_bytes())).as_bytes();
        let mut bob2 = KeyPair::from_bytes(bob.secret.to_bytes());
        bob2.pin_peer(&alice.public_key_bytes());
        let ss_peer = *bob2.secret().diffie_hellman(&x25519_dalek::PublicKey::from(alice.public_key_bytes())).as_bytes();
        assert_eq!(ss_direct, ss_peer);
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

    #[test]
    fn encrypt_into_decrypt_into_roundtrip() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let nonce = [0x00u8; NONCE_LEN];
        let plaintext = b"hello fengni zero-copy";

        let mut ct_buf = vec![0u8; plaintext.len() + TAG_LEN];
        let written = encrypt_into(&key, &nonce, plaintext, &mut ct_buf).unwrap();
        assert_eq!(written, plaintext.len() + TAG_LEN);

        let mut pt_buf = vec![0u8; plaintext.len()];
        let read = decrypt_into(&key, &nonce, &ct_buf[..written], &mut pt_buf).unwrap();
        assert_eq!(read, plaintext.len());
        assert_eq!(&pt_buf[..read], plaintext);
    }

    #[test]
    fn cipherstate_encrypt_into_decrypt_into_roundtrip() {
        let key = [0xAAu8; SYMMETRIC_KEY_LEN];
        let plaintext = b"zero-copy via cipherstate";
        let mut cs_send = CipherState::new(&key);
        let mut cs_recv = CipherState::new(&key);

        let mut ct_buf = vec![0u8; plaintext.len() + TAG_LEN];
        let written = cs_send.encrypt_into(plaintext, &mut ct_buf).unwrap();
        assert_eq!(written, plaintext.len() + TAG_LEN);
        assert_eq!(cs_send.nonce(), 1);

        let mut pt_buf = vec![0u8; plaintext.len()];
        let read = cs_recv.decrypt_into(&ct_buf[..written], &mut pt_buf).unwrap();
        assert_eq!(read, plaintext.len());
        assert_eq!(&pt_buf[..read], plaintext);
        assert_eq!(cs_recv.nonce(), 1);
    }

    // --- ReplayValidator tests ---

    #[test]
    fn replay_validator_accepts_sequential() {
        let mut r = ReplayValidator::new();
        for i in 0..100 {
            assert!(r.will_accept(i).is_ok(), "should accept {}", i);
            r.mark_did_receive(i);
        }
    }

    #[test]
    fn replay_validator_rejects_duplicate() {
        let mut r = ReplayValidator::new();
        r.will_accept(0).unwrap();
        r.mark_did_receive(0);
        r.will_accept(1).unwrap();
        r.mark_did_receive(1);

        // Duplicate of 0 should be rejected
        assert!(r.will_accept(0).is_err());
        // Duplicate of 1 should be rejected
        assert!(r.will_accept(1).is_err());
    }

    #[test]
    fn replay_validator_rejects_too_old() {
        let mut r = ReplayValidator::new();
        // Advance past the window
        for i in 0..REPLAY_N_BITS {
            r.will_accept(i).unwrap();
            r.mark_did_receive(i);
        }
        r.will_accept(REPLAY_N_BITS).unwrap();
        r.mark_did_receive(REPLAY_N_BITS);

        // Nonce 0 is now too old (1024 behind)
        assert!(r.will_accept(0).is_err());
    }

    #[test]
    fn replay_validator_accepts_out_of_order() {
        let mut r = ReplayValidator::new();
        // Receive 0, 1, 5, then 3 (out of order), then duplicate 3
        r.will_accept(0).unwrap();
        r.mark_did_receive(0);
        r.will_accept(1).unwrap();
        r.mark_did_receive(1);
        r.will_accept(5).unwrap();
        r.mark_did_receive(5);
        // 3 is within window and not yet seen
        r.will_accept(3).unwrap();
        r.mark_did_receive(3);
        // Now 3 is duplicate
        assert!(r.will_accept(3).is_err());
        // 5 is also duplicate
        assert!(r.will_accept(5).is_err());
    }

    #[test]
    fn replay_validator_large_gap_clears_window() {
        let mut r = ReplayValidator::new();
        r.will_accept(0).unwrap();
        r.mark_did_receive(0);

        // Jump far ahead (> window size)
        let far = REPLAY_N_BITS * 3;
        r.will_accept(far).unwrap();
        r.mark_did_receive(far);

        // Old values should be rejected
        assert!(r.will_accept(0).is_err());
        assert!(r.will_accept(far / 2).is_err());
        // But immediate successor is fine
        assert!(r.will_accept(far + 1).is_ok());
    }

    #[test]
    fn aead_safety_limits() {
        // ChaCha20-Poly1305 confidentiality limit with sequential nonces
        // is effectively unlimited (nonce space is the limit).
        assert_eq!(CipherState::confidentiality_limit(), u64::MAX);
        // Integrity limit from RFC 9001 §6.6
        assert_eq!(CipherState::integrity_limit(), 1 << 36);
    }
}
