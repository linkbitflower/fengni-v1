//! Transport state for the Fengni protocol.
//!
//! After a successful handshake, the [`Handshake::into_transport()`] method
//! consumes the handshake and returns a `TransportState`. This state holds
//! independent send and receive keys with automatic nonce management and
//! replay protection.
//!
//! # AEAD Safety
//!
//! Each key has confidentiality and integrity limits:
//! - [`confidentiality_limit()`] — max safe encryptions per key
//! - [`integrity_limit()`] — max failed decryptions before key retirement
//!
//! Callers should monitor decryption failures and close the connection when
//! the integrity limit is approached.
//!
//! # Example
//!
//! ```rust,no_run
//! # use fengni::{HandshakeBuilder, KeyPair};
//! # let alice = KeyPair::generate();
//! # let bob_pub = KeyPair::generate().public_key_bytes();
//! # let mut hs = HandshakeBuilder::initiator(alice, bob_pub).build();
//! # // ... complete handshake ...
//! let transport = hs.into_transport().unwrap();
//! let ciphertext = transport.send(b"hello").unwrap();
//! let plaintext = transport.recv(&ciphertext).unwrap();
//! ```

use crate::crypto::{CipherStates, ReplayValidator};
use crate::error::CryptoError;
use std::sync::{atomic::AtomicU64, atomic::Ordering, Mutex};

/// The transport state after a successful handshake.
///
/// Holds independent `send` and `recv` [`CipherState`]s with automatic
/// nonce tracking, replay protection, and AEAD safety boundary monitoring.
///
/// - Alice's `send` key = Bob's `recv` key
/// - Alice's `recv` key = Bob's `send` key
///
/// # Thread Safety
///
/// `TransportState` is `Send + Sync`. The send and receive paths use
/// independent locks — send and recv can proceed concurrently without
/// contention. Pattern from boringtun's `Session` which uses `AtomicU64`
/// for the sending counter and `Mutex<ReceivingKeyCounterValidator>`
/// for the receiving counter.
pub struct TransportState {
    send: Mutex<crate::crypto::CipherState>,
    recv: Mutex<crate::crypto::CipherState>,
    /// Bitmap-based replay protection for received packets.
    replay: Mutex<ReplayValidator>,
    /// Count of failed decryption attempts (for integrity limit tracking).
    auth_failures: AtomicU64,
}

impl TransportState {
    /// Create a new TransportState from pre-derived CipherStates.
    pub(crate) fn new(keys: CipherStates) -> Self {
        Self {
            send: Mutex::new(keys.send),
            recv: Mutex::new(keys.recv),
            replay: Mutex::new(ReplayValidator::new()),
            auth_failures: AtomicU64::new(0),
        }
    }

    // --- Limits ---

    /// Maximum safe encryptions under a single send key.
    ///
    /// For ChaCha20-Poly1305 with sequential nonces this is `u64::MAX`.
    /// Call [`rekey_send`](Self::rekey_send) before approaching this limit.
    pub fn confidentiality_limit() -> u64 {
        crate::crypto::CipherState::confidentiality_limit()
    }

    /// Maximum failed decryptions before the receive key MUST be retired.
    ///
    /// After exceeding this limit, discard the transport and re-handshake.
    pub fn integrity_limit() -> u64 {
        crate::crypto::CipherState::integrity_limit()
    }

    /// Returns the current number of authentication (decryption) failures.
    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    // --- Encrypt/Decrypt ---

    /// Encrypt `plaintext` for the peer using the send key.
    ///
    /// Returns ciphertext with authentication tag appended.
    /// Automatically increments the send nonce.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Encrypt` if the nonce counter has
    /// reached the maximum value. Call [`rekey_send`](Self::rekey_send) to rotate.
    pub fn send(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.send.lock().unwrap().encrypt(plaintext)
    }

    /// Decrypt `ciphertext` from the peer using the recv key.
    ///
    /// Checks for replay before decrypting, and marks the nonce as received
    /// after successful decryption. Returns the plaintext.
    ///
    /// # Errors
    ///
    /// - `CryptoError::NonceReplayed` if the nonce has already been seen
    ///   (duplicate packet or replay attack).
    /// - `CryptoError::Decrypt` if authentication fails — increments the
    ///   `auth_failures` counter. If this exceeds [`integrity_limit()`],
    ///   the key should be retired.
    /// - `CryptoError::Encrypt` if the nonce counter has reached the
    ///   maximum value (this variant is reused for "too old" nonces).
    pub fn recv(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Pre-check: validate nonce before expensive decryption.
        // Hold the recv lock across nonce read + replay check + decrypt
        // to prevent TOCTOU races when called from multiple threads.
        let mut recv = self.recv.lock().unwrap();
        let nonce_val = recv.nonce();
        self.replay.lock().unwrap().will_accept(nonce_val)?;

        match recv.decrypt(ciphertext) {
            Ok(pt) => {
                self.replay.lock().unwrap().mark_did_receive(nonce_val);
                Ok(pt)
            }
            Err(e) => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Encrypt `plaintext` into a caller-provided buffer (zero-copy).
    ///
    /// Writes ciphertext + tag into `out`, returns bytes written.
    /// Requires `out.len() >= plaintext.len() + ` [`crypto::TAG_LEN`].
    pub fn send_into(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        self.send.lock().unwrap().encrypt_into(plaintext, out)
    }

    /// Decrypt `ciphertext` into a caller-provided buffer (zero-copy).
    ///
    /// Checks replay before decrypting. Writes plaintext into `out`,
    /// returns bytes written.
    /// Requires `out.len() >= ciphertext.len() - ` [`crypto::TAG_LEN`].
    ///
    /// # Errors
    ///
    /// - `CryptoError::NonceReplayed` — duplicate nonce detected.
    /// - `CryptoError::Decrypt` — authentication failure.
    pub fn recv_into(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        // Pre-check: validate nonce before expensive decryption.
        let mut recv = self.recv.lock().unwrap();
        let nonce_val = recv.nonce();
        self.replay.lock().unwrap().will_accept(nonce_val)?;

        match recv.decrypt_into(ciphertext, out) {
            Ok(written) => {
                self.replay.lock().unwrap().mark_did_receive(nonce_val);
                Ok(written)
            }
            Err(e) => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Explicitly rekey the send cipher state.
    ///
    /// Advances to a new send key per Noise spec Section 4.2.
    pub fn rekey_send(&self) -> Result<(), CryptoError> {
        self.send.lock().unwrap().rekey()
    }

    /// Explicitly rekey the receive cipher state.
    ///
    /// Resets the ReplayValidator alongside the key. This is necessary because
    /// rekeying resets the nonce to 0, so the old validator window (which tracks
    /// high nonces) would reject all new legitimate messages as "too old."
    ///
    /// Pattern: WireGuard/boringtun creates a new `Session` on rekey rather
    /// than rekeying in-place, which naturally resets the validator. fengni
    /// achieves the same by explicitly resetting the validator.
    pub fn rekey_recv(&self) -> Result<(), CryptoError> {
        self.recv.lock().unwrap().rekey()?;
        *self.replay.lock().unwrap() = ReplayValidator::new();
        Ok(())
    }

    // --- Stateless methods (caller manages nonce) ---

    /// Encrypt with an explicit nonce (does not consume `&mut self` internal counter).
    ///
    /// The caller is responsible for nonce uniqueness. Use for session
    /// serialization, connection migration, or multi-threaded encryption
    /// where the caller partitions the nonce space.
    pub fn send_with_nonce(&self, nonce: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.send.lock().unwrap().encrypt_with_nonce(nonce, plaintext)
    }

    /// Zero-copy encrypt with an explicit nonce.
    pub fn send_into_with_nonce(
        &self,
        nonce: u64,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.send.lock().unwrap().encrypt_into_with_nonce(nonce, plaintext, out)
    }

    /// Decrypt with an explicit nonce (does not consume `&mut self` internal counter).
    ///
    /// Includes replay protection against the provided nonce.
    ///
    /// ## Concurrent callers
    ///
    /// The replay window is shared across all `recv*` methods on the same
    /// `TransportState`. When multiple threads call `recv_with_nonce` with
    /// non-overlapping nonce ranges, a thread that marks a high nonce advances
    /// the window past lower nonces from other threads. This is by design —
    /// the window enforces anti-replay at the transport level, not per-thread.
    /// Callers coordinating across threads should partition the nonce space so
    /// that replay ordering is maintained.
    pub fn recv_with_nonce(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.replay.lock().unwrap().will_accept(nonce)?;
        match self.recv.lock().unwrap().decrypt_with_nonce(nonce, ciphertext) {
            Ok(pt) => {
                self.replay.lock().unwrap().mark_did_receive(nonce);
                Ok(pt)
            }
            Err(e) => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Zero-copy decrypt with an explicit nonce.
    ///
    /// Includes replay protection against the provided nonce.
    ///
    /// ## Concurrent callers
    ///
    /// Same replay-window behavior as [`recv_with_nonce`](Self::recv_with_nonce).
    pub fn recv_into_with_nonce(
        &self,
        nonce: u64,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.replay.lock().unwrap().will_accept(nonce)?;
        match self.recv.lock().unwrap().decrypt_into_with_nonce(nonce, ciphertext, out) {
            Ok(written) => {
                self.replay.lock().unwrap().mark_did_receive(nonce);
                Ok(written)
            }
            Err(e) => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}
