//! Transport state for the Fengni protocol.
//!
//! After a successful handshake, the [`Handshake::into_transport()`] method
//! consumes the handshake and returns a `TransportState`. This state holds
//! independent send and receive keys with automatic nonce management.
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

use crate::crypto::CipherStates;
use crate::error::CryptoError;
use core::cell::RefCell;

/// The transport state after a successful handshake.
///
/// Holds independent `send` and `recv` [`CipherState`]s with automatic
/// nonce tracking, using interior mutability via [`RefCell`] so that
/// `send()` and `recv()` take `&self`.
///
/// - Alice's `send` key = Bob's `recv` key
/// - Alice's `recv` key = Bob's `send` key
pub struct TransportState {
    send: RefCell<crate::crypto::CipherState>,
    recv: RefCell<crate::crypto::CipherState>,
}

impl TransportState {
    /// Create a new TransportState from pre-derived CipherStates.
    pub(crate) fn new(keys: CipherStates) -> Self {
        Self {
            send: RefCell::new(keys.send),
            recv: RefCell::new(keys.recv),
        }
    }

    /// Encrypt `plaintext` for the peer using the send key.
    ///
    /// Returns ciphertext with authentication tag appended.
    /// Automatically increments the send nonce.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Encrypt` if the nonce counter has
    /// reached the maximum value. Call [`rekey_send`] to rotate.
    pub fn send(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.send.borrow_mut().encrypt(plaintext)
    }

    /// Decrypt `ciphertext` from the peer using the recv key.
    ///
    /// Returns the plaintext. Automatically increments the recv nonce.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decrypt` if authentication fails or the
    /// nonce counter has reached the maximum value.
    pub fn recv(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.recv.borrow_mut().decrypt(ciphertext)
    }

    /// Encrypt `plaintext` into a caller-provided buffer (zero-copy).
    ///
    /// Writes ciphertext + tag into `out`, returns bytes written.
    /// Requires `out.len() >= plaintext.len() + ` [`crypto::TAG_LEN`].
    pub fn send_into(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        self.send.borrow_mut().encrypt_into(plaintext, out)
    }

    /// Decrypt `ciphertext` into a caller-provided buffer (zero-copy).
    ///
    /// Writes plaintext into `out`, returns bytes written.
    /// Requires `out.len() >= ciphertext.len() - ` [`crypto::TAG_LEN`].
    pub fn recv_into(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        self.recv.borrow_mut().decrypt_into(ciphertext, out)
    }
}
