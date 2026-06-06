//! # Fengni
//!
//! A private encrypted communication protocol library.
//!
//! Fengni defines a complete secure protocol:
//! - **X25519** key exchange with ephemeral-static ECDH
//! - **ChaCha20-Poly1305** authenticated encryption
//! - **HKDF-SHA256** key derivation
//! - **Protobuf** wire format for protocol messages
//!
//! ## Architecture
//!
//! ```text
//! handshake.rs   — Handshake state machine
//! crypto.rs      — Cryptographic primitives
//! wire.rs        — Packet encoding/decoding
//! error.rs       — Unified error types
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fengni::{Handshake, HandshakeState, KeyPair};
//!
//! // Generate identity keys
//! let alice_key = KeyPair::generate();
//! let bob_key = KeyPair::generate();
//!
//! // Alice initiates handshake to Bob
//! let mut hs = Handshake::initiator(alice_key, bob_key.public_key_bytes());
//! let hello = hs.send_hello().unwrap();
//!
//! // Bob receives and responds
//! let mut hs = Handshake::responder(bob_key);
//! let reply = hs.handle_message(&hello).unwrap();
//! ```

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod wire;

// Re-export main types
pub use crypto::KeyPair;
pub use handshake::{Handshake, HandshakeState};
pub use wire::FengniMessage;
