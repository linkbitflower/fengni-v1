//! # Fengni
//!
//! An encrypted communication protocol library.
//!
//! Fengni provides a secure, mutual-authenticated key exchange protocol
//! built on X25519 and ChaCha20-Poly1305.
//!
//! ## Features
//!
//! - **X25519** key exchange with quadruple DH (ee + es + se + ss)
//! - **ChaCha20-Poly1305** authenticated encryption
//! - **HKDF-SHA256** key derivation
//! - **HMAC-SHA256** identity proofs
//! - **Protobuf** wire format for protocol messages
//! - **KCI resistance** via precomputed static-static DH
//! - **Separate send/receive keys** with automatic nonce management
//!
//! ## Architecture
//!
//! ```text
//! handshake.rs   — Handshake state machine + HandshakeBuilder
//! transport.rs   — Post-handshake data channel
//! crypto.rs      — Cryptographic primitives + CipherState
//! wire.rs        — Packet encoding/decoding
//! error.rs       — Unified error types
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fengni::{HandshakeBuilder, KeyPair};
//!
//! // Generate identity keys
//! let mut alice_key = KeyPair::generate();
//! let bob_key = KeyPair::generate();
//! let bob_pub = bob_key.public_key_bytes();
//!
//! // Alice initiates handshake to Bob (with key pinning for KCI resistance)
//! alice_key.pin_peer(&bob_pub);
//! let mut hs_a = HandshakeBuilder::initiator(alice_key, bob_pub).build();
//! let hello = hs_a.send_hello().unwrap();
//!
//! // Bob receives and responds
//! let mut hs_b = HandshakeBuilder::responder(bob_key).build();
//! let reply = hs_b.handle_message(&hello).unwrap().unwrap();
//!
//! // ... complete handshake ...
//!
//! // After handshake, encrypt data
//! let transport = hs_a.into_transport().unwrap();
//! let ct = transport.send(b"hello bob").unwrap();
//! ```

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod transport;
pub mod wire;

// Re-export main types
pub use crypto::KeyPair;
pub use handshake::{Handshake, HandshakeBuilder, HandshakeState};
pub use transport::TransportState;
pub use wire::FengniMessage;
