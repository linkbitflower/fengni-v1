//! Error types for the Fengni protocol.

use thiserror::Error;

/// Top-level error type for all Fengni operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FengniError {
    /// A cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// The handshake failed.
    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    /// Wire format encoding or decoding failed.
    #[error("wire error: {0}")]
    Wire(#[from] WireError),

    /// The protocol is in a wrong state for the requested operation.
    #[error("protocol state error: {0}")]
    State(String),
}

/// Errors from cryptographic operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,

    /// Decryption failed (wrong key, tampered data, or corrupted ciphertext).
    #[error("decryption failed")]
    Decrypt,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,

    /// The provided key material is invalid.
    #[error("invalid key material")]
    InvalidKey,

    /// Random number generation failed.
    #[error("random number generation failed")]
    RngFailure,
}

/// Errors from the handshake phase.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The handshake has already completed.
    #[error("handshake already completed")]
    AlreadyCompleted,

    /// An unexpected message type was received.
    #[error("unexpected message type")]
    UnexpectedMessage,

    /// The timestamp is outside the acceptable window.
    #[error("timestamp expired (peer: {peer_ts}, local: {local_ts})")]
    TimestampExpired {
        peer_ts: u64,
        local_ts: u64,
    },

    /// The peer's identity could not be verified.
    #[error("identity verification failed")]
    IdentityRejected,

    /// The handshake message is malformed.
    #[error("malformed handshake message")]
    Malformed,
}

/// Errors from wire format operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum WireError {
    /// Protobuf encoding failed.
    #[error("encode failed: {0}")]
    Encode(prost::EncodeError),

    /// Protobuf decoding failed.
    #[error("decode failed: {0}")]
    Decode(prost::DecodeError),
}

impl From<prost::EncodeError> for WireError {
    fn from(e: prost::EncodeError) -> Self {
        WireError::Encode(e)
    }
}

impl From<prost::DecodeError> for WireError {
    fn from(e: prost::DecodeError) -> Self {
        WireError::Decode(e)
    }
}

impl From<prost::EncodeError> for FengniError {
    fn from(e: prost::EncodeError) -> Self {
        FengniError::Wire(WireError::Encode(e))
    }
}

impl From<prost::DecodeError> for FengniError {
    fn from(e: prost::DecodeError) -> Self {
        FengniError::Wire(WireError::Decode(e))
    }
}
