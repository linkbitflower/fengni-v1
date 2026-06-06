//! Wire format definitions for the Fengni protocol.
//!
//! All protocol messages are serialized using Protocol Buffers (proto3).

/// Hello message sent by the initiator to start a handshake.
///
/// Contains the initiator's ephemeral public key and the current timestamp
/// for replay protection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hello {
    /// Ephemeral X25519 public key (32 bytes)
    #[prost(bytes, tag = "1")]
    pub ephemeral_public: ::prost::bytes::Bytes,
    /// Unix timestamp in seconds (big-endian)
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
}

/// HelloReply message sent by the responder in response to Hello.
///
/// Contains the responder's ephemeral public key and encrypted session
/// identifier for stateful session tracking.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HelloReply {
    /// Responder's ephemeral X25519 public key (32 bytes)
    #[prost(bytes, tag = "1")]
    pub ephemeral_public: ::prost::bytes::Bytes,
    /// Encrypted session token (opaque to the initiator)
    #[prost(bytes, tag = "2")]
    pub session_token: ::prost::bytes::Bytes,
}

/// Authentication message sent by the initiator after receiving HelloReply.
///
/// Proves the initiator's identity to the responder.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authenticate {
    /// Initiator's long-term X25519 public key (32 bytes)
    #[prost(bytes, tag = "1")]
    pub identity_public: ::prost::bytes::Bytes,
    /// Signature or MAC proving possession of the identity private key
    #[prost(bytes, tag = "2")]
    pub proof: ::prost::bytes::Bytes,
}

/// Wraps the initiator's reply for stateless handshake continuation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerFinish {
    /// Session material encrypted under the handshake key
    #[prost(bytes, tag = "1")]
    pub payload: ::prost::bytes::Bytes,
}

/// An encrypted data packet sent after the handshake completes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DataPacket {
    /// Sequence number for replay protection and ordering
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// Encrypted payload
    #[prost(bytes, tag = "2")]
    pub ciphertext: ::prost::bytes::Bytes,
}

/// Top-level message wrapper. All Fengni protocol messages are
/// encoded as a FengniMessage.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FengniMessage {
    /// Variant discriminator
    #[prost(oneof = "fengni_message::Variant", tags = "1, 2, 3, 4, 5")]
    pub variant: ::core::option::Option<fengni_message::Variant>,
}

/// Nested types for the oneof discriminator.
pub mod fengni_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Variant {
        #[prost(message, tag = "1")]
        Hello(super::Hello),
        #[prost(message, tag = "2")]
        HelloReply(super::HelloReply),
        #[prost(message, tag = "3")]
        Authenticate(super::Authenticate),
        #[prost(message, tag = "4")]
        ServerFinish(super::ServerFinish),
        #[prost(message, tag = "5")]
        DataPacket(super::DataPacket),
    }
}

// --- Encode / Decode ---

use prost::Message;

/// Encode a FengniMessage to protobuf bytes.
pub fn encode(msg: &FengniMessage) -> Result<Vec<u8>, prost::EncodeError> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;
    Ok(buf)
}

/// Decode a FengniMessage from protobuf bytes.
pub fn decode(raw: &[u8]) -> Result<FengniMessage, prost::DecodeError> {
    FengniMessage::decode(raw)
}
