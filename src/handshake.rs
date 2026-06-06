//! Handshake state machine for the Fengni protocol.
//!
//! The handshake establishes a shared session key between two peers
//! using X25519 ephemeral-static ECDH.
//!
//! # Protocol Flow
//!
//! ```text
//! Initiator                          Responder
//!   |                                     |
//!   | -- Hello (ephemeral_pub, ts) ---->  |
//!   |                                     |
//!   | <-- HelloReply (ephemeral_pub, ---  |
//!   |     session_token)                  |
//!   |                                     |
//!   | -- Authenticate (identity_pub, ---> |
//!   |     proof)                          |
//!   |                                     |
//!   | <-- ServerFinish (encrypted) ----   |
//!   |                                     |
//!   | === session key established ====    |
//! ```
//!
//! After the handshake, both peers share a symmetric session key
//! for encrypting subsequent data packets.

use crate::crypto::{self, KeyPair, PUBLIC_KEY_LEN, SYMMETRIC_KEY_LEN};
use crate::error::{FengniError, HandshakeError};
use crate::wire::{
    fengni_message::Variant, Authenticate, FengniMessage, Hello, HelloReply, ServerFinish,
};

/// HKDF info labels for key derivation in each phase.
const HKDF_INFO_HELLO: &[u8] = b"fengni-v1-handshake-hello";
const HKDF_INFO_SESSION: &[u8] = b"fengni-v1-handshake-session";

/// Context label for MAC proof in Authentication.
const PROOF_CONTEXT: &[u8] = b"fengni-v1-auth-proof";

/// Maximum allowed clock skew in seconds.
const CLOCK_SKEW_SECS: u64 = 60;

/// The state of a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for the initiator's Hello.
    ExpectHello,
    /// Waiting for the responder's HelloReply.
    ExpectHelloReply,
    /// Waiting for the initiator's Authenticate.
    ExpectAuthenticate,
    /// Waiting for the responder's ServerFinish.
    ExpectServerFinish,
    /// Handshake is complete; a session key is established.
    Completed,
}

impl HandshakeState {
    /// Returns true if the handshake has completed.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// A Fengni protocol handshake.
///
/// Create via [`Handshake::initiator`] or [`Handshake::responder`].
pub struct Handshake {
    state: HandshakeState,
    identity: KeyPair,
    ephemeral: KeyPair,
    peer_identity_public: Option<[u8; PUBLIC_KEY_LEN]>,
    peer_ephemeral_public: Option<[u8; PUBLIC_KEY_LEN]>,
    session_key: Option<[u8; SYMMETRIC_KEY_LEN]>,
}

impl Handshake {
    /// Create the initiator side of the handshake.
    ///
    /// `identity` — the initiator's long-term key pair.
    /// `peer_static_public` — the expected responder's public key (for pinning).
    pub fn initiator(identity: KeyPair, peer_static_public: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self {
            state: HandshakeState::ExpectHelloReply,
            ephemeral: KeyPair::generate(),
            identity,
            peer_identity_public: Some(peer_static_public),
            peer_ephemeral_public: None,
            session_key: None,
        }
    }

    /// Create the responder side of the handshake.
    ///
    /// `identity` — the responder's long-term key pair.
    pub fn responder(identity: KeyPair) -> Self {
        Self {
            state: HandshakeState::ExpectHello,
            ephemeral: KeyPair::generate(),
            identity,
            peer_identity_public: None,
            peer_ephemeral_public: None,
            session_key: None,
        }
    }

    /// Returns the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the established session key, if any.
    pub fn session_key(&self) -> Option<&[u8; SYMMETRIC_KEY_LEN]> {
        self.session_key.as_ref()
    }

    /// Build and return the Hello message.
    ///
    /// Only valid in [`HandshakeState::ExpectHelloReply`] (initiator).
    pub fn send_hello(&mut self) -> Result<Vec<u8>, FengniError> {
        if self.state != HandshakeState::ExpectHelloReply {
            return Err(HandshakeError::AlreadyCompleted.into());
        }

        let ts = current_timestamp();
        let hello = Hello {
            ephemeral_public: self.ephemeral.public_key_bytes().to_vec().into(),
            timestamp: ts,
        };

        let msg = FengniMessage {
            variant: Some(Variant::Hello(hello)),
        };

        Ok(crate::wire::encode(&msg)?)
    }

    /// Process an incoming handshake message and return the next message to
    /// send, if any.
    ///
    /// Returns `Ok(None)` when the handshake is complete and no response is
    /// needed.
    ///
    /// Returns `Ok(Some(bytes))` when a reply should be sent to the peer.
    pub fn handle_message(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, FengniError> {
        let msg: FengniMessage = crate::wire::decode(raw)?;

        match (self.state, msg.variant) {
            // Responder receives Hello -> sends HelloReply
            (
                HandshakeState::ExpectHello,
                Some(Variant::Hello(Hello {
                    ephemeral_public,
                    timestamp,
                })),
            ) => {
                // Validate timestamp
                let now = current_timestamp();
                if timestamp < now.saturating_sub(CLOCK_SKEW_SECS)
                    || timestamp > now.saturating_add(CLOCK_SKEW_SECS)
                {
                    return Err(HandshakeError::TimestampExpired {
                        peer_ts: timestamp,
                        local_ts: now,
                    }
                    .into());
                }

                // Store peer ephemeral public
                let peer_ephemeral: [u8; PUBLIC_KEY_LEN] = ephemeral_public
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?;
                self.peer_ephemeral_public = Some(peer_ephemeral);

                // Derive handshake key = HKDF(ECDH(our_ephemeral, peer_ephemeral))
                let shared = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&shared, HKDF_INFO_HELLO)?;

                // Build session token = encrypt(our_identity_pub || session_id) under handshake key
                let token_plaintext = {
                    let mut v = self.identity.public_key_bytes().to_vec();
                    v.extend_from_slice(&current_timestamp().to_be_bytes());
                    v
                };
                let nonce = [0u8; crypto::NONCE_LEN];
                let session_token = crypto::encrypt(&hk, &nonce, &token_plaintext)?;

                self.state = HandshakeState::ExpectAuthenticate;

                let reply = HelloReply {
                    ephemeral_public: self.ephemeral.public_key_bytes().to_vec().into(),
                    session_token: session_token.into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::HelloReply(reply)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // Initiator receives HelloReply -> sends Authenticate
            (
                HandshakeState::ExpectHelloReply,
                Some(Variant::HelloReply(HelloReply {
                    ephemeral_public,
                    session_token,
                })),
            ) => {
                let peer_ephemeral: [u8; PUBLIC_KEY_LEN] = ephemeral_public
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?;
                self.peer_ephemeral_public = Some(peer_ephemeral);

                // Derive handshake key
                let shared = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&shared, HKDF_INFO_HELLO)?;

                // Decrypt session token and verify it contains the expected peer identity
                let nonce = [0u8; crypto::NONCE_LEN];
                let token_plaintext = crypto::decrypt(&hk, &nonce, &session_token)?;
                if token_plaintext.len() < PUBLIC_KEY_LEN {
                    return Err(HandshakeError::Malformed.into());
                }
                let claimed_identity: [u8; PUBLIC_KEY_LEN] =
                    token_plaintext[..PUBLIC_KEY_LEN].try_into().unwrap();

                // Verify the responder's identity matches the pinned key
                if let Some(expected) = &self.peer_identity_public {
                    if claimed_identity != *expected {
                        return Err(HandshakeError::IdentityRejected.into());
                    }
                }
                // Update the stored identity
                self.peer_identity_public = Some(claimed_identity);

                // Build proof = MAC(handshake_key, our_identity_pub || PROOF_CONTEXT)
                let proof = {
                    let mut plaintext = self.identity.public_key_bytes().to_vec();
                    plaintext.extend_from_slice(PROOF_CONTEXT);
                    crypto::encrypt(&hk, &nonce, &plaintext)?
                };

                self.state = HandshakeState::ExpectServerFinish;

                let auth = Authenticate {
                    identity_public: self.identity.public_key_bytes().to_vec().into(),
                    proof: proof.into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::Authenticate(auth)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // Responder receives Authenticate -> sends ServerFinish, derives session key
            (
                HandshakeState::ExpectAuthenticate,
                Some(Variant::Authenticate(Authenticate {
                    identity_public,
                    proof,
                })),
            ) => {
                let peer_identity: [u8; PUBLIC_KEY_LEN] = identity_public
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?;

                // Verify the proof
                let peer_ephemeral = self
                    .peer_ephemeral_public
                    .ok_or(FengniError::State("no peer ephemeral".into()))?;
                let shared = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&shared, HKDF_INFO_HELLO)?;

                // Verify proof: decrypt and check it contains the claimed identity
                let nonce = [0u8; crypto::NONCE_LEN];
                let proof_plaintext = crypto::decrypt(&hk, &nonce, &proof)
                    .map_err(|_| HandshakeError::IdentityRejected)?;
                if proof_plaintext.len() < PUBLIC_KEY_LEN {
                    return Err(HandshakeError::IdentityRejected.into());
                }
                // TODO: Proper MAC verification instead of encrypt-based proof
                if proof_plaintext[..PUBLIC_KEY_LEN] != peer_identity {
                    return Err(HandshakeError::IdentityRejected.into());
                }

                // Accept the peer identity
                self.peer_identity_public = Some(peer_identity);

                // Derive session key via triple DH.
                // Concatenate the three DH outputs in sorted order so that
                // both peers produce the same combined material regardless
                // of which side is initiator vs responder.
                let ee = shared; // already computed above
                let se = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let es = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_identity),
                );
                let sk = derive_triple_dh_key(&[ee, se, es])?;
                self.session_key = Some(sk);

                // Build ServerFinish (encrypted confirmation under session key)
                let finish_payload = {
                    let plaintext = b"fengni-handshake-complete";
                    crypto::encrypt(&sk, &nonce, plaintext)?
                };

                self.state = HandshakeState::Completed;

                let finish = ServerFinish {
                    payload: finish_payload.into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::ServerFinish(finish)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // Initiator receives ServerFinish -> verifies and derives session key
            (
                HandshakeState::ExpectServerFinish,
                Some(Variant::ServerFinish(ServerFinish { payload })),
            ) => {
                let peer_ephemeral = self
                    .peer_ephemeral_public
                    .ok_or(FengniError::State("no peer ephemeral".into()))?;
                let peer_static = self
                    .peer_identity_public
                    .ok_or(FengniError::State("no peer identity".into()))?;

                // Derive session key via triple DH (same formula as responder).
                // Concatenate the three DH outputs in sorted order so that
                // both peers produce the same combined material.
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let se = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let es = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_static),
                );
                let sk = derive_triple_dh_key(&[ee, se, es])?;

                // Verify the finish payload
                let nonce = [0u8; crypto::NONCE_LEN];
                let plaintext = crypto::decrypt(&sk, &nonce, &payload)
                    .map_err(|_| HandshakeError::IdentityRejected)?;
                if plaintext != b"fengni-handshake-complete" {
                    return Err(HandshakeError::IdentityRejected.into());
                }

                self.session_key = Some(sk);
                self.state = HandshakeState::Completed;

                Ok(None) // Handshake complete, no more messages
            }

            // Any other message in the current state is unexpected
            _ => Err(HandshakeError::UnexpectedMessage.into()),
        }
    }
}

/// Combine three DH shared secrets via HKDF.
///
/// Sorts the three byte arrays before concatenation so that both peers
/// produce identical input material regardless of role (initiator/responder).
fn derive_triple_dh_key(shares: &[[u8; PUBLIC_KEY_LEN]; 3]) -> Result<[u8; SYMMETRIC_KEY_LEN], FengniError> {
    let mut sorted: Vec<&[u8]> = shares.iter().map(|s| s.as_slice()).collect();
    sorted.sort();
    let mut combined = Vec::with_capacity(PUBLIC_KEY_LEN * 3);
    for s in &sorted {
        combined.extend_from_slice(s);
    }
    crypto::derive_key(&combined, HKDF_INFO_SESSION).map_err(Into::into)
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_succeeds() {
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();

        // Alice initiates to Bob
        let mut hs_a = Handshake::initiator(alice_key.clone(), bob_key.public_key_bytes());
        assert_eq!(hs_a.state(), HandshakeState::ExpectHelloReply);

        let hello = hs_a.send_hello().unwrap();
        assert!(!hello.is_empty());

        // Bob receives Hello
        let mut hs_b = Handshake::responder(bob_key.clone());
        assert_eq!(hs_b.state(), HandshakeState::ExpectHello);

        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        assert_eq!(hs_b.state(), HandshakeState::ExpectAuthenticate);

        // Alice receives HelloReply, sends Authenticate
        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        assert_eq!(hs_a.state(), HandshakeState::ExpectServerFinish);

        // Bob receives Authenticate, sends ServerFinish
        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        assert_eq!(hs_b.state(), HandshakeState::Completed);
        assert!(hs_b.session_key().is_some());

        // Alice receives ServerFinish
        let done = hs_a.handle_message(&finish).unwrap();
        assert!(done.is_none());
        assert_eq!(hs_a.state(), HandshakeState::Completed);
        assert!(hs_a.session_key().is_some());

        // Both have the same session key
        assert_eq!(hs_a.session_key().unwrap(), hs_b.session_key().unwrap());
    }

    #[test]
    fn wrong_peer_identity_rejected() {
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let mallory_key = KeyPair::generate();

        // Alice expects Bob, but Mallory responds
        let mut hs_a = Handshake::initiator(alice_key, bob_key.public_key_bytes());
        let hello = hs_a.send_hello().unwrap();

        let mut hs_m = Handshake::responder(mallory_key);
        let reply = hs_m.handle_message(&hello).unwrap().unwrap();

        // Alice should reject Mallory's HelloReply because the identity in the
        // session token doesn't match the pinned Bob key
        let result = hs_a.handle_message(&reply);
        assert!(result.is_err());
    }

    #[test]
    fn expired_timestamp_rejected() {
        let bob_key = KeyPair::generate();
        let mut hs_b = Handshake::responder(bob_key);

        // Craft a Hello with a timestamp far in the past
        let hello = FengniMessage {
            variant: Some(Variant::Hello(Hello {
                ephemeral_public: KeyPair::generate().public_key_bytes().to_vec().into(),
                timestamp: 0, // Jan 1, 1970
            })),
        };
        let raw = crate::wire::encode(&hello).unwrap();

        let result = hs_b.handle_message(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn unexpected_message_rejected() {
        let bob_key = KeyPair::generate();
        let mut hs_b = Handshake::responder(bob_key);

        // Send Authenticate before Hello
        let auth = FengniMessage {
            variant: Some(Variant::Authenticate(Authenticate {
                identity_public: KeyPair::generate().public_key_bytes().to_vec().into(),
                proof: vec![0u8; 48].into(),
            })),
        };
        let raw = crate::wire::encode(&auth).unwrap();

        let result = hs_b.handle_message(&raw);
        assert!(result.is_err());
    }
}
