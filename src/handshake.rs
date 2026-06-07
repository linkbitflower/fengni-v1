//! Handshake state machine for the Fengni protocol.
//!
//! The handshake establishes a shared session key between two peers
//! using X25519 quadruple DH (ee + es + se + ss).
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
//!   | === send_key + recv_key established |
//! ```
//!
//! After the handshake, both peers hold independent send and receive keys
//! for encrypting subsequent data packets via `TransportState`.

use crate::crypto::{self, CipherStates, KeyPair, PUBLIC_KEY_LEN, SYMMETRIC_KEY_LEN};
use crate::error::{FengniError, HandshakeError};
use crate::transport::TransportState;
use crate::wire::{
    fengni_message::Variant, Authenticate, FengniMessage, Hello, HelloReply, ServerFinish,
};

/// HKDF info labels for key derivation in each phase.
const HKDF_INFO_HELLO: &[u8] = b"fengni-v1-handshake-hello";

/// HKDF info labels for deriving individual send/recv keys.
const HKDF_INFO_SEND: &[u8] = b"fengni-v1-transport-send";
const HKDF_INFO_RECV: &[u8] = b"fengni-v1-transport-recv";

/// Context label for HMAC proof in Authentication.
const PROOF_CONTEXT: &[u8] = b"fengni-v1-auth-proof";

/// Maximum allowed clock skew in seconds.
const CLOCK_SKEW_SECS: u64 = 60;


// --- Handshake State ---

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
    /// Handshake is complete; send/recv keys are established.
    Completed,
}

impl HandshakeState {
    /// Returns true if the handshake has completed.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// A Fengni protocol handshake builder.
///
/// Validates inputs before the handshake starts.
pub struct HandshakeBuilder {
    identity: KeyPair,
    peer_static_public: Option<[u8; PUBLIC_KEY_LEN]>,
    is_initiator: bool,
}

impl HandshakeBuilder {
    /// Create a new builder for the initiator role.
    ///
    /// `identity` — the initiator's long-term key pair.
    /// `peer_static_public` — the expected responder's public key (pinned).
    pub fn initiator(mut identity: KeyPair, peer_static_public: [u8; PUBLIC_KEY_LEN]) -> Self {
        identity.pin_peer(&peer_static_public);
        Self {
            identity,
            peer_static_public: Some(peer_static_public),
            is_initiator: true,
        }
    }

    /// Create a new builder for the responder role.
    ///
    /// `identity` — the responder's long-term key pair.
    pub fn responder(identity: KeyPair) -> Self {
        Self {
            identity,
            peer_static_public: None,
            is_initiator: false,
        }
    }

    /// Build the handshake state machine.
    pub fn build(self) -> Handshake {
        Handshake {
            state: if self.is_initiator {
                HandshakeState::ExpectHelloReply
            } else {
                HandshakeState::ExpectHello
            },
            identity: self.identity,
            ephemeral: KeyPair::generate(),
            peer_identity_public: self.peer_static_public,
            peer_ephemeral_public: None,
            send_key: None,
            recv_key: None,
        }
    }
}

/// A Fengni protocol handshake.
///
/// Create via [`HandshakeBuilder`].
pub struct Handshake {
    state: HandshakeState,
    identity: KeyPair,
    ephemeral: KeyPair,
    peer_identity_public: Option<[u8; PUBLIC_KEY_LEN]>,
    peer_ephemeral_public: Option<[u8; PUBLIC_KEY_LEN]>,
    send_key: Option<[u8; SYMMETRIC_KEY_LEN]>,
    recv_key: Option<[u8; SYMMETRIC_KEY_LEN]>,
}

impl Handshake {
    /// Returns the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
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
    /// needed (initiator receiving ServerFinish).
    ///
    /// Returns `Ok(Some(bytes))` when a reply should be sent to the peer.
    pub fn handle_message(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, FengniError> {
        let msg: FengniMessage = crate::wire::decode(raw)?;

        match (self.state, msg.variant) {
            // ── Responder receives Hello → sends HelloReply ──
            (
                HandshakeState::ExpectHello,
                Some(Variant::Hello(Hello {
                    ephemeral_public,
                    timestamp,
                })),
            ) => {
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

                let peer_ephemeral: [u8; PUBLIC_KEY_LEN] = ephemeral_public
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?;
                self.peer_ephemeral_public = Some(peer_ephemeral);

                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&ee, HKDF_INFO_HELLO)?;

                // Session token: encrypt(our_identity_pub || timestamp)
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

            // ── Initiator receives HelloReply → sends Authenticate ──
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

                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&ee, HKDF_INFO_HELLO)?;

                // Decrypt and verify session token
                let nonce = [0u8; crypto::NONCE_LEN];
                let token_plaintext = crypto::decrypt(&hk, &nonce, &session_token)?;
                if token_plaintext.len() < PUBLIC_KEY_LEN {
                    return Err(HandshakeError::Malformed.into());
                }
                let claimed_identity: [u8; PUBLIC_KEY_LEN] =
                    token_plaintext[..PUBLIC_KEY_LEN].try_into().unwrap();

                // Verify responder identity matches pinned key
                if let Some(expected) = &self.peer_identity_public {
                    if claimed_identity != *expected {
                        return Err(HandshakeError::IdentityRejected.into());
                    }
                }
                self.peer_identity_public = Some(claimed_identity);

                // Build HMAC proof: HMAC-SHA256(hk, our_identity_pub || PROOF_CONTEXT)
                let proof: [u8; crypto::HMAC_TAG_LEN] = crypto::hmac_sha256(
                    &hk,
                    &[&self.identity.public_key_bytes(), PROOF_CONTEXT],
                );

                self.state = HandshakeState::ExpectServerFinish;

                let auth = Authenticate {
                    identity_public: self.identity.public_key_bytes().to_vec().into(),
                    proof: proof.to_vec().into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::Authenticate(auth)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // ── Responder receives Authenticate → sends ServerFinish ──
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

                let peer_ephemeral = self
                    .peer_ephemeral_public
                    .ok_or(FengniError::State("no peer ephemeral".into()))?;

                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&ee, HKDF_INFO_HELLO)?;

                // Verify HMAC proof
                let proof_bytes: [u8; crypto::HMAC_TAG_LEN] = proof
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed)?;
                if !crypto::hmac_verify(
                    &hk,
                    &[&peer_identity, PROOF_CONTEXT],
                    &proof_bytes,
                ) {
                    return Err(HandshakeError::IdentityRejected.into());
                }

                // Accept peer identity. Precompute ss.
                self.peer_identity_public = Some(peer_identity);
                self.identity.pin_peer(&peer_identity);

                // Quadruple DH session key derivation:
                //   ee = ECDH(our_ephem,    peer_ephem)    ← FS
                //   es = ECDH(our_ephem,    peer_static)    ← FS + auth
                //   se = ECDH(our_static,   peer_ephem)    ← auth
                //   ss = ECDH(our_static,   peer_static)    ← KCI resistance
                let es = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_identity),
                );
                let se = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let ss = self
                    .identity
                    .static_shared()
                    .ok_or(FengniError::State("ss not precomputed".into()))?;

                let combined = sort_and_concat(&[&ee, &es, &se, &ss]);

                // Derive send/recv keys from the combined material.
                // Initiator: send=HKDF(combined, "send"), recv=HKDF(combined, "recv")
                // Responder: send=HKDF(combined, "recv"), recv=HKDF(combined, "send")
                let sk1 = crypto::derive_key(&combined, HKDF_INFO_SEND)?;
                let sk2 = crypto::derive_key(&combined, HKDF_INFO_RECV)?;
                // Responder gives sk1 to initiator as send, and keeps sk2 as send
                // Initiator gets sk1 → recv_key, sk2 → send_key
                // Responder: send_key = sk1, recv_key = sk2
                // But initiator takes sk2 as send_key and sk1 as recv_key
                // We are the responder here.
                self.send_key = Some(sk1);
                self.recv_key = Some(sk2);

                // Build ServerFinish under recv_key (initiator's send_key, i.e., sk2)
                let nonce = [0u8; crypto::NONCE_LEN];
                let finish_plaintext = b"fengni-handshake-complete";
                // For ServerFinish, we encrypt with the session confirmation key.
                // Use a dedicated label.
                let confirm_key = crypto::derive_key(&combined, b"fengni-v1-handshake-confirm")?;
                let finish_payload = crypto::encrypt(&confirm_key, &nonce, finish_plaintext)?;

                self.state = HandshakeState::Completed;

                let finish = ServerFinish {
                    payload: finish_payload.into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::ServerFinish(finish)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // ── Initiator receives ServerFinish → derives send/recv keys ──
            (
                HandshakeState::ExpectServerFinish,
                Some(Variant::ServerFinish(ServerFinish { payload })),
            ) => {
                let peer_ephemeral = self
                    .peer_ephemeral_public
                    .ok_or(FengniError::State("no peer ephemeral".into()))?;
                let peer_identity = self
                    .peer_identity_public
                    .ok_or(FengniError::State("no peer identity".into()))?;

                // Compute ss now that we know peer identity.
                self.identity.pin_peer(&peer_identity);

                // Quadruple DH (same as responder).
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let es = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_identity),
                );
                let se = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let ss = self
                    .identity
                    .static_shared()
                    .ok_or(FengniError::State("ss not precomputed".into()))?;

                let combined = sort_and_concat(&[&ee, &es, &se, &ss]);

                let sk1 = crypto::derive_key(&combined, HKDF_INFO_SEND)?;
                let sk2 = crypto::derive_key(&combined, HKDF_INFO_RECV)?;
                // Initiator: send_key = sk2, recv_key = sk1
                // (mirror of responder)

                // Verify ServerFinish
                let confirm_key = crypto::derive_key(&combined, b"fengni-v1-handshake-confirm")?;
                let nonce = [0u8; crypto::NONCE_LEN];
                let plaintext = crypto::decrypt(&confirm_key, &nonce, &payload)
                    .map_err(|_| HandshakeError::IdentityRejected)?;
                if plaintext != b"fengni-handshake-complete" {
                    return Err(HandshakeError::IdentityRejected.into());
                }

                self.send_key = Some(sk2);
                self.recv_key = Some(sk1);
                self.state = HandshakeState::Completed;

                Ok(None)
            }

            _ => Err(HandshakeError::UnexpectedMessage.into()),
        }
    }

    /// Consume the handshake and return a [`TransportState`] for data encryption.
    ///
    /// Returns an error if the handshake has not completed.
    pub fn into_transport(self) -> Result<TransportState, FengniError> {
        if !self.state.is_completed() {
            return Err(FengniError::State("handshake not completed".into()));
        }
        let send_key = self
            .send_key
            .ok_or(FengniError::State("no send key".into()))?;
        let recv_key = self
            .recv_key
            .ok_or(FengniError::State("no recv key".into()))?;
        Ok(TransportState::new(CipherStates {
            send: crypto::CipherState::new(&send_key),
            recv: crypto::CipherState::new(&recv_key),
        }))
    }
}

fn sort_and_concat(shares: &[&[u8; PUBLIC_KEY_LEN]]) -> Vec<u8> {
    let mut sorted: Vec<&&[u8; PUBLIC_KEY_LEN]> = shares.iter().collect();
    sorted.sort_by_key(|s| s.as_slice());
    let mut combined = Vec::with_capacity(PUBLIC_KEY_LEN * shares.len());
    for s in &sorted {
        combined.extend_from_slice(s.as_slice());
    }
    combined
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
    fn builder_initiator() {
        let alice = KeyPair::generate();
        let bob_pub = KeyPair::generate().public_key_bytes();
        let hs = HandshakeBuilder::initiator(alice, bob_pub).build();
        assert_eq!(hs.state(), HandshakeState::ExpectHelloReply);
        assert!(hs.identity.static_shared().is_some());
    }

    #[test]
    fn builder_responder() {
        let bob = KeyPair::generate();
        let hs = HandshakeBuilder::responder(bob).build();
        assert_eq!(hs.state(), HandshakeState::ExpectHello);
    }

    #[test]
    fn full_handshake_succeeds() {
        let mut alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();

        let bob_pub = bob_key.public_key_bytes();
        alice_key.pin_peer(&bob_pub);

        let mut hs_a = HandshakeBuilder::initiator(alice_key.clone(), bob_pub).build();
        assert_eq!(hs_a.state(), HandshakeState::ExpectHelloReply);

        let hello = hs_a.send_hello().unwrap();
        assert!(!hello.is_empty());

        let mut hs_b = HandshakeBuilder::responder(bob_key.clone()).build();
        assert_eq!(hs_b.state(), HandshakeState::ExpectHello);

        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        assert_eq!(hs_b.state(), HandshakeState::ExpectAuthenticate);

        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        assert_eq!(hs_a.state(), HandshakeState::ExpectServerFinish);

        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        assert_eq!(hs_b.state(), HandshakeState::Completed);

        let done = hs_a.handle_message(&finish).unwrap();
        assert!(done.is_none());
        assert_eq!(hs_a.state(), HandshakeState::Completed);

        // Transition to transport and verify send/recv keys work
        let transport_a = hs_a.into_transport().unwrap();
        let transport_b = hs_b.into_transport().unwrap();

        // Alice sends to Bob
        let ct = transport_a.send(b"hello bob").unwrap();
        let pt = transport_b.recv(&ct).unwrap();
        assert_eq!(pt, b"hello bob");

        // Bob sends to Alice
        let ct = transport_b.send(b"hello alice").unwrap();
        let pt = transport_a.recv(&ct).unwrap();
        assert_eq!(pt, b"hello alice");
    }

    #[test]
    fn wrong_peer_identity_rejected() {
        let mut alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let mallory_key = KeyPair::generate();

        let bob_pub = bob_key.public_key_bytes();
        alice_key.pin_peer(&bob_pub);

        let mut hs_a = HandshakeBuilder::initiator(alice_key, bob_pub).build();
        let hello = hs_a.send_hello().unwrap();

        let mut hs_m = HandshakeBuilder::responder(mallory_key).build();
        let reply = hs_m.handle_message(&hello).unwrap().unwrap();

        let result = hs_a.handle_message(&reply);
        assert!(result.is_err());
    }

    #[test]
    fn expired_timestamp_rejected() {
        let bob_key = KeyPair::generate();
        let mut hs_b = HandshakeBuilder::responder(bob_key).build();

        let hello = FengniMessage {
            variant: Some(Variant::Hello(Hello {
                ephemeral_public: KeyPair::generate().public_key_bytes().to_vec().into(),
                timestamp: 0,
            })),
        };
        let raw = crate::wire::encode(&hello).unwrap();

        let result = hs_b.handle_message(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn unexpected_message_rejected() {
        let bob_key = KeyPair::generate();
        let mut hs_b = HandshakeBuilder::responder(bob_key).build();

        let auth = FengniMessage {
            variant: Some(Variant::Authenticate(Authenticate {
                identity_public: KeyPair::generate().public_key_bytes().to_vec().into(),
                proof: vec![0u8; 32].into(),
            })),
        };
        let raw = crate::wire::encode(&auth).unwrap();

        let result = hs_b.handle_message(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn into_transport_before_completion_fails() {
        let alice = KeyPair::generate();
        let bob_pub = KeyPair::generate().public_key_bytes();
        let hs = HandshakeBuilder::initiator(alice, bob_pub).build();
        let result = hs.into_transport();
        assert!(result.is_err());
    }
}
