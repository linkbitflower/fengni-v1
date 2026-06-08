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

/// HKDF info label for identity encryption in Authenticate message.
const HKDF_INFO_IDENTITY_HIDE: &[u8] = b"fengni-v1-auth-identity";

/// Maximum allowed clock skew in seconds.
const CLOCK_SKEW_SECS: u64 = 60;


// --- Handshake State ---

/// The state of a handshake.
///
/// Each variant carries only the data relevant to that phase.
/// No `Option<>` fields — the type system guarantees data is present
/// when the state matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for the initiator's Hello.
    ExpectHello,
    /// Waiting for the responder's HelloReply.
    /// Carries the pinned peer static public key for identity verification.
    ExpectHelloReply {
        peer_static_public: [u8; PUBLIC_KEY_LEN],
    },
    /// Waiting for the initiator's Authenticate.
    ExpectAuthenticate {
        peer_ephemeral_public: [u8; PUBLIC_KEY_LEN],
    },
    /// Waiting for the responder's ServerFinish.
    ExpectServerFinish {
        peer_ephemeral_public: [u8; PUBLIC_KEY_LEN],
        peer_identity_public: [u8; PUBLIC_KEY_LEN],
    },
    /// Handshake is complete; send/recv keys are established.
    Completed {
        send_key: [u8; SYMMETRIC_KEY_LEN],
        recv_key: [u8; SYMMETRIC_KEY_LEN],
    },
}

impl HandshakeState {
    /// Returns true if the handshake has completed.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

/// A Fengni protocol handshake builder.
///
/// Validates inputs before the handshake starts.
pub struct HandshakeBuilder {
    identity: KeyPair,
    peer_static_public: Option<[u8; PUBLIC_KEY_LEN]>,
    is_initiator: bool,
    prologue: Vec<u8>,
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
            prologue: Vec::new(),
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
            prologue: Vec::new(),
        }
    }

    /// Set an optional prologue for cross-protocol key isolation.
    ///
    /// The prologue is prefixed to every HKDF info label in the handshake,
    /// ensuring that keys derived under different prologues are independent.
    /// Both peers must agree on the prologue; a mismatch causes decryption
    /// failure.
    ///
    /// Pattern from snow's `Builder::prologue()` and the TLS 1.3 `"tls13 "`
    /// label prefix.
    pub fn prologue(mut self, data: &[u8]) -> Self {
        self.prologue = data.to_vec();
        self
    }

    /// Build the handshake state machine.
    pub fn build(self) -> Handshake {
        let state = if self.is_initiator {
            HandshakeState::ExpectHelloReply {
                peer_static_public: self
                    .peer_static_public
                    .expect("initiator requires peer_static_public"),
            }
        } else {
            HandshakeState::ExpectHello
        };
        Handshake {
            state,
            identity: self.identity,
            ephemeral: KeyPair::generate(),
            prologue: self.prologue,
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
    /// Optional prologue prefixed to every HKDF info label.
    prologue: Vec<u8>,
}

impl Handshake {
    /// Returns the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Build an HKDF info label with the optional prologue prefix.
    ///
    /// Example: `self.info(b"fengni-v1-handshake-hello")` returns
    /// `prologue || b"fengni-v1-handshake-hello"` if a prologue is set,
    /// or just the suffix if empty.
    fn info(&self, suffix: &[u8]) -> Vec<u8> {
        if self.prologue.is_empty() {
            suffix.to_vec()
        } else {
            let mut v = Vec::with_capacity(self.prologue.len() + suffix.len());
            v.extend_from_slice(&self.prologue);
            v.extend_from_slice(suffix);
            v
        }
    }

    /// Build and return the Hello message.
    ///
    /// Only valid in [`HandshakeState::ExpectHelloReply`] (initiator).
    pub fn send_hello(&mut self) -> Result<Vec<u8>, FengniError> {
        let _peer_static = match &self.state {
            HandshakeState::ExpectHelloReply { .. } => {}
            _ => return Err(HandshakeError::AlreadyCompleted.into()),
        };

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

    /// Build and write the Hello message into a caller-provided buffer.
    ///
    /// Returns the number of bytes written. Use [`FengniMessage::encoded_len`]
    /// on a Hello message to determine the required buffer size.
    ///
    /// Only valid in [`HandshakeState::ExpectHelloReply`] (initiator).
    pub fn send_hello_into(&mut self, buf: &mut [u8]) -> Result<usize, FengniError> {
        let _peer_static = match &self.state {
            HandshakeState::ExpectHelloReply { .. } => {}
            _ => return Err(HandshakeError::AlreadyCompleted.into()),
        };

        let hello = Hello {
            ephemeral_public: self.ephemeral.public_key_bytes().to_vec().into(),
            timestamp: current_timestamp(),
        };
        let msg = FengniMessage {
            variant: Some(Variant::Hello(hello)),
        };

        Ok(crate::wire::encode_into(&msg, buf)?)
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
                    .map_err(|_| HandshakeError::Malformed { context: "Hello.ephemeral_public" })?;

                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&ee, &self.info(HKDF_INFO_HELLO))?;

                // Session token: encrypt(our_identity_pub || timestamp)
                let token_plaintext = {
                    let mut v = self.identity.public_key_bytes().to_vec();
                    v.extend_from_slice(&current_timestamp().to_be_bytes());
                    v
                };
                let nonce = [0u8; crypto::NONCE_LEN];
                let session_token = crypto::encrypt(&hk, &nonce, &token_plaintext)?;

                self.state = HandshakeState::ExpectAuthenticate {
                    peer_ephemeral_public: peer_ephemeral,
                };

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
                HandshakeState::ExpectHelloReply { peer_static_public },
                Some(Variant::HelloReply(HelloReply {
                    ephemeral_public,
                    session_token,
                })),
            ) => {
                let peer_ephemeral: [u8; PUBLIC_KEY_LEN] = ephemeral_public
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed { context: "HelloReply.ephemeral_public" })?;


                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral),
                );
                let hk = crypto::derive_key(&ee, &self.info(HKDF_INFO_HELLO))?;

                // Decrypt and verify session token
                let nonce = [0u8; crypto::NONCE_LEN];
                let token_plaintext = crypto::decrypt(&hk, &nonce, &session_token)?;
                if token_plaintext.len() < PUBLIC_KEY_LEN {
                    return Err(HandshakeError::Malformed { context: "session token too short" }.into());
                }
                let claimed_identity: [u8; PUBLIC_KEY_LEN] =
                    token_plaintext[..PUBLIC_KEY_LEN].try_into().unwrap();

                // Verify responder identity matches pinned key
                if claimed_identity != peer_static_public {
                        return Err(HandshakeError::IdentityRejected { reason: "public key mismatch" }.into());
                }
                

                // Build HMAC proof: HMAC-SHA256(hk, our_identity_pub || PROOF_CONTEXT)
                let proof: [u8; crypto::HMAC_TAG_LEN] = crypto::hmac_sha256(
                    &hk,
                    &[&self.identity.public_key_bytes(), PROOF_CONTEXT],
                );

                // Encrypt identity with es = DH(our_ephem, peer_static)
                // Only the intended responder can decrypt this.
                let es_id = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_static_public),
                );
                let identity_key = crypto::derive_key(&es_id, &self.info(HKDF_INFO_IDENTITY_HIDE))?;
                let nonce = [0u8; crypto::NONCE_LEN];
                let encrypted_identity = crypto::encrypt(
                    &identity_key,
                    &nonce,
                    &self.identity.public_key_bytes(),
                )?;

                self.state = HandshakeState::ExpectServerFinish {
                    peer_ephemeral_public: peer_ephemeral,
                    peer_identity_public: claimed_identity,
                };

                let auth = Authenticate {
                    identity_public: encrypted_identity.into(),
                    proof: proof.to_vec().into(),
                };

                let msg = FengniMessage {
                    variant: Some(Variant::Authenticate(auth)),
                };

                Ok(Some(crate::wire::encode(&msg)?))
            }

            // ── Responder receives Authenticate → sends ServerFinish ──
            (
                HandshakeState::ExpectAuthenticate { peer_ephemeral_public },
                Some(Variant::Authenticate(Authenticate {
                    identity_public,
                    proof,
                })),
            ) => {
                // Decrypt identity: DH(our_static, peer_ephemeral) = DH(peer_ephem, our_static)
                // Only the initiator who knows our public key could have encrypted this.
                let se_id = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral_public),
                );
                let identity_key = crypto::derive_key(&se_id, &self.info(HKDF_INFO_IDENTITY_HIDE))?;
                let nonce = [0u8; crypto::NONCE_LEN];
                let decrypted_id = crypto::decrypt(&identity_key, &nonce, &identity_public)
                    .map_err(|_| HandshakeError::IdentityRejected { reason: "identity decryption failed" })?;
                let peer_identity: [u8; PUBLIC_KEY_LEN] = decrypted_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed { context: "Authenticate.identity_public" })?;


                // ee = ECDH(our_ephem, peer_ephem)
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral_public),
                );
                let hk = crypto::derive_key(&ee, &self.info(HKDF_INFO_HELLO))?;

                // Verify HMAC proof
                let proof_bytes: [u8; crypto::HMAC_TAG_LEN] = proof
                    .as_ref()
                    .try_into()
                    .map_err(|_| HandshakeError::Malformed { context: "Authenticate.proof" })?;
                if !crypto::hmac_verify(
                    &hk,
                    &[&peer_identity, PROOF_CONTEXT],
                    &proof_bytes,
                ) {
                    return Err(HandshakeError::IdentityRejected { reason: "HMAC proof invalid" }.into());
                }

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
                    &x25519_dalek::PublicKey::from(peer_ephemeral_public),
                );
                // Compute ss locally — defer pin_peer until all ops succeed.
                let ss = *self.identity.secret()
                    .diffie_hellman(&x25519_dalek::PublicKey::from(peer_identity))
                    .as_bytes();

                let combined = sort_and_concat(&[&ee, &es, &se, &ss]);

                // Derive send/recv keys from the combined material.
                let sk1 = crypto::derive_key(&combined, &self.info(HKDF_INFO_SEND))?;
                let sk2 = crypto::derive_key(&combined, &self.info(HKDF_INFO_RECV))?;

                // Build ServerFinish under recv_key (initiator's send_key, i.e., sk2)
                let nonce = [0u8; crypto::NONCE_LEN];
                let finish_plaintext = b"fengni-handshake-complete";
                // For ServerFinish, we encrypt with the session confirmation key.
                // Use a dedicated label.
                let confirm_key = crypto::derive_key(&combined, &self.info(b"fengni-v1-handshake-confirm"))?;
                let finish_payload = crypto::encrypt(&confirm_key, &nonce, finish_plaintext)?;

                // All computations succeeded — now commit.
                self.identity.pin_peer(&peer_identity);
                self.state = HandshakeState::Completed {
                    send_key: sk1,
                    recv_key: sk2,
                };

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
                HandshakeState::ExpectServerFinish {
                    peer_ephemeral_public,
                    peer_identity_public,
                },
                Some(Variant::ServerFinish(ServerFinish { payload })),
            ) => {

                // Quadruple DH (same as responder).
                let ee = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral_public),
                );
                let es = crypto::diffie_hellman(
                    self.ephemeral.secret(),
                    &x25519_dalek::PublicKey::from(peer_identity_public),
                );
                let se = crypto::diffie_hellman(
                    self.identity.secret(),
                    &x25519_dalek::PublicKey::from(peer_ephemeral_public),
                );
                // Compute ss locally — defer pin_peer until all ops succeed.
                let ss = *self.identity.secret()
                    .diffie_hellman(&x25519_dalek::PublicKey::from(peer_identity_public))
                    .as_bytes();

                let combined = sort_and_concat(&[&ee, &es, &se, &ss]);

                let sk1 = crypto::derive_key(&combined, &self.info(HKDF_INFO_SEND))?;
                let sk2 = crypto::derive_key(&combined, &self.info(HKDF_INFO_RECV))?;
                // Initiator: send_key = sk2, recv_key = sk1
                // (mirror of responder)

                // Verify ServerFinish
                let confirm_key = crypto::derive_key(&combined, &self.info(b"fengni-v1-handshake-confirm"))?;
                let nonce = [0u8; crypto::NONCE_LEN];
                let plaintext = crypto::decrypt(&confirm_key, &nonce, &payload)
                    .map_err(|_| HandshakeError::IdentityRejected { reason: "ServerFinish decryption failed" })?;
                if plaintext != b"fengni-handshake-complete" {
                    return Err(HandshakeError::IdentityRejected { reason: "ServerFinish confirm failed" }.into());
                }

                // All computations succeeded — now commit.
                self.identity.pin_peer(&peer_identity_public);
                self.state = HandshakeState::Completed {
                    send_key: sk2,
                    recv_key: sk1,
                };

                Ok(None)
            }

            _ => Err(HandshakeError::UnexpectedMessage { expected: self.state }.into()),
        }
    }

    /// Consume the handshake and return a [`TransportState`] for data encryption.
    ///
    /// Returns an error if the handshake has not completed.
    pub fn into_transport(self) -> Result<TransportState, FengniError> {
        match self.state {
            HandshakeState::Completed { send_key, recv_key } => {
                Ok(TransportState::new(CipherStates {
                    send: crypto::CipherState::new(&send_key),
                    recv: crypto::CipherState::new(&recv_key),
                }))
            }
            _ => Err(FengniError::State("handshake not completed".into())),
        }
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
        assert!(matches!(hs.state(), HandshakeState::ExpectHelloReply { .. }));
        assert!(hs.identity.ss.is_some());
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
        assert!(matches!(hs_a.state(), HandshakeState::ExpectHelloReply { .. }));

        let hello = hs_a.send_hello().unwrap();
        assert!(!hello.is_empty());

        let mut hs_b = HandshakeBuilder::responder(bob_key.clone()).build();
        assert_eq!(hs_b.state(), HandshakeState::ExpectHello);

        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        assert!(matches!(hs_b.state(), HandshakeState::ExpectAuthenticate { .. }));

        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        assert!(matches!(hs_a.state(), HandshakeState::ExpectServerFinish { .. }));

        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        assert!(matches!(hs_b.state(), HandshakeState::Completed { .. }));

        let done = hs_a.handle_message(&finish).unwrap();
        assert!(done.is_none());
        assert!(matches!(hs_a.state(), HandshakeState::Completed { .. }));

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

    #[test]
    fn transport_replay_rejects_duplicate() {
        // Complete a handshake
        let mut alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let bob_pub = bob_key.public_key_bytes();
        alice_key.pin_peer(&bob_pub);

        let mut hs_a = HandshakeBuilder::initiator(alice_key, bob_pub).build();
        let mut hs_b = HandshakeBuilder::responder(bob_key).build();

        let hello = hs_a.send_hello().unwrap();
        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        let _finish = hs_b.handle_message(&auth).unwrap().unwrap();
        hs_a.handle_message(&_finish).unwrap();

        let transport_a = hs_a.into_transport().unwrap();
        let transport_b = hs_b.into_transport().unwrap();

        // First message works
        let ct = transport_a.send(b"msg 1").unwrap();
        let pt = transport_b.recv(&ct).unwrap();
        assert_eq!(pt, b"msg 1");

        // Replaying the same ciphertext should fail (nonce already consumed)
        let result = transport_b.recv(&ct);
        assert!(result.is_err());
    }

    #[test]
    fn transport_auth_failures_increment() {
        // Complete a handshake
        let mut alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let bob_pub = bob_key.public_key_bytes();
        alice_key.pin_peer(&bob_pub);

        let mut hs_a = HandshakeBuilder::initiator(alice_key, bob_pub).build();
        let mut hs_b = HandshakeBuilder::responder(bob_key).build();

        let hello = hs_a.send_hello().unwrap();
        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        hs_a.handle_message(&finish).unwrap();

        let transport_a = hs_a.into_transport().unwrap();
        let transport_b = hs_b.into_transport().unwrap();

        // Send a valid message first
        let ct = transport_a.send(b"valid").unwrap();
        let _ = transport_b.recv(&ct).unwrap();

        // Try to decrypt garbage — should fail and increment auth_failures
        assert_eq!(transport_b.auth_failures(), 0);
        let garbage = vec![0xCCu8; 32];
        let result = transport_b.recv(&garbage);
        assert!(result.is_err());
        assert_eq!(transport_b.auth_failures(), 1);
    }

    #[test]
    fn transport_integrity_limit_is_defined() {
        // ChaCha20-Poly1305 integrity limit per RFC 9001 §6.6
        assert_eq!(TransportState::integrity_limit(), 1 << 36);
        assert_eq!(TransportState::confidentiality_limit(), u64::MAX);
    }

    #[test]
    fn prologue_mismatch_causes_handshake_failure() {
        let mut ak = KeyPair::generate();
        let bk = KeyPair::generate();
        let bp = bk.public_key_bytes();
        ak.pin_peer(&bp);

        // Alice uses prologue "alice-v1", Bob uses "bob-v1" — must fail
        let mut hs_a = HandshakeBuilder::initiator(ak, bp)
            .prologue(b"alice-v1")
            .build();
        let mut hs_b = HandshakeBuilder::responder(bk)
            .prologue(b"bob-v1")
            .build();

        let hello = hs_a.send_hello().unwrap();
        // Bob's hello_key is derived with different prologue → decryption will fail
        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        // Alice tries to process with different prologue → must fail
        let result = hs_a.handle_message(&reply);
        assert!(result.is_err());
    }

    #[test]
    fn prologue_match_handshake_succeeds() {
        let mut ak = KeyPair::generate();
        let bk = KeyPair::generate();
        let bp = bk.public_key_bytes();
        ak.pin_peer(&bp);

        let mut hs_a = HandshakeBuilder::initiator(ak, bp)
            .prologue(b"shared-prologue")
            .build();
        let mut hs_b = HandshakeBuilder::responder(bk)
            .prologue(b"shared-prologue")
            .build();

        let hello = hs_a.send_hello().unwrap();
        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        hs_a.handle_message(&finish).unwrap();

        // Verify transport works
        let ta = hs_a.into_transport().unwrap();
        let tb = hs_b.into_transport().unwrap();
        let ct = ta.send(b"prologue test").unwrap();
        let pt = tb.recv(&ct).unwrap();
        assert_eq!(pt, b"prologue test");
    }

    #[test]
    fn stateless_transport_roundtrip() {
        // Complete a handshake
        let mut ak = KeyPair::generate();
        let bk = KeyPair::generate();
        let bp = bk.public_key_bytes();
        ak.pin_peer(&bp);

        let mut hs_a = HandshakeBuilder::initiator(ak, bp).build();
        let mut hs_b = HandshakeBuilder::responder(bk).build();

        let hello = hs_a.send_hello().unwrap();
        let reply = hs_b.handle_message(&hello).unwrap().unwrap();
        let auth = hs_a.handle_message(&reply).unwrap().unwrap();
        let finish = hs_b.handle_message(&auth).unwrap().unwrap();
        hs_a.handle_message(&finish).unwrap();

        let ta = hs_a.into_transport().unwrap();
        let tb = hs_b.into_transport().unwrap();

        // Stateless send/recv with explicit nonces
        let msg = b"stateless test message";
        let ct = ta.send_with_nonce(42, msg).unwrap();
        let pt = tb.recv_with_nonce(42, &ct).unwrap();
        assert_eq!(pt, msg);

        // Replay of same nonce should be rejected
        assert!(tb.recv_with_nonce(42, &ct).is_err());
    }

    #[test]
    fn stateless_zero_copy_roundtrip() {
        let key = [0xAAu8; 32];
        let cs = crate::crypto::CipherState::new(&key);
        let pt = b"stateless zero-copy";

        let mut ct_buf = vec![0u8; pt.len() + 16];
        let w = cs.encrypt_into_with_nonce(7, pt, &mut ct_buf).unwrap();
        assert_eq!(w, pt.len() + 16);

        let mut pt_buf = vec![0u8; pt.len()];
        let r = cs.decrypt_into_with_nonce(7, &ct_buf[..w], &mut pt_buf).unwrap();
        assert_eq!(r, pt.len());
        assert_eq!(&pt_buf[..r], pt);

        // Internal nonce unchanged by stateless methods
        assert_eq!(cs.nonce(), 0);
    }
}
