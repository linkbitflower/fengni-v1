# Fengni Protocol Specification

**Status: Draft v0.1.0**

## Abstract

Fengni is a mutual-authenticated key exchange protocol built on X25519 and
ChaCha20-Poly1305. It establishes a shared symmetric session key between two
peers with mutual identity verification.

## Protocol Properties

| Property | Status |
|---|---|
| Mutual authentication | ✅ Both peers prove possession of their static key |
| Forward secrecy | ✅ Compromise of static keys does not reveal past sessions |
| Key compromise impersonation resistance | ❌ Not yet analyzed |
| Identity hiding | ❌ Identities transmitted in plaintext |
| Replay protection | ✅ Timestamp-based, ±60s window |

## Cryptographic Primitives

- **Key exchange**: X25519 ECDH (RFC 7748)
- **AEAD**: ChaCha20-Poly1305 (RFC 8439)
- **KDF**: HKDF-SHA256 (RFC 5869)
- **Serialization**: Protocol Buffers v3

## Handshake Flow

```
Initiator (Alice)                        Responder (Bob)
     |                                        |
     |  Hello                                |
     |  {ephemeral_pub_alice, timestamp}     |
     | ------------------------------------> |
     |                                        |
     |                      HelloReply       |
     |  {ephemeral_pub_bob, session_token}   |
     | <------------------------------------ |
     |                                        |
     |  Authenticate                         |
     |  {identity_pub_alice, proof}          |
     | ------------------------------------> |
     |                                        |
     |                      ServerFinish     |
     |  {encrypted_confirmation}             |
     | <------------------------------------ |
     |                                        |
     |===== session_key established ==========|
```

## Key Derivation

### Handshake Key

```
shared_ee = X25519(ephemeral_alice, ephemeral_bob)
handshake_key = HKDF-SHA256(ikm=shared_ee, info="fengni-v1-handshake-hello")
```

### Session Key (Triple DH)

```
ee = X25519(ephemeral_alice, ephemeral_bob)
se = X25519(static_alice,    ephemeral_bob)
es = X25519(ephemeral_alice, static_bob)

combined = sorted(ee, es, se) || ee || es || se
session_key = HKDF-SHA256(ikm=combined, info="fengni-v1-handshake-session")
```

## Wire Format

All messages are encoded as `FengniMessage` (protobuf oneof).
See `proto/fengni.proto` for the canonical message definitions.

## Security Considerations

### Nonce Management

Each handshake generates a fresh ephemeral key pair, making the derived
handshake key unique per session. Therefore, a fixed nonce of all-zeros
is safe for the handshake messages.

**Data packets**: Post-handshake data packets MUST use unique,
monotonically increasing nonces. The library enforces this via the
`sequence` field in `DataPacket`.

### Timestamp Replay Window

A ±60-second clock skew window is allowed. Peers outside this window
receive a `TimestampExpired` error and should synchronize clocks before
retrying.
