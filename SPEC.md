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
| Identity hiding | ✅ v0.3.0 — initiator identity encrypted in Authenticate |
| Replay protection | ✅ v0.3.0 — Timestamp-based, ±60s window; v0.4.0 — bitmap-based data channel replay protection |
| Forward secrecy | ✅ Quadruple DH (ee + es + se + ss) |
| Zero-copy output | ✅ v0.4.0 — AeadInPlace (no internal heap allocation) |
| AEAD safety boundaries | ✅ v0.4.0 — confidentiality_limit, integrity_limit exposed |

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

### Session Key (Quadruple DH)

```
ee = X25519(ephemeral_alice, ephemeral_bob)
es = X25519(ephemeral_alice, static_bob)
se = X25519(static_alice,    ephemeral_bob)
ss = X25519(static_alice,    static_bob)     ← KCI resistance

combined = sorted(ee, es, se, ss)
send_key = HKDF-SHA256(ikm=combined, info="fengni-v1-transport-send")
recv_key = HKDF-SHA256(ikm=combined, info="fengni-v1-transport-recv")
```

## Wire Format

All messages are encoded as `FengniMessage` (protobuf oneof).
See `proto/fengni.proto` for the canonical message definitions.

## Security Considerations

### Nonce Management

Each handshake generates a fresh ephemeral key pair, making the derived
handshake key unique per session. Therefore, a fixed nonce of all-zeros
is safe for the handshake messages.

**Data packets**: Post-handshake data packets use the `CipherState` nonce
counter, which auto-increments after each encryption/decryption. Nonce
`u64::MAX` is reserved for `rekey()` per Noise spec Section 4.2.

### Replay Protection (v0.4.0)

Received data packets are protected by a bitmap-based sliding window:

- **Window size**: 1024 packets (16 × 64-bit words)
- **Pre-check**: Before decryption, `will_accept(counter)` verifies the
  nonce is not a replay — avoiding expensive AEAD operations on
  duplicate/too-old packets
- **Post-check**: After successful decryption, `mark_did_receive(counter)`
  commits the nonce and advances the window
- **Out-of-order tolerance**: Packets within the 1024-packet window are
  accepted even if they arrive out of order
- **Too-old rejection**: Packets older than 1024 behind the current
  highest nonce are rejected

Pattern from boringtun's `ReceivingKeyCounterValidator`.

### Timestamp Replay Window

A ±60-second clock skew window is allowed for handshake messages. Peers
outside this window receive a `TimestampExpired` error and should
synchronize clocks before retrying.

### AEAD Safety Boundaries (v0.4.0)

Per RFC 9001 §6.6 and draft-irtf-cfrg-aead-limits §5.2.1:

| Limit | Value | Meaning |
|---|---|---|
| Confidentiality | `u64::MAX` | ChaCha20-Poly1305 with sequential nonces has no practical limit |
| Integrity | `2^36` (~68.7B) | Max failed decryptions before key MUST be retired |

`TransportState` tracks `authentication_failures` — callers should monitor
this and close the connection when it approaches the integrity limit.
