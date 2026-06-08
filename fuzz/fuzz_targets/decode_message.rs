/// Fuzz target for `fengni::wire::decode()`.
///
/// Verifies that wire format decoding never panics on arbitrary input.
/// Pattern from quinn's `fuzz_targets/packet.rs`.
///
/// Run with:
///   cargo +nightly fuzz run decode_message
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Verify decode() never panics on arbitrary input.
    // It may return Err for malformed input — that's expected.
    let _ = fengni::wire::decode(data);
});
