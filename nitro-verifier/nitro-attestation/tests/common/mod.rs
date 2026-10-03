use base64::Engine;
use base64::engine::general_purpose::STANDARD;

#[must_use]
pub fn report() -> Vec<u8> {
    decode(include_str!("../../testdata/nitro-report-b64.txt"))
}

#[must_use]
pub fn debug_report() -> Vec<u8> {
    decode(include_str!("../../testdata/nitro-report-debug-b64.txt"))
}

fn decode(b64: &str) -> Vec<u8> {
    STANDARD.decode(b64.trim()).expect("decoding fixture")
}
