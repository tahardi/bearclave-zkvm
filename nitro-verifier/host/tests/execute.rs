use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use host::{decode_journal, execute};
use nitro_attestation::{AWS_NITRO_ROOT_SHA256, NitroJournal, parse_document};

fn decode(b64: &str) -> Vec<u8> {
    STANDARD.decode(b64.trim()).expect("decoding fixture")
}

fn report() -> Vec<u8> {
    decode(include_str!(
        "../../nitro-attestation/testdata/nitro-report-b64.txt"
    ))
}

fn debug_report() -> Vec<u8> {
    decode(include_str!(
        "../../nitro-attestation/testdata/nitro-report-debug-b64.txt"
    ))
}

#[test]
fn execute_happy_path() {
    // given
    let report = report();
    let document = parse_document(&report).expect("parsing document");
    let want =
        NitroJournal::from_document(&document, &AWS_NITRO_ROOT_SHA256).expect("building journal");

    // when
    let session = execute(&report).expect("executing guest");

    // then
    let got = decode_journal(&session.journal).expect("decoding journal");
    assert_eq!(got, want);
}

#[test]
fn execute_error_debug_report() {
    // given
    let report = debug_report();

    // when
    let result = execute(&report);

    // then
    assert!(result.is_err());
}

#[test]
fn execute_error_tampered_signature() {
    // given
    let mut report = report();
    *report.last_mut().expect("non-empty report") ^= 0x01;

    // when
    let result = execute(&report);

    // then
    assert!(result.is_err());
}

#[test]
fn execute_error_empty_input() {
    // given
    let report: &[u8] = &[];

    // when
    let result = execute(report);

    // then
    assert!(result.is_err());
}
