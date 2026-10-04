mod common;

use nitro_attestation::{AWS_NITRO_ROOT_SHA256, Error, parse_document, verify, verify_chain};

const NOW_SECS: u64 = 1_749_295_504;
const DEBUG_NOW_SECS: u64 = 1_749_558_205;
const LEAF_NOT_BEFORE: u64 = 1_749_295_179;
const LEAF_NOT_AFTER: u64 = 1_749_305_982;

#[test]
fn verify_happy_path() {
    // given
    let report = common::report();

    // when
    let doc = verify(&report, &AWS_NITRO_ROOT_SHA256, NOW_SECS).expect("verifying report");

    // then
    assert_eq!(doc.user_data.as_deref(), Some(b"Hello, world!".as_slice()));
    assert_eq!(doc.timestamp_ms, 1_749_295_504_541);
}

#[test]
fn verify_happy_path_debug() {
    // given
    let report = common::debug_report();

    // when
    let doc = verify(&report, &AWS_NITRO_ROOT_SHA256, DEBUG_NOW_SECS).expect("verifying report");

    // then
    assert!(doc.is_debug());
}

#[test]
fn verify_happy_path_leaf_boundaries() {
    for now_secs in [LEAF_NOT_BEFORE, LEAF_NOT_AFTER] {
        // given
        let report = common::report();

        // when
        let result = verify(&report, &AWS_NITRO_ROOT_SHA256, now_secs);

        // then
        assert!(result.is_ok(), "now_secs {now_secs}: got {result:?}");
    }
}

#[test]
fn verify_error_times() {
    let cases = [
        ("epoch", 0, 0),
        ("before leaf", LEAF_NOT_BEFORE - 1, 4),
        ("after leaf", LEAF_NOT_AFTER + 1, 4),
        ("after root", 2_600_000_000, 0),
    ];

    for (name, now_secs, want) in cases {
        // given
        let report = common::report();

        // when
        let result = verify(&report, &AWS_NITRO_ROOT_SHA256, now_secs);

        // then
        assert_eq!(
            result,
            Err(Error::CertificateNotValidAt { index: want }),
            "case {name}"
        );
    }
}

#[test]
fn verify_error_wrong_root() {
    // given
    let report = common::report();

    // when
    let result = verify(&report, &[0u8; 32], NOW_SECS);

    // then
    assert_eq!(result, Err(Error::UntrustedRoot));
}

#[test]
fn verify_error_tampered_cose_signature() {
    // given
    let mut report = common::report();
    *report.last_mut().expect("non-empty report") ^= 0x01;

    // when
    let result = verify(&report, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result, Err(Error::InvalidSignature));
}

#[test]
fn verify_error_tampered_payload() {
    // given
    let mut report = common::report();
    let needle = b"Hello, world!";
    let offset = report
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("finding user data");
    report[offset] = b'J';
    assert!(parse_document(&report).is_ok());

    // when
    let result = verify(&report, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result, Err(Error::InvalidSignature));
}

#[test]
fn verify_error_debug_cert_on_prod_doc() {
    // given
    let mut doc = parse_document(&common::report()).expect("parsing document");
    let debug_doc = parse_document(&common::debug_report()).expect("parsing debug document");
    doc.certificate = debug_doc.certificate;

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(
        result.err(),
        Some(Error::CertificateNotValidAt { index: 4 })
    );
}
