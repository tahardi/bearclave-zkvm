mod common;

use nitro_attestation::{
    AWS_NITRO_ROOT_SHA256, Error, parse_document, verify_chain, verify_cose_signature,
};
use p384::ecdsa::SigningKey;

const NOW_SECS: u64 = 1_749_295_504;
const DEBUG_NOW_SECS: u64 = 1_749_558_205;

#[test]
fn verify_cose_signature_happy_path() {
    let cases = [
        ("production", common::report(), NOW_SECS),
        ("debug", common::debug_report(), DEBUG_NOW_SECS),
    ];

    for (name, report, now_secs) in cases {
        // given
        let doc = parse_document(&report).expect("parsing document");
        let key = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, now_secs).expect("verifying chain");

        // when
        let result = verify_cose_signature(&report, &key);

        // then
        assert!(result.is_ok(), "case {name}: got {result:?}");
    }
}

#[test]
fn verify_cose_signature_error_wrong_key() {
    // given
    let report = common::report();
    let key = *SigningKey::random(&mut rand_core::OsRng).verifying_key();

    // when
    let result = verify_cose_signature(&report, &key);

    // then
    assert_eq!(result, Err(Error::InvalidSignature));
}
