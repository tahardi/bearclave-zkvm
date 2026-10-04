mod common;

use sha2::{Digest, Sha256};

use nitro_attestation::{
    AWS_NITRO_ROOT_SHA256, AttestationDocument, Error, parse_document, verify_chain,
};

const NOW_SECS: u64 = 1_749_295_504;
const DEBUG_NOW_SECS: u64 = 1_749_558_205;
const ECDSA_WITH_SHA384: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA_WITH_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const SECP521R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
const BASIC_CONSTRAINTS_CRITICAL: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
const BASIC_CONSTRAINTS_NOT_CRITICAL: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0x00];
const CA_TRUE: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xff];
const CA_FALSE: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0x00];
const ROOT_KEY_USAGE: &[u8] = &[0x03, 0x02, 0x01, 0x86];
const ROOT_KEY_USAGE_NO_CERT_SIGN: &[u8] = &[0x03, 0x02, 0x01, 0x82];
const PATH_LEN_1: &[u8] = &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01];
const PATH_LEN_0: &[u8] = &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];
const LEAF_KEY_USAGE: &[u8] = &[0x03, 0x02, 0x06, 0xc0];
const LEAF_KEY_USAGE_NO_DIGITAL_SIGNATURE: &[u8] = &[0x03, 0x02, 0x06, 0x40];

fn document() -> AttestationDocument {
    parse_document(&common::report()).expect("parsing document")
}

fn replace_last(der: &mut [u8], from: &[u8], to: &[u8]) {
    let offset = der
        .windows(from.len())
        .rposition(|w| w == from)
        .expect("finding bytes to replace");
    der[offset..offset + to.len()].copy_from_slice(to);
}

#[test]
fn verify_chain_happy_path() {
    let cases = [
        ("production", common::report(), NOW_SECS),
        ("debug", common::debug_report(), DEBUG_NOW_SECS),
    ];

    for (name, report, now_secs) in cases {
        // given
        let doc = parse_document(&report).expect("parsing document");

        // when
        let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, now_secs);

        // then
        assert!(result.is_ok(), "case {name}: got {result:?}");
    }
}

#[test]
fn verify_chain_error_tampered_intermediate_signature() {
    // given
    let mut doc = document();
    *doc.cabundle[2].last_mut().expect("non-empty cert") ^= 0x01;

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(
        result.err(),
        Some(Error::InvalidCertificateSignature { index: 2 })
    );
}

#[test]
fn verify_chain_error_missing_intermediate() {
    // given
    let mut doc = document();
    doc.cabundle.remove(2);

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::IssuerMismatch { index: 2 }));
}

#[test]
fn verify_chain_error_reordered() {
    // given
    let mut doc = document();
    doc.cabundle.swap(1, 2);

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::IssuerMismatch { index: 1 }));
}

#[test]
fn verify_chain_error_root_only_bundle() {
    // given
    let mut doc = document();
    doc.cabundle.truncate(1);

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::IssuerMismatch { index: 1 }));
}

#[test]
fn verify_chain_error_garbage_cert() {
    // given
    let mut doc = document();
    doc.cabundle[1] = vec![0x30, 0x00];

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::ParsingCertificate { index: 1 }));
}

#[test]
fn verify_chain_error_tampered_root() {
    let cases: [(&str, &[u8], &[u8], Error); 4] = [
        (
            "basic constraints not critical",
            BASIC_CONSTRAINTS_CRITICAL,
            BASIC_CONSTRAINTS_NOT_CRITICAL,
            Error::BasicConstraints { index: 0 },
        ),
        (
            "curve secp521r1",
            SECP384R1,
            SECP521R1,
            Error::InvalidPublicKey { index: 0 },
        ),
        (
            "ca false",
            CA_TRUE,
            CA_FALSE,
            Error::BasicConstraints { index: 0 },
        ),
        (
            "no keyCertSign",
            ROOT_KEY_USAGE,
            ROOT_KEY_USAGE_NO_CERT_SIGN,
            Error::KeyUsage { index: 0 },
        ),
    ];

    for (name, from, to, want) in cases {
        // given
        let mut doc = document();
        replace_last(&mut doc.cabundle[0], from, to);
        let pin: [u8; 32] = Sha256::digest(&doc.cabundle[0]).into();

        // when
        let result = verify_chain(&doc, &pin, NOW_SECS);

        // then
        assert_eq!(result.err(), Some(want), "case {name}");
    }
}

#[test]
fn verify_chain_error_unsupported_signature_algorithm() {
    // given
    let mut doc = document();
    replace_last(&mut doc.cabundle[1], ECDSA_WITH_SHA384, ECDSA_WITH_SHA256);

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(
        result.err(),
        Some(Error::UnsupportedSignatureAlgorithm { index: 1 })
    );
}

#[test]
fn verify_chain_error_path_len_exceeded() {
    // given
    let mut doc = document();
    replace_last(&mut doc.cabundle[2], PATH_LEN_1, PATH_LEN_0);

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::BasicConstraints { index: 2 }));
}

#[test]
fn verify_chain_error_ca_cert_as_leaf() {
    // given
    let mut doc = document();
    doc.certificate = doc.cabundle.pop().expect("non-empty cabundle");

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::BasicConstraints { index: 3 }));
}

#[test]
fn verify_chain_error_leaf_without_digital_signature() {
    // given
    let mut doc = document();
    replace_last(
        &mut doc.certificate,
        LEAF_KEY_USAGE,
        LEAF_KEY_USAGE_NO_DIGITAL_SIGNATURE,
    );

    // when
    let result = verify_chain(&doc, &AWS_NITRO_ROOT_SHA256, NOW_SECS);

    // then
    assert_eq!(result.err(), Some(Error::KeyUsage { index: 4 }));
}
