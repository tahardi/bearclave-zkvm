mod common;

use alloy_sol_types::SolValue;
use nitro_attestation::{AWS_NITRO_ROOT_SHA256, Error, NitroJournal, parse_document};

const PCR0: &str = "1606040ac5afb19824cb0f783ed0f90583ef1ac555dc3b0b5f00d564ec0d206bd7a56ca6ee049ba2e03bb7d4ea88d00b";
const PCR1: &str = "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493";
const PCR2: &str = "e0742e0e40b8576aeadccff8539e448399b9924bb9701772bb5d2501d97757faba6d2aa390e761ef60c5a4d7452f101f";

#[test]
fn from_document_happy_path() {
    // given
    let doc = parse_document(&common::report()).expect("parsing document");

    // when
    let journal =
        NitroJournal::from_document(&doc, &AWS_NITRO_ROOT_SHA256).expect("building journal");

    // then
    assert_eq!(journal.rootSha256.0, AWS_NITRO_ROOT_SHA256);
    assert_eq!(journal.timestampMs, 1_749_295_504_541);
    assert_eq!(hex::encode(&journal.pcr0), PCR0);
    assert_eq!(hex::encode(&journal.pcr1), PCR1);
    assert_eq!(hex::encode(&journal.pcr2), PCR2);
    assert_eq!(journal.userData.as_ref(), b"Hello, world!");
    assert_eq!(journal.publicKey.as_ref(), b"TODO: generate public key");
    assert_eq!(journal.nonce.as_ref(), b"TODO: generate nonce");
}

#[test]
fn from_document_error_missing_pcr() {
    for (name, report) in [
        ("production", common::report()),
        ("debug", common::debug_report()),
    ] {
        // given
        let mut doc = parse_document(&report).expect("parsing document");
        doc.pcrs.remove(&1);

        // when
        let result = NitroJournal::from_document(&doc, &AWS_NITRO_ROOT_SHA256);

        // then
        assert_eq!(result, Err(Error::MissingPcr(1)), "case {name}");
    }
}

#[test]
fn abi_round_trip() {
    // given
    let doc = parse_document(&common::report()).expect("parsing document");
    let journal =
        NitroJournal::from_document(&doc, &AWS_NITRO_ROOT_SHA256).expect("building journal");

    // when
    let decoded = NitroJournal::abi_decode(&journal.abi_encode()).expect("decoding journal");

    // then
    assert_eq!(decoded, journal);
}
