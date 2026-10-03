mod common;

use nitro_attestation::{Error, parse_document};

const PCR0: &str = "1606040ac5afb19824cb0f783ed0f90583ef1ac555dc3b0b5f00d564ec0d206bd7a56ca6ee049ba2e03bb7d4ea88d00b";
const PCR1: &str = "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493";
const PCR2: &str = "e0742e0e40b8576aeadccff8539e448399b9924bb9701772bb5d2501d97757faba6d2aa390e761ef60c5a4d7452f101f";

#[test]
fn parse_document_happy_path() {
    // given
    let report = common::report();
    assert_eq!(report.len(), 4518);

    // when
    let doc = parse_document(&report).expect("parsing document");

    // then
    assert_eq!(doc.module_id, "i-01bdf23ce28366cb5-enc01974a1e041bde39");
    assert_eq!(doc.digest, "SHA384");
    assert_eq!(doc.timestamp_ms, 1_749_295_504_541);
    assert_eq!(doc.pcrs.len(), 16);
    assert!(doc.pcrs.iter().all(|(i, v)| *i < 16 && v.len() == 48));
    assert_eq!(hex::encode(&doc.pcrs[&0]), PCR0);
    assert_eq!(hex::encode(&doc.pcrs[&1]), PCR1);
    assert_eq!(hex::encode(&doc.pcrs[&2]), PCR2);
    assert!(!doc.certificate.is_empty());
    assert_eq!(doc.cabundle.len(), 4);
    assert_eq!(doc.user_data.as_deref(), Some(b"Hello, world!".as_slice()));
    assert_eq!(
        doc.nonce.as_deref(),
        Some(b"TODO: generate nonce".as_slice())
    );
    assert_eq!(
        doc.public_key.as_deref(),
        Some(b"TODO: generate public key".as_slice())
    );
    assert!(!doc.is_debug());
}

#[test]
fn parse_document_happy_path_debug() {
    // given
    let report = common::debug_report();
    assert_eq!(report.len(), 4518);

    // when
    let doc = parse_document(&report).expect("parsing document");

    // then
    assert_eq!(doc.module_id, "i-01bdf23ce28366cb5-enc019759c92189a1e4");
    assert_eq!(doc.digest, "SHA384");
    assert_eq!(doc.timestamp_ms, 1_749_558_205_687);
    assert_eq!(doc.pcrs.len(), 16);
    for i in 0..3 {
        assert_eq!(doc.pcrs[&i], vec![0u8; 48]);
    }
    assert_eq!(doc.cabundle.len(), 4);
    assert_eq!(doc.user_data.as_deref(), Some(b"Hello, world!".as_slice()));
    assert!(doc.is_debug());
}

#[test]
fn parse_document_error_not_cbor() {
    // given
    let report = b"invalid attestation report";

    // when
    let result = parse_document(report);

    // then
    assert!(
        matches!(result, Err(Error::DecodingCose(_))),
        "got {result:?}"
    );
}

#[test]
fn parse_document_error_truncated() {
    // given
    let report = common::report();

    // when
    let result = parse_document(&report[..100]);

    // then
    assert!(
        matches!(result, Err(Error::DecodingCose(_))),
        "got {result:?}"
    );
}
