use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use host::read_report;
use nitro_attestation::{AWS_NITRO_ROOT_SHA256, NitroJournal, SolValue, parse_document};

const GROTH16_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];

fn field(proof: &serde_json::Value, name: &str) -> Vec<u8> {
    let b64 = proof[name].as_str().expect("reading field");
    STANDARD.decode(b64).expect("decoding field")
}

#[test]
fn proof_fixture_matches_image_id_and_journal() {
    // given
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let proof: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("proofs/groth16.json")).expect("reading proof"),
    )
    .expect("parsing proof");
    let image_id = std::fs::read_to_string(root.join("image-id.txt")).expect("reading image id");
    let report = read_report(&root.join("nitro-attestation/testdata/nitro-report-b64.txt"))
        .expect("reading report");
    let document = parse_document(&report).expect("parsing document");
    let want =
        NitroJournal::from_document(&document, &AWS_NITRO_ROOT_SHA256).expect("building journal");

    // when
    let journal = NitroJournal::abi_decode(&field(&proof, "journal")).expect("decoding journal");
    let seal = field(&proof, "seal");

    // then
    assert_eq!(
        field(&proof, "image_id"),
        hex::decode(image_id.trim()).expect("decoding image id")
    );
    assert_eq!(journal, want);
    assert!(seal.len() > 4);
    assert_eq!(seal[..4], GROTH16_SELECTOR);
}
