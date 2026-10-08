#![no_main]

use std::io::Read;

use nitro_attestation::{AWS_NITRO_ROOT_SHA256, NitroJournal, SolValue, parse_document, verify};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut report = Vec::new();
    env::stdin().read_to_end(&mut report).expect("reading report");
    let parsed = parse_document(&report).expect("parsing report");
    let document = verify(
        &report,
        &AWS_NITRO_ROOT_SHA256,
        parsed.timestamp_ms / 1000,
    )
    .expect("verifying report");
    assert!(!document.is_debug(), "rejecting debug-mode attestation");
    let journal = NitroJournal::from_document(&document, &AWS_NITRO_ROOT_SHA256).expect("building journal");
    env::commit_slice(&journal.abi_encode());
}
