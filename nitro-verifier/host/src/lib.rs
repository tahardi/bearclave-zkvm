use std::path::Path;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nitro_attestation::{NitroJournal, SolValue};
use nitro_verifier_methods::VERIFY_NITRO_ELF;
use risc0_zkvm::{ExecutorEnv, Journal, SessionInfo, default_executor};

pub fn read_report(path: &Path) -> anyhow::Result<Vec<u8>> {
    let b64 =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    STANDARD.decode(b64.trim()).context("decoding report")
}

pub fn execute(report: &[u8]) -> anyhow::Result<SessionInfo> {
    let env = ExecutorEnv::builder().write_slice(report).build()?;
    default_executor().execute(env, VERIFY_NITRO_ELF)
}

pub fn decode_journal(journal: &Journal) -> anyhow::Result<NitroJournal> {
    NitroJournal::abi_decode(&journal.bytes).context("decoding journal")
}
