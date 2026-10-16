use std::path::Path;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nitro_attestation::{NitroJournal, SolValue};
use nitro_verifier_methods::{VERIFY_NITRO_ELF, VERIFY_NITRO_ID};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    ExecutorEnv, Journal, ProverOpts, Receipt, SessionInfo, default_executor, default_prover,
};

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

pub fn prove_groth16(report: &[u8]) -> anyhow::Result<Receipt> {
    let env = ExecutorEnv::builder().write_slice(report).build()?;
    let receipt = default_prover()
        .prove_with_opts(env, VERIFY_NITRO_ELF, &ProverOpts::groth16())?
        .receipt;
    receipt
        .verify(VERIFY_NITRO_ID)
        .context("verifying receipt")?;
    Ok(receipt)
}

#[must_use]
pub fn image_id_hex() -> String {
    hex::encode(Digest::from(VERIFY_NITRO_ID).as_bytes())
}
