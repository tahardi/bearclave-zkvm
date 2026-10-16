use std::path::Path;

use anyhow::bail;
use host::{decode_journal, execute, image_id_hex, read_report};

const USAGE: &str = "usage: host execute <report-b64-path> | host image-id | host prove <report-b64-path> <out.json>";

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, command, path] if command == "execute" => run_execute(Path::new(path)),
        [_, command] if command == "image-id" => {
            println!("{}", image_id_hex());
            Ok(())
        }
        #[cfg(feature = "prove")]
        [_, command, path, out] if command == "prove" => run_prove(Path::new(path), Path::new(out)),
        _ => bail!(USAGE),
    }
}

fn run_execute(path: &Path) -> anyhow::Result<()> {
    let report = read_report(path)?;
    let session = execute(&report)?;
    let journal = decode_journal(&session.journal)?;

    println!("rootSha256:   {}", hex::encode(journal.rootSha256));
    println!("timestampMs:  {}", journal.timestampMs);
    println!("pcr0:         {}", hex::encode(&journal.pcr0));
    println!("pcr1:         {}", hex::encode(&journal.pcr1));
    println!("pcr2:         {}", hex::encode(&journal.pcr2));
    println!("userData:     {}", hex::encode(&journal.userData));
    println!("publicKey:    {}", hex::encode(&journal.publicKey));
    println!("nonce:        {}", hex::encode(&journal.nonce));
    println!("segments:     {}", session.segments.len());
    println!("user cycles:  {}", session.cycles());
    println!(
        "total cycles: {}",
        session.segments.iter().map(|s| 1u64 << s.po2).sum::<u64>()
    );
    Ok(())
}

#[cfg(feature = "prove")]
fn run_prove(path: &Path, out: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let report = read_report(path)?;
    let start = std::time::Instant::now();
    let receipt = host::prove_groth16(&report)?;
    println!("proving time: {:.1?}", start.elapsed());

    let seal = risc0_ethereum_contracts::encode_seal(&receipt)?;
    let image_id = hex::decode(image_id_hex())?;
    let proof = serde_json::json!({
        "seal": STANDARD.encode(seal),
        "image_id": STANDARD.encode(image_id),
        "journal": STANDARD.encode(&receipt.journal.bytes),
    });
    std::fs::write(out, serde_json::to_string_pretty(&proof)? + "\n")
        .with_context(|| format!("writing {}", out.display()))?;
    println!("wrote {}", out.display());
    Ok(())
}
