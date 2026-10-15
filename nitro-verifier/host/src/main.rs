use std::path::Path;

use anyhow::bail;
use host::{decode_journal, execute, read_report};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    let [_, command, path] = args.as_slice() else {
        bail!("usage: host execute <report-b64-path>");
    };
    if command != "execute" {
        bail!("unknown command {command}; usage: host execute <report-b64-path>");
    }

    let report = read_report(Path::new(path))?;
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
