use crate::{AttestationDocument, Error, parse_document, verify_chain, verify_cose_signature};

pub fn verify(
    cose_bytes: &[u8],
    root_sha256: &[u8; 32],
    now_secs: u64,
) -> Result<AttestationDocument, Error> {
    let document = parse_document(cose_bytes)?;
    let leaf_key = verify_chain(&document, root_sha256, now_secs)?;
    verify_cose_signature(cose_bytes, &leaf_key)?;
    Ok(document)
}
