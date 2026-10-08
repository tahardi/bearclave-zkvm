use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};

use crate::Error;

pub fn verify_cose_signature(cose_bytes: &[u8], leaf_key: &VerifyingKey) -> Result<(), Error> {
    let sign1 = CoseSign1::from_slice(cose_bytes).map_err(|_| Error::InvalidSignature)?;
    sign1.verify_signature(b"", |sig, data| {
        let signature = Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
        leaf_key
            .verify(data, &signature)
            .map_err(|_| Error::InvalidSignature)
    })
}
