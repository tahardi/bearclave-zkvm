use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate, iana};

use crate::{AttestationDocument, Error};

pub fn parse_document(cose_bytes: &[u8]) -> Result<AttestationDocument, Error> {
    let sign1 =
        CoseSign1::from_slice(cose_bytes).map_err(|e| Error::DecodingCose(e.to_string()))?;
    if sign1.protected.header.alg
        != Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384))
    {
        return Err(Error::UnsupportedAlgorithm);
    }
    let payload = sign1.payload.as_deref().ok_or(Error::MissingPayload)?;
    AttestationDocument::from_cbor(payload)
}
