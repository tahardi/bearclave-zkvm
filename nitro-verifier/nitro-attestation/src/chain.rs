use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use crate::{AttestationDocument, Error};

pub fn verify_chain(
    document: &AttestationDocument,
    root_sha256: &[u8; 32],
    now_secs: u64,
) -> Result<VerifyingKey, Error> {
    let ders: Vec<&[u8]> = document
        .cabundle
        .iter()
        .chain(std::iter::once(&document.certificate))
        .map(Vec::as_slice)
        .collect();
    if Sha256::digest(ders[0])[..] != root_sha256[..] {
        return Err(Error::UntrustedRoot);
    }
    let chain = ders
        .iter()
        .enumerate()
        .map(|(index, der)| {
            Certificate::from_der(der).map_err(|_| Error::ParsingCertificate { index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = chain.len() - 1;
    for (index, cert) in chain.iter().enumerate() {
        check_validity(cert, index, now_secs)?;
        if index > 0 && cert.tbs_certificate.issuer != chain[index - 1].tbs_certificate.subject {
            return Err(Error::IssuerMismatch { index });
        }
        if index < leaf {
            check_ca_extensions(cert, index, leaf - 1 - index)?;
        } else {
            check_leaf_extensions(cert, index)?;
        }
        if index > 0 {
            check_signature(&chain[index - 1], cert, index)?;
        }
    }
    public_key(&chain[leaf], leaf)
}

fn check_validity(cert: &Certificate, index: usize, now_secs: u64) -> Result<(), Error> {
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();
    if (not_before..=not_after).contains(&now_secs) {
        Ok(())
    } else {
        Err(Error::CertificateNotValidAt { index })
    }
}

fn check_signature(parent: &Certificate, cert: &Certificate, index: usize) -> Result<(), Error> {
    if cert.signature_algorithm.oid != ECDSA_WITH_SHA_384 {
        return Err(Error::UnsupportedSignatureAlgorithm { index });
    }
    let key = public_key(parent, index - 1)?;
    let invalid = |_| Error::InvalidCertificateSignature { index };
    let signature = Signature::from_der(cert.signature.raw_bytes()).map_err(invalid)?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| Error::InvalidCertificateSignature { index })?;
    key.verify(&tbs, &signature).map_err(invalid)
}

fn public_key(cert: &Certificate, index: usize) -> Result<VerifyingKey, Error> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            != Some(SECP_384_R_1)
    {
        return Err(Error::InvalidPublicKey { index });
    }
    VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|_| Error::InvalidPublicKey { index })
}

fn check_ca_extensions(cert: &Certificate, index: usize, cas_below: usize) -> Result<(), Error> {
    let constraints = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| Error::BasicConstraints { index })?;
    let ok = constraints.is_some_and(|(critical, bc)| {
        critical
            && bc.ca
            && bc
                .path_len_constraint
                .is_none_or(|max| cas_below <= usize::from(max))
    });
    if !ok {
        return Err(Error::BasicConstraints { index });
    }
    if !key_usage(cert, index)?.key_cert_sign() {
        return Err(Error::KeyUsage { index });
    }
    Ok(())
}

fn check_leaf_extensions(cert: &Certificate, index: usize) -> Result<(), Error> {
    let constraints = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| Error::BasicConstraints { index })?;
    if constraints.is_some_and(|(_, bc)| bc.ca || bc.path_len_constraint.is_some()) {
        return Err(Error::BasicConstraints { index });
    }
    if !key_usage(cert, index)?.digital_signature() {
        return Err(Error::KeyUsage { index });
    }
    Ok(())
}

fn key_usage(cert: &Certificate, index: usize) -> Result<KeyUsage, Error> {
    cert.tbs_certificate
        .get::<KeyUsage>()
        .ok()
        .flatten()
        .map(|(_, usage)| usage)
        .ok_or(Error::KeyUsage { index })
}
