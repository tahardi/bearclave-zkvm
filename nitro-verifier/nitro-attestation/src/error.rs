#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("decoding cose sign1: {0}")]
    DecodingCose(String),
    #[error("unsupported cose algorithm")]
    UnsupportedAlgorithm,
    #[error("missing cose payload")]
    MissingPayload,
    #[error("decoding attestation document: {0}")]
    DecodingDocument(String),
    #[error("validating field: {0}")]
    InvalidField(&'static str),
    #[error("parsing certificate {index}")]
    ParsingCertificate { index: usize },
    #[error("matching pinned root certificate")]
    UntrustedRoot,
    #[error("checking validity of certificate {index}")]
    CertificateNotValidAt { index: usize },
    #[error("matching issuer of certificate {index}")]
    IssuerMismatch { index: usize },
    #[error("checking signature algorithm of certificate {index}")]
    UnsupportedSignatureAlgorithm { index: usize },
    #[error("parsing public key of certificate {index}")]
    InvalidPublicKey { index: usize },
    #[error("verifying signature of certificate {index}")]
    InvalidCertificateSignature { index: usize },
    #[error("checking basic constraints of certificate {index}")]
    BasicConstraints { index: usize },
    #[error("checking key usage of certificate {index}")]
    KeyUsage { index: usize },
    #[error("verifying cose signature")]
    InvalidSignature,
    #[error("missing pcr {0}")]
    MissingPcr(u64),
}
