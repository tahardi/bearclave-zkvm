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
}
