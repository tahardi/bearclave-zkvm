mod chain;
mod document;
mod error;
mod parse;
mod root;
mod signature;
mod verify;

pub use chain::verify_chain;
pub use document::AttestationDocument;
pub use error::Error;
pub use parse::parse_document;
pub use root::AWS_NITRO_ROOT_SHA256;
pub use signature::verify_cose_signature;
pub use verify::verify;
