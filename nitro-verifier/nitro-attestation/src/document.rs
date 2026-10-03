use std::collections::BTreeMap;

use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::Error;

const MAX_PCRS: usize = 32;
const PCR_LENGTHS: [usize; 3] = [32, 48, 64];
const MAX_CERT_LENGTH: usize = 1024;
const MAX_PUBLIC_KEY_LENGTH: usize = 1024;
const MAX_USER_DATA_LENGTH: usize = 512;
const MAX_NONCE_LENGTH: usize = 512;
const DEBUG_PCRS: [u64; 3] = [0, 1, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationDocument {
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: u64,
    pub pcrs: BTreeMap<u64, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct RawDocument {
    module_id: String,
    digest: String,
    timestamp: u64,
    pcrs: BTreeMap<u64, ByteBuf>,
    certificate: ByteBuf,
    cabundle: Vec<ByteBuf>,
    public_key: Option<ByteBuf>,
    user_data: Option<ByteBuf>,
    nonce: Option<ByteBuf>,
}

impl AttestationDocument {
    pub fn from_cbor(payload: &[u8]) -> Result<Self, Error> {
        let raw: RawDocument =
            ciborium::from_reader(payload).map_err(|e| Error::DecodingDocument(e.to_string()))?;
        let doc = Self {
            module_id: raw.module_id,
            digest: raw.digest,
            timestamp_ms: raw.timestamp,
            pcrs: raw
                .pcrs
                .into_iter()
                .map(|(i, v)| (i, v.into_vec()))
                .collect(),
            certificate: raw.certificate.into_vec(),
            cabundle: raw.cabundle.into_iter().map(ByteBuf::into_vec).collect(),
            public_key: raw.public_key.map(ByteBuf::into_vec),
            user_data: raw.user_data.map(ByteBuf::into_vec),
            nonce: raw.nonce.map(ByteBuf::into_vec),
        };
        doc.validate()?;
        Ok(doc)
    }

    #[must_use]
    pub fn is_debug(&self) -> bool {
        DEBUG_PCRS.iter().all(|i| {
            self.pcrs
                .get(i)
                .is_some_and(|pcr| pcr.iter().all(|b| *b == 0))
        })
    }

    fn validate(&self) -> Result<(), Error> {
        check(!self.module_id.is_empty(), "module_id")?;
        check(self.digest == "SHA384", "digest")?;
        check(self.timestamp_ms > 0, "timestamp")?;
        check(
            (1..=MAX_PCRS).contains(&self.pcrs.len())
                && self
                    .pcrs
                    .iter()
                    .all(|(i, v)| *i < MAX_PCRS as u64 && PCR_LENGTHS.contains(&v.len())),
            "pcrs",
        )?;
        check(valid_cert(&self.certificate), "certificate")?;
        check(
            !self.cabundle.is_empty() && self.cabundle.iter().all(|c| valid_cert(c)),
            "cabundle",
        )?;
        check(
            self.public_key
                .as_ref()
                .is_none_or(|k| (1..=MAX_PUBLIC_KEY_LENGTH).contains(&k.len())),
            "public_key",
        )?;
        check(
            self.user_data
                .as_ref()
                .is_none_or(|d| d.len() <= MAX_USER_DATA_LENGTH),
            "user_data",
        )?;
        check(
            self.nonce
                .as_ref()
                .is_none_or(|n| n.len() <= MAX_NONCE_LENGTH),
            "nonce",
        )
    }
}

fn valid_cert(cert: &[u8]) -> bool {
    (1..=MAX_CERT_LENGTH).contains(&cert.len())
}

fn check(ok: bool, field: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidField(field))
    }
}
