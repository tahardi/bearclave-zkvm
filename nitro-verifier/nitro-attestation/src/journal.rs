use crate::{AttestationDocument, Error};

alloy_sol_types::sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct NitroJournal {
        bytes32 rootSha256;
        uint64 timestampMs;
        bytes pcr0;
        bytes pcr1;
        bytes pcr2;
        bytes userData;
        bytes publicKey;
        bytes nonce;
    }
}

impl NitroJournal {
    pub fn from_document(
        document: &AttestationDocument,
        root_sha256: &[u8; 32],
    ) -> Result<Self, Error> {
        let pcr = |index: u64| {
            document
                .pcrs
                .get(&index)
                .map(|pcr| pcr.clone().into())
                .ok_or(Error::MissingPcr(index))
        };
        let optional = |field: &Option<Vec<u8>>| field.clone().unwrap_or_default().into();
        Ok(Self {
            rootSha256: (*root_sha256).into(),
            timestampMs: document.timestamp_ms,
            pcr0: pcr(0)?,
            pcr1: pcr(1)?,
            pcr2: pcr(2)?,
            userData: optional(&document.user_data),
            publicKey: optional(&document.public_key),
            nonce: optional(&document.nonce),
        })
    }
}
