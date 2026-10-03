# Nitro Verifier

Rust crates for verifying AWS Nitro Enclave attestations, built to run inside
a RISC Zero zkVM guest. The `nitro-attestation` crate decodes the COSE_Sign1
attestation and checks the attestation document's fields.
