# Nitro Verifier

Rust crates for verifying AWS Nitro Enclave attestations, built to run inside
a RISC Zero zkVM guest. The `nitro-attestation` crate decodes the COSE_Sign1
attestation and checks the attestation document's fields.

## Proof and Image ID

The `host` crate runs the `verify-nitro` guest. `proofs/groth16.json` is a
Groth16 proof of the guest on the production fixture, and `image-id.txt` is
the guest's image ID. Contracts and Go tests use both.

Both come from risc0's Docker guest build, so they match on any machine.
Docker must be running, and proving needs the Groth16 prover
(`rzup install risc0-groth16`).

```shell
make image-id > image-id.txt  # write the image ID
make image-id-check           # check image-id.txt matches the current guest
make prove                    # write proofs/groth16.json on CPU (slow, needs 16 GB+ RAM)
make prove-cuda               # same, on an NVIDIA GPU
```

On risc0 3.0.x, `make prove-cuda` crashes in the final Groth16 step with
"an illegal memory access was encountered"
([risc0#3785](https://github.com/risc0/risc0/issues/3785)). Use `make prove`
until risc0 is upgraded.

The image ID is a hash of the guest ELF. It changes when any of these change:

- guest code (`methods/guest/src/`) or `nitro-attestation`
- guest dependencies or `methods/guest/Cargo.lock`
- the risc0 version
- the Rust toolchain, which comes from the Docker builder image tag pinned in
  `methods/build.rs`

When it changes, regenerate both files, then update any contract that stores
the image ID.
