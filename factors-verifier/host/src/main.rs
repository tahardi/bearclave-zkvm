use factors_verifier_methods::MULTIPLY_ID;
use host::multiply;

#[cfg(feature = "prove")]
use hex;
#[cfg(feature = "prove")]
use risc0_ethereum_contracts::encode_seal;
#[cfg(feature = "prove")]
use serde_json::json;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Pick two numbers
    let (receipt, _) = multiply(17, 23);

    // Verify receipt, panic if it's wrong
    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );

    #[cfg(feature = "prove")]
    {
        let seal = encode_seal(&receipt).unwrap();
        std::fs::write("seal.bin", &seal).unwrap();

        let image_id_bytes: Vec<u8> = MULTIPLY_ID.iter().flat_map(|n| n.to_le_bytes()).collect();
        let proof_json = json!({
            "seal": hex::encode(&seal),
            "image_id": hex::encode(image_id_bytes),
            "journal": hex::encode(receipt.journal.bytes),
        });
        std::fs::write(
            "proof.json",
            serde_json::to_string_pretty(&proof_json).unwrap(),
        )
        .unwrap();
    }
}
