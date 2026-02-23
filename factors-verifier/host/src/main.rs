use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use factors_verifier_methods::MULTIPLY_ID;
use host::multiply;
use serde_json::json;

#[cfg(feature = "prove")]
use risc0_ethereum_contracts::encode_seal;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (receipt, _) = multiply(17, 23);
    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );

    let image_id_bytes: Vec<u8> = MULTIPLY_ID.iter().flat_map(|n| n.to_le_bytes()).collect();
    #[cfg(feature = "prove")]
    {
        let seal = encode_seal(&receipt).unwrap();
        let groth16_json = json!({
            "seal": BASE64.encode(&seal),
            "image_id": BASE64.encode(&image_id_bytes),
            "journal": BASE64.encode(receipt.journal.bytes),
        });
        std::fs::write(
            "groth16.json",
            serde_json::to_string_pretty(&groth16_json).unwrap(),
        )
        .unwrap();
    }

    #[cfg(not(feature = "prove"))]
    {
        let stark_json = json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "image_id": BASE64.encode(&image_id_bytes),
            "journal": BASE64.encode(receipt.journal.bytes),
        });
        std::fs::write(
            "stark.json",
            serde_json::to_string_pretty(&stark_json).unwrap(),
        )
        .unwrap();
    }
}
