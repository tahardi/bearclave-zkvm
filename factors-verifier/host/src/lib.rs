use factors_verifier_methods::MULTIPLY_ELF;
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};

/// Computes the product of two numbers using the RISC Zero zkVM.
///
/// This function demonstrates zero-knowledge proof generation using the RISC
/// Zero zkVM. It proves knowledge of factors `a` and `b` such that `a * b`
/// equals the returned product, without revealing the factors themselves.
///
/// # Arguments
///
/// * `a` - The first factor (kept secret in the proof)
/// * `b` - The second factor (kept secret in the proof)
///
/// # Returns
///
/// A tuple containing:
/// * `Receipt` - A zero-knowledge proof that the computation was performed correctly
/// * `u64` - The product of `a` and `b`
///
/// # Panics
///
/// Panics if:
/// * The `ExecutorEnv` fails to build
/// * The prover fails to generate a valid receipt
/// * The journal output cannot be decoded as a `u64`
///
/// # Example
///
/// ```
/// let (receipt, product) = multiply(17, 23);
/// assert_eq!(product, 391);
/// ```
#[must_use]
pub fn multiply(a: u64, b: u64) -> (Receipt, u64) {
    let env = ExecutorEnv::builder()
        // Send a & b to the guest
        .write(&a)
        .unwrap()
        .write(&b)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, MULTIPLY_ELF).unwrap().receipt;

    // Extract journal of receipt (i.e. output c, where c = a * b)
    let c: u64 = receipt.journal.decode().expect(
        "Journal output should deserialize into the same types (& order) that it was written",
    );

    // Report the product
    println!("I know the factors of {c}, and I can prove it!");

    (receipt, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        const TEST_FACTOR_ONE: u64 = 17;
        const TEST_FACTOR_TWO: u64 = 23;
        let (_, result) = multiply(17, 23);
        assert_eq!(
            result,
            TEST_FACTOR_ONE * TEST_FACTOR_TWO,
            "We expect the zkVM output to be the product of the inputs"
        )
    }
}
