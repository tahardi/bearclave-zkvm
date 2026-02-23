# Bearclave: Verifying Attestations with zkVMs

A Zero-Knowledge Proof (ZKP) is a cryptographic proof that allows one party
to prove to another that a specific statement is true without revealing any
information beyond the statement itself. For example, a ZKP can be used to
prove that you are over 21 without revealing your actual date of birth. Initial
ZKP systems required you to design a new "circuit" for each statement you
wanted to prove. So, you might have a circuit for "I am over 21", and another
for "I have a valid driver's license", and so on. This was cumbersome and
inefficient, especially for complex statements.

Zero-Knowledge Virtual Machines (zkVMs) are a new approach to ZKPs that
allow you to prove statements without having to design custom circuits for
each one. Instead, zkVMs are circuits that prove the execution of a given
program by modeling an instruction set. For example, the RISC Zero zkVM
proves the execution of programs written in the RISC-V instruction set. This
allows developers to write programs in any language that can be compiled to
RISC-V, and then execute them on the zkVM to prove their correctness.

While modern zkVMs allow you to prove statements without having to design a
circuit for each one, they are still orders of magnitude slower than running
a program in a traditional computing environment. Thus, you want to minimize
the scope of what you want to prove for your given application.

This project will soon contain Rust crates for verifying TEE attestations using
Risc Zero zkVMs. Specifically, it will support:

- AWS Nitro Enclaves
- AMD SEV-SNP
- Intel TDX
