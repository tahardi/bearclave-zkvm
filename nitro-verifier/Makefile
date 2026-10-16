# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := pre-pr
.DELETE_ON_ERROR:
.SUFFIXES:

.PHONY: pre-pr
pre-pr: fmt lint audit test-unit test-guest

.PHONY: audit
audit:
	@cargo audit

.PHONY: fmt
fmt:
	@cargo fmt --all

.PHONY: lint
lint:
	@RISC0_SKIP_BUILD=1 cargo clippy \
		--workspace \
		--all-targets \
		-- \
		-D warnings \
		-W clippy::cargo \
		-W clippy::pedantic \
		-A clippy::multiple_crate_versions \
		-A clippy::missing_errors_doc \
		-A clippy::missing_panics_doc

.PHONY: test-unit
test-unit:
	@cargo test -p nitro-attestation

.PHONY: test-guest
test-guest:
	@cargo test -p host

.PHONY: image-id
image-id:
	@RISC0_USE_DOCKER=1 cargo run -q -p host -- image-id

.PHONY: image-id-check
image-id-check:
	@diff <(RISC0_USE_DOCKER=1 cargo run -q -p host -- image-id) image-id.txt

.PHONY: prove
prove:
	@RISC0_USE_DOCKER=1 cargo run \
		--release \
		-p host \
		-F prove \
		-- \
		prove \
		nitro-attestation/testdata/nitro-report-b64.txt \
		proofs/groth16.json

.PHONY: prove-cuda
prove-cuda:
	@RISC0_USE_DOCKER=1 cargo run \
		--release \
		-p host \
		-F prove,cuda \
		-- \
		prove \
		nitro-attestation/testdata/nitro-report-b64.txt \
		proofs/groth16.json
