# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := pre-pr
.DELETE_ON_ERROR:
.SUFFIXES:

.PHONY: pre-pr
pre-pr: fmt lint audit test-unit

.PHONY: audit
audit:
	@cargo audit

.PHONY: fmt
fmt:
	@cargo fmt --all

.PHONY: lint
lint:
	@cargo clippy \
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
