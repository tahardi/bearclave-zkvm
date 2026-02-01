# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := pre-pr
.DELETE_ON_ERROR:
.SUFFIXES:

.PHONY: pre-pr
pre-pr: fmt lint audit

.PHONY: audit
audit:
	@cargo audit

.PHONY: fmt
fmt:
	@cargo fmt --all

.PHONY: lint
lint:
	@RISC0_SKIP_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo clippy \
		--workspace \
		-- \
		-D warnings \
		-W clippy::cargo \
		-W clippy::pedantic \
		-A clippy::multiple_crate_versions
