# SPDX-License-Identifier: GPL-2.0-only
GO ?= go
GINKGO_LABEL ?= local && basic
GINKGO_FOCUS ?=

# Export values instead of interpolating them into shell source. In particular,
# label expressions and focus regexps can contain shell metacharacters.
export GO GINKGO_LABEL GINKGO_FOCUS GINKGO_CONFIG
export SCST_TEST_SOURCE_DIR := $(abspath ../..)

help:
	@echo "check  : unit tests, vet and component-suite compilation; no SCST access"
	@echo "list   : Ginkgo dry run; no SCST access"
	@echo "config : validate and print GINKGO_CONFIG; no SCST access"
	@echo "test   : load built SCST modules from this checkout, then run tests (root)"
	@echo "test-build: build and load SCST from this checkout, then run tests (root)"
	@echo "GINKGO_LABEL selects groups, e.g. local or basic"

check:
	$(GO) test -count=1 ./internal/... ./cmd/...
	$(GO) vet ./...
	$(GO) test -run='^$$' ./suite

list:
	$(GO) run ./cmd/run -list

config:
	@test -n "$$GINKGO_CONFIG" || { echo "Set GINKGO_CONFIG to a JSON file" >&2; exit 2; }
	$(GO) run ./cmd/config-check "$$GINKGO_CONFIG"

test test-build:
	@test -n "$$GINKGO_CONFIG" || { echo "Set GINKGO_CONFIG to a disposable-host JSON file" >&2; exit 2; }
	SCST_TEST_BUILD=$(if $(filter test-build,$@),1,0) SCST_TEST_CONFIG="$$GINKGO_CONFIG" \
		SCST_TEST_KDIR="$${SCST_TEST_KDIR:-$${KDIR:-}}" $(GO) run ./cmd/run

.PHONY: help check list config test test-build
